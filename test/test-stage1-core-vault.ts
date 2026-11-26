import {
  AuthorizationRecord,
  DeviceLinkRecord,
  LocalDeviceIdentityRecord
} from '../src/contracts/velContracts';
import {
  generateDeviceCryptoMaterial,
  isPrivateKeyProtected
} from '../src/crypto/deviceCrypto';
import {
  computeSha256Hex,
  hashBlobIncremental,
  IncrementalSha256,
  toExactArrayBuffer
} from '../src/crypto/fileHash';
import {
  STORE_AUTHORIZATIONS,
  STORE_CONFIG,
  STORE_IDENTITY,
  STORE_INCOMING_CHUNKS,
  STORE_ITEMS,
  STORE_LINKS,
  STORE_RECORDS,
  STORE_VAULT_CHUNKS,
  STORE_VAULT_FILES,
  VEL_DB_VERSION,
  VelDatabase
} from '../src/db/db';
import {
  classifyFileKind,
  formatBytesHuman,
  MAX_VEL_FILE_BYTES,
  VEL_CHUNK_SIZE_BYTES,
  VelLocalStore
} from '../src/db/velLocalStore';

let passed = 0;
let failed = 0;

function assert(condition: boolean, label: string, detail?: string): void {
  if (condition) {
    passed++;
    console.log(`✓ [PASS] ${label}`);
  } else {
    failed++;
    console.error(`✗ [FAIL] ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

async function assertRejects(fn: () => Promise<unknown>, label: string): Promise<Error | null> {
  try {
    await fn();
    assert(false, label, 'Se esperaba rechazo/excepción pero resolvió correctamente');
    return null;
  } catch (err) {
    assert(true, label);
    return err instanceof Error ? err : new Error(String(err));
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function makePatternBytes(size: number, seed = 17): Uint8Array {
  const out = new Uint8Array(size);
  let x = seed >>> 0;
  for (let i = 0; i < size; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out[i] = (x >>> 24) & 0xff;
  }
  return out;
}

async function subtleSha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
  );
  const view = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < view.length; i++) {
    hex += view[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Simulador IndexedDB en memoria para verificar migración v2 -> v4 de VelDatabase y VelLocalStore.
 */
function createPersistentIndexedDbHarness() {
  interface StoredIndexDef {
    name: string;
    keyPath: string;
    unique: boolean;
  }
  interface StoredObjectStore {
    name: string;
    keyPath: string;
    indexes: Map<string, StoredIndexDef>;
    records: Map<string, any>;
  }
  interface StoredDbSchema {
    version: number;
    stores: Map<string, StoredObjectStore>;
  }

  const databases = new Map<string, StoredDbSchema>();

  function cloneValue<T>(val: T): T {
    if (val === null || val === undefined || typeof val !== 'object') return val;
    if (val instanceof Uint8Array) return new Uint8Array(val) as unknown as T;
    if (val instanceof ArrayBuffer) return val.slice(0) as unknown as T;
    if (typeof Blob !== 'undefined' && val instanceof Blob) return val;
    if (typeof CryptoKey !== 'undefined' && val instanceof CryptoKey) return val;
    if (Array.isArray(val)) return val.map((item) => cloneValue(item)) as unknown as T;
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(val as Record<string, any>)) {
      out[k] = cloneValue(v);
    }
    return out as T;
  }

  function makeDomStringList(names: Iterable<string>) {
    const arr = Array.from(names);
    return {
      length: arr.length,
      contains(name: string) {
        return arr.includes(name);
      },
      item(i: number) {
        return arr[i] || null;
      },
      [Symbol.iterator]: () => arr[Symbol.iterator]()
    };
  }

  function createFakeDb(schema: StoredDbSchema) {
    const dbObj: any = {
      name: '',
      get version() {
        return schema.version;
      },
      get objectStoreNames() {
        return makeDomStringList(schema.stores.keys());
      },
      onversionchange: null as null | (() => void),
      onclose: null as null | (() => void),
      close() {
        if (typeof dbObj.onclose === 'function') dbObj.onclose();
      },
      createObjectStore(name: string, opts: { keyPath: string }) {
        const storeDef: StoredObjectStore = {
          name,
          keyPath: opts.keyPath,
          indexes: new Map(),
          records: new Map()
        };
        schema.stores.set(name, storeDef);
        return {
          name,
          createIndex(indexName: string, keyPath: string, indexOpts?: { unique?: boolean }) {
            storeDef.indexes.set(indexName, {
              name: indexName,
              keyPath,
              unique: Boolean(indexOpts?.unique)
            });
          }
        };
      },
      transaction(storeNames: string | string[], _mode: 'readonly' | 'readwrite') {
        const names = Array.isArray(storeNames) ? storeNames : [storeNames];
        for (const n of names) {
          if (!schema.stores.has(n)) {
            throw new Error(`ObjectStore "${n}" no existe`);
          }
        }
        const tx: any = {
          error: null,
          oncomplete: null,
          onerror: null,
          onabort: null,
          abort() {
            queueMicrotask(() => {
              if (typeof tx.onabort === 'function') tx.onabort();
            });
          },
          objectStore(name: string) {
            const storeDef = schema.stores.get(name)!;
            const scheduleComplete = (req: any) => {
              queueMicrotask(() => {
                if (typeof req.onsuccess === 'function') req.onsuccess({ target: req });
                queueMicrotask(() => {
                  if (typeof tx.oncomplete === 'function') tx.oncomplete({ target: tx });
                });
              });
            };
            return {
              put(value: any) {
                const req: any = { result: undefined, error: null, onsuccess: null, onerror: null };
                const key = value[storeDef.keyPath];
                storeDef.records.set(String(key), cloneValue(value));
                req.result = key;
                scheduleComplete(req);
                return req;
              },
              get(key: IDBValidKey) {
                const req: any = { result: undefined, error: null, onsuccess: null, onerror: null };
                const found = storeDef.records.get(String(key));
                req.result = found ? cloneValue(found) : undefined;
                scheduleComplete(req);
                return req;
              },
              getAll() {
                const req: any = { result: undefined, error: null, onsuccess: null, onerror: null };
                req.result = Array.from(storeDef.records.values()).map((r) => cloneValue(r));
                scheduleComplete(req);
                return req;
              },
              delete(key: IDBValidKey) {
                const req: any = { result: undefined, error: null, onsuccess: null, onerror: null };
                storeDef.records.delete(String(key));
                scheduleComplete(req);
                return req;
              },
              index(indexName: string) {
                const idxDef = storeDef.indexes.get(indexName);
                if (!idxDef) throw new Error(`Índice "${indexName}" no existe en "${name}"`);
                return {
                  getAll(range?: { onlyValue?: any }) {
                    const req: any = { result: undefined, error: null, onsuccess: null, onerror: null };
                    const rows = Array.from(storeDef.records.values())
                      .filter((r) =>
                        range && 'onlyValue' in range ? r[idxDef.keyPath] === range.onlyValue : true
                      )
                      .map((r) => cloneValue(r));
                    req.result = rows;
                    scheduleComplete(req);
                    return req;
                  },
                  openCursor(range?: { onlyValue?: any }) {
                    const matchingKeys = Array.from(storeDef.records.entries())
                      .filter(([, r]) =>
                        range && 'onlyValue' in range ? r[idxDef.keyPath] === range.onlyValue : true
                      )
                      .map(([k]) => k);
                    let pos = 0;
                    const req: any = { result: null, error: null, onsuccess: null, onerror: null };
                    const emitNext = () => {
                      queueMicrotask(() => {
                        if (pos >= matchingKeys.length) {
                          req.result = null;
                          if (typeof req.onsuccess === 'function') req.onsuccess({ target: req });
                          queueMicrotask(() => {
                            if (typeof tx.oncomplete === 'function') tx.oncomplete({ target: tx });
                          });
                          return;
                        }
                        const currentKey = matchingKeys[pos++];
                        const cursor = {
                          value: cloneValue(storeDef.records.get(currentKey)),
                          delete() {
                            const delReq: any = { onerror: null, onsuccess: null };
                            storeDef.records.delete(currentKey);
                            queueMicrotask(() => {
                              if (typeof delReq.onsuccess === 'function') delReq.onsuccess({ target: delReq });
                            });
                            return delReq;
                          },
                          continue() {
                            emitNext();
                          }
                        };
                        req.result = cursor;
                        if (typeof req.onsuccess === 'function') req.onsuccess({ target: req });
                      });
                    };
                    emitNext();
                    return req;
                  }
                };
              }
            };
          }
        };
        return tx;
      }
    };
    return dbObj;
  }

  const fakeIndexedDB = {
    open(dbName: string, version = 1) {
      const req: any = {
        result: null,
        error: null,
        transaction: null,
        onupgradeneeded: null,
        onsuccess: null,
        onerror: null,
        onblocked: null
      };

      queueMicrotask(() => {
        let schema = databases.get(dbName);
        const oldVersion = schema ? schema.version : 0;
        if (!schema) {
          schema = { version, stores: new Map() };
          databases.set(dbName, schema);
        }
        const fakeDb = createFakeDb(schema);
        fakeDb.name = dbName;
        req.result = fakeDb;

        if (version > oldVersion) {
          schema.version = version;
          req.transaction = { onerror: null, onabort: null, abort() {} };
          if (typeof req.onupgradeneeded === 'function') {
            req.onupgradeneeded({ target: req, oldVersion, newVersion: version });
          }
          req.transaction = null;
        }
        if (typeof req.onsuccess === 'function') {
          req.onsuccess({ target: req });
        }
      });

      return req;
    }
  };

  return {
    databases,
    installGlobals() {
      const prevIdb = (globalThis as any).indexedDB;
      const prevKeyRange = (globalThis as any).IDBKeyRange;
      (globalThis as any).indexedDB = fakeIndexedDB;
      (globalThis as any).IDBKeyRange = {
        only(val: any) {
          return { onlyValue: val };
        }
      };
      return () => {
        (globalThis as any).indexedDB = prevIdb;
        (globalThis as any).IDBKeyRange = prevKeyRange;
      };
    }
  };
}

async function runTests() {
  console.log('==================================================================');
  console.log('VEL 0.1 — PRUEBAS DE BASE LOCAL UNIFICADA v4 (VelLocalStore)');
  console.log('==================================================================\n');

  console.log('--- 1. Utilidades de clasificación, formato y hash ---');
  assert(classifyFileKind('vacaciones.jpg', 'image/jpeg') === 'photo', 'Clasifica imagen como photo');
  assert(classifyFileKind('clip.mp4', 'video/mp4') === 'video', 'Clasifica vídeo como video');
  assert(classifyFileKind('contrato.pdf', 'application/pdf') === 'file', 'Clasifica PDF como file');
  assert(formatBytesHuman(1536) === '1.5 KB', 'Formatea KB correctamente');

  const sample = makePatternBytes(200 * 1024, 99);
  const exactBuf = toExactArrayBuffer(sample);
  const directHex = await computeSha256Hex(sample);
  const subtleHex = await subtleSha256Hex(sample);
  const blobHex = await hashBlobIncremental(new Blob([exactBuf]));
  const inc = new IncrementalSha256();
  inc.update(sample.subarray(0, 50_000));
  inc.update(sample.subarray(50_000));
  const incHex = await inc.digestHex();
  assert(
    directHex === subtleHex && blobHex === subtleHex && incHex === subtleHex,
    'SHA-256 incremental y directo coinciden bit a bit con WebCrypto'
  );

  console.log('\n--- 2. Migración IndexedDB v2 -> v4 conservando identidad previa ---');
  const harness = createPersistentIndexedDbHarness();
  const restoreGlobals = harness.installGlobals();

  try {
    const dbV2 = new VelDatabase('VelLocalDB_Stage1', 2);
    await dbV2.open();

    const coreMaterial = await generateDeviceCryptoMaterial('CORE');
    const savedIdentity: LocalDeviceIdentityRecord = {
      id: 'current',
      deviceId: coreMaterial.deviceId,
      role: 'CORE',
      fingerprint: coreMaterial.fingerprint,
      publicKeySpkiBase64: coreMaterial.publicKeySpkiBase64,
      signingPublicKeySpkiBase64: coreMaterial.signingPublicKeySpkiBase64,
      privateEcdhKey: coreMaterial.ecdhKeyPair.privateKey,
      privateSigningKey: coreMaterial.signingKeyPair.privateKey,
      firebaseAuthUid: 'anon-core-uid-v2',
      registrationStatus: 'paired',
      activeLinkId: 'LNK-V2-001',
      pairedPeerDeviceId: 'VEL-MOV-1234567890AB',
      lastServerError: null,
      createdAt: '2026-10-01T00:00:00.000Z',
      updatedAt: '2026-10-01T00:00:00.000Z'
    };
    await dbV2.saveIdentity(savedIdentity);
    await dbV2.setConfig('legacy_pref', { theme: 'dark' });
    const authRec: AuthorizationRecord = {
      authorizationId: 'LNK-V2-001',
      linkId: 'LNK-V2-001',
      coreDeviceId: coreMaterial.deviceId,
      terminalDeviceId: 'VEL-MOV-1234567890AB',
      coreAuthUid: 'anon-core-uid-v2',
      terminalAuthUid: 'anon-mov-uid-v2',
      status: 'active',
      permissions: ['RELAY_CONNECT'],
      grantedAt: '2026-10-01T00:00:00.000Z',
      revokedAt: null,
      revokedByDeviceId: null,
      lastActivityAt: '2026-10-01T00:00:00.000Z'
    };
    const linkRec: DeviceLinkRecord = {
      linkId: 'LNK-V2-001',
      coreDeviceId: coreMaterial.deviceId,
      terminalDeviceId: 'VEL-MOV-1234567890AB',
      coreAuthUid: 'anon-core-uid-v2',
      terminalAuthUid: 'anon-mov-uid-v2',
      coreFingerprint: coreMaterial.fingerprint,
      terminalFingerprint: 'AA:BB:CC',
      status: 'active',
      sasVerified: true,
      createdAt: '2026-10-01T00:00:00.000Z',
      activatedAt: '2026-10-01T00:00:00.000Z',
      revokedAt: null,
      revokedByDeviceId: null,
      revocationReason: null
    };
    await dbV2.saveAuthorization(authRec);
    await dbV2.saveLink(linkRec);
    await dbV2.close();

    const dbV4 = new VelDatabase('VelLocalDB_Stage1', VEL_DB_VERSION);
    const openedV4 = await dbV4.open();
    assert(VEL_DB_VERSION === 4 && openedV4.version === 4, 'VelDatabase abre y migra a versión 4');

    const expectedStores = [
      STORE_RECORDS,
      STORE_IDENTITY,
      STORE_CONFIG,
      STORE_AUTHORIZATIONS,
      STORE_LINKS,
      STORE_VAULT_FILES,
      STORE_VAULT_CHUNKS,
      STORE_ITEMS,
      STORE_INCOMING_CHUNKS
    ];
    assert(
      expectedStores.every((s) => openedV4.objectStoreNames.contains(s)),
      'Todos los ObjectStores de v1..v4 existen tras la migración'
    );

    const restoredIdentity = await dbV4.getIdentity();
    assert(
      restoredIdentity?.deviceId === savedIdentity.deviceId &&
        restoredIdentity.role === 'CORE' &&
        isPrivateKeyProtected(restoredIdentity.privateEcdhKey) &&
        (await dbV4.getConfig<{ theme: string }>('legacy_pref'))?.theme === 'dark',
      'La migración v2 -> v4 conserva intactos device_identity, CryptoKeys y configuraciones'
    );

    console.log('\n--- 3. VelLocalStore: Notas, fotos, archivos y validación de límites ---');
    const localStore = new VelLocalStore(dbV4);

    await assertRejects(
      () => localStore.saveNote('TERMINAL', 'Vacía', '   '),
      'Rechaza guardar nota sin texto'
    );

    const movNote = await localStore.saveNote('TERMINAL', 'Lista compras', 'Pan y leche');
    assert(
      movNote.syncStatus === 'pending' && movNote.kind === 'note' && movNote.ownerRole === 'TERMINAL',
      'Nota guardada en VEL MÓVIL arranca con syncStatus=pending'
    );

    const coreNote = await localStore.saveNote('CORE', 'Nota local CORE', 'Solo en casa');
    assert(
      coreNote.syncStatus === 'local_only' && coreNote.ownerRole === 'CORE',
      'Nota creada localmente en VEL CORE arranca con syncStatus=local_only'
    );

    await assertRejects(
      () =>
        localStore.saveLocalFile('TERMINAL', {
          name: 'gigante.mp4',
          type: 'video/mp4',
          size: MAX_VEL_FILE_BYTES + 1,
          blob: new Blob([new Uint8Array(8)])
        }),
      'Rechaza archivo que supera MAX_VEL_FILE_BYTES (100 MB)'
    );

    const photoBytes = makePatternBytes(64 * 1024, 55);
    const savedPhoto = await localStore.saveLocalFile('TERMINAL', {
      name: 'recibo.png',
      type: 'image/png',
      size: photoBytes.byteLength,
      blob: new Blob([toExactArrayBuffer(photoBytes)], { type: 'image/png' })
    });
    assert(
      savedPhoto.kind === 'photo' && savedPhoto.syncStatus === 'pending',
      'Foto guardada en MÓVIL queda clasificada y lista para enviarse'
    );

    console.log('\n--- 4. Recepción por fragmentos (128 KB) y reensamblaje bit a bit ---');
    const largeBytes = makePatternBytes(VEL_CHUNK_SIZE_BYTES * 2 + 17_321, 77);
    const totalChunks = Math.ceil(largeBytes.byteLength / VEL_CHUNK_SIZE_BYTES);
    const incomingId = 'FILE-INCOMING-001';

    for (let i = 0; i < totalChunks; i++) {
      const slice = largeBytes.subarray(i * VEL_CHUNK_SIZE_BYTES, (i + 1) * VEL_CHUNK_SIZE_BYTES);
      await localStore.stageIncomingChunk(incomingId, i, toExactArrayBuffer(slice));
    }

    const assembled = await localStore.finalizeIncomingFile({
      itemId: incomingId,
      title: 'video-familiar.mp4',
      fileKind: 'video',
      mimeType: 'video/mp4',
      sizeBytes: largeBytes.byteLength,
      totalChunks,
      sourceDeviceId: 'VEL-MOV-1234567890AB',
      createdAt: Date.now()
    });

    const assembledBytes = new Uint8Array(await assembled.blob!.arrayBuffer());
    assert(
      bytesEqual(assembledBytes, largeBytes) && assembled.syncStatus === 'synced',
      'Archivo multi-fragmento reensamblado bit a bit en vel_items'
    );
    assert(
      (await dbV4.getIncomingChunksByItemId(incomingId)).length === 0,
      'Los fragmentos temporales se limpian tras finalizar el archivo'
    );

    // Re-finalización idempotente si ya existe completo
    const idempotentAssembled = await localStore.finalizeIncomingFile({
      itemId: incomingId,
      title: 'video-familiar.mp4',
      fileKind: 'video',
      mimeType: 'video/mp4',
      sizeBytes: largeBytes.byteLength,
      totalChunks,
      sourceDeviceId: 'VEL-MOV-1234567890AB',
      createdAt: Date.now()
    });
    assert(idempotentAssembled.id === incomingId, 'Finalización idempotente si el item ya existía');

    const statsBeforeDelete = await localStore.getStats();
    assert(
      statsBeforeDelete.itemCount === 4 && statsBeforeDelete.totalBytes > largeBytes.byteLength,
      'getStats() suma correctamente elementos y bytes'
    );

    await localStore.deleteItem(savedPhoto.id);
    assert((await localStore.getItem(savedPhoto.id)) === null, 'deleteItem() elimina el elemento indicado');

    await dbV4.close();
  } finally {
    restoreGlobals();
  }

  console.log('\n==================================================================');
  console.log(`RESUMEN STAGE 1 (VEL LOCAL STORE v4): ${passed} PASS / ${failed} FAIL`);
  console.log('==================================================================');
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('\n[ERROR FATAL STAGE 1]:', err);
  process.exit(1);
});
