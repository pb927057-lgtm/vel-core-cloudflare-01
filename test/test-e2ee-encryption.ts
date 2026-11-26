import WebSocket from 'ws';
import fs from 'fs';
import path from 'path';
import {
  AuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  LocalDeviceIdentityRecord,
  VelIncomingChunkRecord,
  VelVaultItemRecord
} from '../src/contracts/velContracts';
import {
  decryptAesGcmJson,
  deriveSharedAesGcmKey,
  encryptAesGcmJson,
  generateDeviceCryptoMaterial,
  isPrivateKeyProtected
} from '../src/crypto/deviceCrypto';
import { toExactArrayBuffer } from '../src/crypto/fileHash';
import { VelUnifiedStorageAdapter } from '../src/db/db';
import { VEL_CHUNK_SIZE_BYTES, VelLocalStore } from '../src/db/velLocalStore';
import { setupNewDeviceIdentity } from '../src/services/deviceIdentityService';
import { VelRelayClient } from '../src/services/relayClient';
import { VelTransferManager } from '../src/services/transferManager';
import { VelRelayServer } from '../server-vel/relay-server';
import { registerDeviceHandler } from '../netlify/functions/register-device';
import { deviceSessionHandler } from '../netlify/functions/device-session';
import {
  DeviceTransactionContext,
  DeviceTransactionStore
} from '../netlify/functions/shared/deviceAuthService';

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

async function waitFor(predicate: () => boolean, timeoutMs = 8000, label = 'condición'): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`Timeout (${timeoutMs}ms) esperando: ${label}`);
}

function makePatternBytes(size: number, seed = 77): Uint8Array {
  const out = new Uint8Array(size);
  let x = seed >>> 0;
  for (let i = 0; i < size; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out[i] = (x >>> 24) & 0xff;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function createMemoryUnifiedStorage(): VelUnifiedStorageAdapter {
  let identity: LocalDeviceIdentityRecord | null = null;
  const config = new Map<string, any>();
  const auths = new Map<string, AuthorizationRecord>();
  const linksMap = new Map<string, DeviceLinkRecord>();
  const items = new Map<string, VelVaultItemRecord>();
  const incomingChunks = new Map<string, VelIncomingChunkRecord>();

  return {
    async getIdentity() {
      return identity;
    },
    async saveIdentity(record) {
      identity = { ...record };
    },
    async clearIdentity() {
      identity = null;
    },
    async getConfig<T>(key: string) {
      return config.has(key) ? (config.get(key) as T) : null;
    },
    async setConfig(key: string, value: unknown) {
      config.set(key, value);
    },
    async deleteConfig(key: string) {
      config.delete(key);
    },
    async getAuthorization(authorizationId: string) {
      return auths.get(authorizationId) || null;
    },
    async saveAuthorization(record: AuthorizationRecord) {
      auths.set(record.authorizationId, { ...record });
    },
    async getLink(linkId: string) {
      return linksMap.get(linkId) || null;
    },
    async saveLink(record: DeviceLinkRecord) {
      linksMap.set(record.linkId, { ...record });
    },
    async putItem(record) {
      items.set(record.id, { ...record });
    },
    async getItem(id) {
      const found = items.get(id);
      return found ? { ...found } : null;
    },
    async getAllItems() {
      return Array.from(items.values()).map((r) => ({ ...r }));
    },
    async deleteItem(id) {
      items.delete(id);
    },
    async putIncomingChunk(record) {
      incomingChunks.set(record.chunkKey, { ...record, data: record.data.slice(0) });
    },
    async getIncomingChunksByItemId(itemId) {
      const rows: VelIncomingChunkRecord[] = [];
      for (const c of incomingChunks.values()) {
        if (c.itemId === itemId) rows.push({ ...c, data: c.data.slice(0) });
      }
      rows.sort((a, b) => a.chunkIndex - b.chunkIndex);
      return rows;
    },
    async deleteIncomingChunksByItemId(itemId) {
      let deleted = 0;
      for (const [k, c] of incomingChunks.entries()) {
        if (c.itemId === itemId) {
          incomingChunks.delete(k);
          deleted++;
        }
      }
      return deleted;
    },
    async close() {}
  };
}

function createInMemoryFirestoreDeviceStore() {
  const devices = new Map<string, DeviceRecord>();
  const links = new Map<string, DeviceLinkRecord>();
  const authorizations = new Map<string, AuthorizationRecord>();

  const store: DeviceTransactionStore = {
    async runTransaction<T>(fn: (ctx: DeviceTransactionContext) => Promise<T>): Promise<T> {
      const ctx: DeviceTransactionContext = {
        async getDevice(deviceId) {
          const found = devices.get(deviceId);
          return found ? { ...found } : null;
        },
        createDevice(record) {
          devices.set(record.deviceId, { ...record });
        },
        updateDevice(deviceId, patch) {
          const current = devices.get(deviceId);
          if (!current) throw new Error(`Missing device ${deviceId}`);
          devices.set(deviceId, { ...current, ...patch });
        },
        async getLink(linkId) {
          const found = links.get(linkId);
          return found ? { ...found } : null;
        },
        createLink(record) {
          links.set(record.linkId, { ...record });
        },
        updateLink(linkId, patch) {
          const current = links.get(linkId);
          if (!current) throw new Error(`Missing link ${linkId}`);
          links.set(linkId, { ...current, ...patch });
        },
        async getAuthorizationByLink(linkId) {
          const found = authorizations.get(linkId);
          return found ? { ...found } : null;
        },
        createAuthorization(record) {
          authorizations.set(record.authorizationId, { ...record });
        },
        updateAuthorization(authorizationId, patch) {
          const current = authorizations.get(authorizationId);
          if (!current) throw new Error(`Missing auth ${authorizationId}`);
          authorizations.set(authorizationId, { ...current, ...patch });
        }
      };
      return fn(ctx);
    }
  };

  return { store, devices, links, authorizations };
}

function makeVerifyTokenFn() {
  return async (authHeader?: string) => {
    if (!authHeader || !authHeader.startsWith('Bearer valid-token-')) {
      return { authenticated: false as const, reason: 'invalid_token' as const, message: 'Token inválido.' };
    }
    return { authenticated: true as const, uid: authHeader.replace('Bearer valid-token-', '').trim(), email: '' };
  };
}

function makeFetchAdapter(dbMemory: ReturnType<typeof createInMemoryFirestoreDeviceStore>) {
  const verifyToken = makeVerifyTokenFn();
  return (async (url: RequestInfo | URL, init?: RequestInit) => {
    const target = String(url);
    const method = (init?.method || 'GET').toUpperCase();
    const headers = (init?.headers || {}) as Record<string, string>;
    const body = typeof init?.body === 'string' ? init.body : undefined;

    if (target.startsWith('/api/register-device')) {
      const res = await registerDeviceHandler(
        { httpMethod: method, headers, body },
        { verifyToken, hasDbCredentials: () => true, getDeviceStore: () => dbMemory.store }
      );
      return new Response(res.body, { status: res.statusCode, headers: { 'Content-Type': 'application/json' } });
    }
    if (target.startsWith('/api/device-session')) {
      const parsedUrl = new URL(target, 'https://vel-test.local');
      const res = await deviceSessionHandler(
        {
          httpMethod: method,
          headers,
          queryStringParameters: Object.fromEntries(parsedUrl.searchParams.entries()),
          body
        },
        { verifyToken, hasDbCredentials: () => true, getDeviceStore: () => dbMemory.store }
      );
      return new Response(res.body, { status: res.statusCode, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`Endpoint inesperado: ${target}`);
  }) as typeof fetch;
}

/**
 * Envuelve WebSocket para capturar exactamente qué viaja por la red hacia el Relay.
 */
function createWireSpyWebSocketClass(capturedOutgoingFrames: string[], capturedIncomingFrames: string[]) {
  return class SpyWebSocket extends WebSocket {
    constructor(address: string) {
      super(address);
      this.on('message', (data) => {
        capturedIncomingFrames.push(data.toString());
      });
    }

    send(data: any, ...rest: any[]) {
      capturedOutgoingFrames.push(typeof data === 'string' ? data : data?.toString?.() || '');
      return super.send(data, ...rest);
    }
  };
}

function mutateBase64FirstByte(b64: string): string {
  const buf = Buffer.from(b64, 'base64');
  buf[0] = buf[0] ^ 0xff;
  return buf.toString('base64');
}

async function runTests() {
  console.log('==================================================================');
  console.log('VEL 0.1 — PRUEBAS DE CIFRADO E2EE (ECDH P-256 + AES-256-GCM)');
  console.log('==================================================================\n');

  // ------------------------------------------------------------------
  // 1. Prueba unitaria directa de ECDH P-256 + AES-256-GCM
  // ------------------------------------------------------------------
  console.log('--- 1. Derivación ECDH P-256 y rechazo por alteración en AES-256-GCM ---');
  const matCore = await generateDeviceCryptoMaterial('CORE');
  const matMov = await generateDeviceCryptoMaterial('TERMINAL');
  const matIntruder = await generateDeviceCryptoMaterial('TERMINAL');

  const keyCore = await deriveSharedAesGcmKey(matCore.ecdhKeyPair.privateKey, matMov.publicKeySpkiBase64);
  const keyMov = await deriveSharedAesGcmKey(matMov.ecdhKeyPair.privateKey, matCore.publicKeySpkiBase64);
  const keyIntruder = await deriveSharedAesGcmKey(
    matIntruder.ecdhKeyPair.privateKey,
    matCore.publicKeySpkiBase64
  );

  assert(
    isPrivateKeyProtected(matCore.ecdhKeyPair.privateKey) &&
      isPrivateKeyProtected(matMov.ecdhKeyPair.privateKey) &&
      keyCore.extractable === false &&
      keyMov.extractable === false,
    'Claves privadas ECDH y clave compartida AES-256-GCM son no exportables (extractable=false)'
  );

  const encSample = await encryptAesGcmJson(
    keyMov,
    { msg: 'SECRETO_E2EE_VEL', num: 12345 },
    'LNK-1|ITEM-1'
  );
  const decSample = await decryptAesGcmJson<{ msg: string; num: number }>(
    keyCore,
    encSample.ivBase64,
    encSample.ciphertextBase64,
    'LNK-1|ITEM-1'
  );
  assert(
    decSample.msg === 'SECRETO_E2EE_VEL' && decSample.num === 12345,
    'MÓVIL cifra con AES-256-GCM y CORE descifra usando clave compartida ECDH P-256'
  );

  let rejectedTamperedCipher = false;
  try {
    await decryptAesGcmJson(
      keyCore,
      encSample.ivBase64,
      mutateBase64FirstByte(encSample.ciphertextBase64),
      'LNK-1|ITEM-1'
    );
  } catch {
    rejectedTamperedCipher = true;
  }
  assert(rejectedTamperedCipher, 'AES-256-GCM rechaza ciphertext alterado');

  let rejectedTamperedIv = false;
  try {
    await decryptAesGcmJson(
      keyCore,
      mutateBase64FirstByte(encSample.ivBase64),
      encSample.ciphertextBase64,
      'LNK-1|ITEM-1'
    );
  } catch {
    rejectedTamperedIv = true;
  }
  assert(rejectedTamperedIv, 'AES-256-GCM rechaza IV alterado');

  let rejectedWrongKey = false;
  try {
    await decryptAesGcmJson(
      keyIntruder,
      encSample.ivBase64,
      encSample.ciphertextBase64,
      'LNK-1|ITEM-1'
    );
  } catch {
    rejectedWrongKey = true;
  }
  assert(rejectedWrongKey, 'Un tercero no emparejado no puede descifrar el mensaje');

  // ------------------------------------------------------------------
  // 2. Flujo completo sobre Relay: Nota y Archivo multi-chunk cifrados
  // ------------------------------------------------------------------
  console.log('\n--- 2. Transferencia real MÓVIL -> Relay -> CORE verificando cero texto claro ---');
  const testDir = path.join(process.cwd(), 'server-vel', 'test-data-e2ee-real');
  if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });

  const dbMemory = createInMemoryFirestoreDeviceStore();
  const fetchAdapter = makeFetchAdapter(dbMemory);
  const verifyToken = makeVerifyTokenFn();

  const server = new VelRelayServer({
    port: 0,
    storageDir: testDir,
    deviceStore: dbMemory.store,
    verifyToken,
    hasDbCredentials: () => true,
    heartbeatIntervalMs: 60_000,
    authTimeoutMs: 5_000
  });
  const port = await server.start();
  const wssUrl = `ws://127.0.0.1:${port}`;

  const coreStorage = createMemoryUnifiedStorage();
  const movStorage = createMemoryUnifiedStorage();
  const coreLocalStore = new VelLocalStore(coreStorage);
  const movLocalStore = new VelLocalStore(movStorage);

  const coreUid = 'uid-e2ee-core';
  const movUid = 'uid-e2ee-mov';

  await setupNewDeviceIdentity('CORE', undefined, {
    storage: coreStorage,
    ensureAnonymousAuth: async () => ({ success: true, uid: coreUid, idToken: `valid-token-${coreUid}` }),
    fetchFn: fetchAdapter
  });
  await setupNewDeviceIdentity('TERMINAL', undefined, {
    storage: movStorage,
    ensureAnonymousAuth: async () => ({ success: true, uid: movUid, idToken: `valid-token-${movUid}` }),
    fetchFn: fetchAdapter
  });

  const wireMovOut: string[] = [];
  const wireMovIn: string[] = [];
  const wireCoreOut: string[] = [];
  const wireCoreIn: string[] = [];

  const coreClient = new VelRelayClient({
    storage: coreStorage,
    getFirebaseIdToken: async () => `valid-token-${coreUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: createWireSpyWebSocketClass(wireCoreOut, wireCoreIn)
  });
  const movClient = new VelRelayClient({
    storage: movStorage,
    getFirebaseIdToken: async () => `valid-token-${movUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: createWireSpyWebSocketClass(wireMovOut, wireMovIn)
  });

  const coreManager = new VelTransferManager({
    relayClient: coreClient,
    role: 'CORE',
    store: coreLocalStore
  });
  const movManager = new VelTransferManager({
    relayClient: movClient,
    role: 'TERMINAL',
    store: movLocalStore
  });

  try {
    coreClient.connect(wssUrl);
    movClient.connect(wssUrl);
    await waitFor(
      () => coreClient.getState() === 'AUTHENTICATED' && movClient.getState() === 'AUTHENTICATED',
      4000,
      'Autenticación inicial'
    );

    const session = coreClient.startCorePairingOffer();
    movClient.claimPairingCode(session!.code);
    await waitFor(
      () =>
        coreClient.getState() === 'LINKED' &&
        movClient.getState() === 'LINKED' &&
        movClient.getSnapshot().peerOnline,
      3000,
      'Emparejamiento completado'
    );

    // 2a. Envío de nota secreta
    const secretNoteTitle = 'PinTarjetaBancaria';
    const secretNoteBody = 'CLAVE_ULTRA_SECRETA_987654';
    await movManager.addNote(secretNoteTitle, secretNoteBody);

    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === secretNoteTitle) &&
        movManager.getSnapshot().items.some((i) => i.title === secretNoteTitle && i.syncStatus === 'synced'),
      5000,
      'Nota cifrada recibida y descifrada en CORE'
    );

    const coreNote = coreManager.getSnapshot().items.find((i) => i.title === secretNoteTitle)!;
    assert(
      coreNote.textContent === secretNoteBody,
      'CORE descifra y guarda la nota exacta recibida desde MÓVIL'
    );

    // 2b. Envío de archivo multi-chunk (>300 KB)
    const secretFileName = 'contrato-confidencial-vel.pdf';
    const secretBytes = makePatternBytes(VEL_CHUNK_SIZE_BYTES * 2 + 17_321, 99);
    await movManager.addFiles([
      {
        name: secretFileName,
        type: 'application/pdf',
        size: secretBytes.byteLength,
        blob: new Blob([toExactArrayBuffer(secretBytes)], { type: 'application/pdf' })
      }
    ]);

    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === secretFileName) &&
        movManager.getSnapshot().items.some((i) => i.title === secretFileName && i.syncStatus === 'synced'),
      6000,
      'Archivo cifrado recibido y descifrado en CORE'
    );

    const movFileSummary = movManager.getSnapshot().items.find((i) => i.title === secretFileName)!;
    const coreFileRecord = await coreLocalStore.getItem(movFileSummary.id);
    const coreFileBytes = new Uint8Array(await coreFileRecord!.blob!.arrayBuffer());
    assert(
      bytesEqual(coreFileBytes, secretBytes),
      'CORE descifra cada bloque AES-256-GCM y reconstruye el archivo bit a bit'
    );

    // 2c. Verificar que lo que viajó por el Relay NO tiene texto claro
    const allWireRelayData = [...wireMovOut, ...wireCoreIn]
      .filter((raw) => raw.includes('"type":"RELAY_DATA"'))
      .map((raw) => JSON.parse(raw));

    const firstChunkSampleBase64 = Buffer.from(secretBytes.slice(0, 64)).toString('base64');
    const wireJsonDump = JSON.stringify(allWireRelayData);
    const allHaveE2eeEnvelope =
      allWireRelayData.length >= 4 &&
      allWireRelayData.every(
        (m) =>
          m.payload?.kind === 'e2ee' &&
          m.payload?.v === 1 &&
          typeof m.payload?.ivBase64 === 'string' &&
          typeof m.payload?.ciphertextBase64 === 'string'
      );

    assert(
      allHaveE2eeEnvelope &&
        !wireJsonDump.includes(secretNoteTitle) &&
        !wireJsonDump.includes(secretNoteBody) &&
        !wireJsonDump.includes(secretFileName) &&
        !wireJsonDump.includes(firstChunkSampleBase64),
      'El Relay solo transportó sobres kind="e2ee" cifrados, sin título, texto, nombre de archivo ni bytes legibles'
    );

    // ------------------------------------------------------------------
    // 3. Rechazo de datos alterados o en texto claro recibidos por CORE
    // ------------------------------------------------------------------
    console.log('\n--- 3. Rechazo de datos alterados o sin cifrar en CORE ---');
    const securityErrorsOnCore: string[] = [];
    coreClient.onSecurityError((reason) => securityErrorsOnCore.push(reason));
    const coreItemsBeforeTamper = coreManager.getSnapshot().items.length;

    const coreStoredNow = (await coreStorage.getIdentity())!;
    const movStoredNow = (await movStorage.getIdentity())!;
    const linkId = coreStoredNow.activeLinkId!;

    // Interceptar un paquete cifrado válido y alterarlo antes de reenviarlo por el socket de MÓVIL
    const sharedForTamperTest = await deriveSharedAesGcmKey(
      movStoredNow.privateEcdhKey,
      coreStoredNow.publicKeySpkiBase64
    );
    const validEnc = await encryptAesGcmJson(
      sharedForTamperTest,
      {
        kind: 'note',
        itemId: 'NOTE-TAMPERED-1',
        title: 'Nota Alterada',
        textContent: 'ESTO_NO_DEBE_GUARDARSE',
        createdAt: Date.now()
      },
      `${linkId}|NOTE-TAMPERED-1`
    );

    // 3a. Enviar paquete con ciphertext alterado
    const rawMovWs = (movClient as any).ws as WebSocket;
    rawMovWs.send(
      JSON.stringify({
        type: 'RELAY_DATA',
        senderId: movStoredNow.deviceId,
        recipientId: coreStoredNow.deviceId,
        linkId,
        operationId: 'op-tamper-cipher-1',
        payload: {
          kind: 'e2ee',
          v: 1,
          itemId: 'NOTE-TAMPERED-1',
          ivBase64: validEnc.ivBase64,
          ciphertextBase64: mutateBase64FirstByte(validEnc.ciphertextBase64)
        },
        timestamp: Date.now()
      })
    );

    // 3b. Enviar paquete en texto plano (sin cifrado E2EE)
    rawMovWs.send(
      JSON.stringify({
        type: 'RELAY_DATA',
        senderId: movStoredNow.deviceId,
        recipientId: coreStoredNow.deviceId,
        linkId,
        operationId: 'op-plaintext-attack-1',
        payload: {
          kind: 'note',
          itemId: 'NOTE-PLAINTEXT-1',
          title: 'Texto Claro Prohibido',
          textContent: 'ESTO_TAMPOCO_DEBE_GUARDARSE',
          createdAt: Date.now()
        },
        timestamp: Date.now()
      })
    );

    await waitFor(
      () => securityErrorsOnCore.length >= 2,
      3000,
      'CORE reporta rechazo de ambos paquetes inválidos'
    );
    await new Promise((r) => setTimeout(r, 150));

    assert(
      coreManager.getSnapshot().items.length === coreItemsBeforeTamper &&
        !coreManager.getSnapshot().items.some((i) => i.id === 'NOTE-TAMPERED-1' || i.id === 'NOTE-PLAINTEXT-1'),
      'CORE rechaza paquetes alterados y paquetes sin cifrar sin guardar nada'
    );

    // ------------------------------------------------------------------
    // 4. Si falla el cifrado, nunca se envía información en texto claro
    // ------------------------------------------------------------------
    console.log('\n--- 4. Fallo de cifrado aborta el envío sin enviar texto claro ---');
    const brokenMovId = (await movStorage.getIdentity())!;
    await movStorage.saveIdentity({
      ...brokenMovId,
      pairedPeerPublicKeySpkiBase64: 'CLAVE_INVALIDA_CORRUPTA'
    });
    (movClient as any).invalidateSharedKeyCache();

    const framesBeforeFailure = wireMovOut.length;
    await movManager.addNote('Nota No Enviable', 'NUNCA_DEBE_SALIR_EN_TEXTO_CLARO');

    await waitFor(
      () => movManager.getSnapshot().items.some((i) => i.title === 'Nota No Enviable' && i.syncStatus === 'error'),
      3000,
      'Item marcado en error al fallar cifrado'
    );

    const newFramesDuringFailure = wireMovOut.slice(framesBeforeFailure);
    assert(
      newFramesDuringFailure.length === 0 &&
        !newFramesDuringFailure.join('\n').includes('NUNCA_DEBE_SALIR_EN_TEXTO_CLARO'),
      'Si falla el cifrado, VEL aborta con error y no transmite ningún dato en texto claro por WebSocket'
    );
  } finally {
    coreManager.dispose();
    movManager.dispose();
    coreClient.disconnect();
    movClient.disconnect();
    await server.stop();
    if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });
  }

  console.log('\n==================================================================');
  console.log(`RESUMEN PRUEBAS CIFRADO E2EE (VEL 0.1): ${passed} PASS / ${failed} FAIL`);
  console.log('==================================================================');
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('\n[ERROR FATAL EN PRUEBAS E2EE]:', err);
  process.exit(1);
});
