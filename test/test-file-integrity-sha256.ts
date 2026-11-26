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
import { hashBlobIncremental, toExactArrayBuffer } from '../src/crypto/fileHash';
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

async function assertRejects(fn: () => Promise<unknown>, label: string): Promise<Error | null> {
  try {
    await fn();
    failed++;
    console.error(`✗ [FAIL] ${label} — no lanzó error`);
    return null;
  } catch (err: any) {
    passed++;
    console.log(`✓ [PASS] ${label}`);
    return err instanceof Error ? err : new Error(String(err));
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

function makePatternBytes(size: number, seed = 17): Uint8Array {
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

function createMemoryUnifiedStorage(options?: {
  onBeforePutChunk?: (record: VelIncomingChunkRecord) => VelIncomingChunkRecord;
}): VelUnifiedStorageAdapter & {
  items: Map<string, VelVaultItemRecord>;
  incomingChunks: Map<string, VelIncomingChunkRecord>;
} {
  let identity: LocalDeviceIdentityRecord | null = null;
  const config = new Map<string, any>();
  const auths = new Map<string, AuthorizationRecord>();
  const linksMap = new Map<string, DeviceLinkRecord>();
  const items = new Map<string, VelVaultItemRecord>();
  const incomingChunks = new Map<string, VelIncomingChunkRecord>();

  return {
    items,
    incomingChunks,
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
      const next = options?.onBeforePutChunk ? options.onBeforePutChunk(record) : record;
      incomingChunks.set(next.chunkKey, {
        ...next,
        data: next.data.slice(0)
      });
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
      const parsedUrl = new URL(target, 'https://proyecto-vel.pages.dev');
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

async function runTests() {
  console.log('==================================================================');
  console.log('VEL 0.1 — PRUEBAS DE INTEGRIDAD SHA-256 EN TRANSFERENCIAS E2EE');
  console.log('==================================================================\n');

  console.log('--- 1. Verificación directa en VelLocalStore.finalizeIncomingFile ---');
  const unitStorage = createMemoryUnifiedStorage();
  const unitStore = new VelLocalStore(unitStorage);

  const unitBytes = makePatternBytes(VEL_CHUNK_SIZE_BYTES + 2_048, 77);
  const unitExpectedHash = await hashBlobIncremental(new Blob([toExactArrayBuffer(unitBytes)]), VEL_CHUNK_SIZE_BYTES);
  const unitChunks = Math.ceil(unitBytes.byteLength / VEL_CHUNK_SIZE_BYTES);

  for (let i = 0; i < unitChunks; i++) {
    const slice = unitBytes.subarray(i * VEL_CHUNK_SIZE_BYTES, (i + 1) * VEL_CHUNK_SIZE_BYTES);
    await unitStore.stageIncomingChunk('UNIT-VALID-1', i, toExactArrayBuffer(slice));
  }

  const unitOk = await unitStore.finalizeIncomingFile({
    itemId: 'UNIT-VALID-1',
    title: 'unidad-valida.bin',
    fileKind: 'file',
    mimeType: 'application/octet-stream',
    sizeBytes: unitBytes.byteLength,
    totalChunks: unitChunks,
    sourceDeviceId: 'VEL-MOV-UNIT',
    createdAt: Date.now(),
    expectedSha256Hex: unitExpectedHash
  });
  assert(
    unitOk.sha256Hex === unitExpectedHash && unitStorage.incomingChunks.size === 0,
    'VelLocalStore guarda archivo válido con sha256Hex coincidente y limpia chunks'
  );

  // Archivo con 1 byte alterado manteniendo el mismo tamaño
  for (let i = 0; i < unitChunks; i++) {
    const slice = unitBytes.subarray(i * VEL_CHUNK_SIZE_BYTES, (i + 1) * VEL_CHUNK_SIZE_BYTES).slice();
    if (i === 1) {
      slice[0] = slice[0] ^ 0xff;
    }
    await unitStore.stageIncomingChunk('UNIT-BAD-1', i, toExactArrayBuffer(slice));
  }

  const unitErr = await assertRejects(
    () =>
      unitStore.finalizeIncomingFile({
        itemId: 'UNIT-BAD-1',
        title: 'unidad-alterada.bin',
        fileKind: 'file',
        mimeType: 'application/octet-stream',
        sizeBytes: unitBytes.byteLength,
        totalChunks: unitChunks,
        sourceDeviceId: 'VEL-MOV-UNIT',
        createdAt: Date.now(),
        expectedSha256Hex: unitExpectedHash
      }),
    'VelLocalStore rechaza archivo cuando 1 byte del fragmento fue alterado'
  );
  assert(
    Boolean(unitErr?.message.includes('SHA-256')) && (await unitStore.getItem('UNIT-BAD-1')) === null,
    'Archivo alterado no se guarda en el almacén de CORE'
  );

  console.log('\n--- 2. Transferencias E2EE completas (válida, fragmentada y alterada) ---');
  const testDir = path.join(process.cwd(), 'server-vel', 'test-data-sha256');
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

  const corruptedChunkItemTitles = new Set(['archivo-alterado.bin']);
  let corruptTargetItemId: string | null = null;

  const wireMessages: string[] = [];
  class SpyWebSocket extends WebSocket {
    override send(data: any, ...args: any[]) {
      if (typeof data === 'string') {
        wireMessages.push(data);
      }
      return (super.send as any)(data, ...args);
    }
  }

  const coreStorage = createMemoryUnifiedStorage({
    onBeforePutChunk: (record) => {
      if (corruptTargetItemId && record.itemId === corruptTargetItemId && record.chunkIndex === 1) {
        const copy = new Uint8Array(record.data.slice(0));
        copy[0] = copy[0] ^ 0x5a;
        return {
          ...record,
          data: toExactArrayBuffer(copy)
        };
      }
      return record;
    }
  });
  const movStorage = createMemoryUnifiedStorage();
  const coreLocalStore = new VelLocalStore(coreStorage);
  const movLocalStore = new VelLocalStore(movStorage);

  const coreUid = 'uid-sha256-core';
  const movUid = 'uid-sha256-mov';

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

  const coreClient = new VelRelayClient({
    storage: coreStorage,
    getFirebaseIdToken: async () => `valid-token-${coreUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: SpyWebSocket as any
  });
  const movClient = new VelRelayClient({
    storage: movStorage,
    getFirebaseIdToken: async () => `valid-token-${movUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: SpyWebSocket as any
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

  const coreErrors: Array<{ itemId: string; title?: string; error: string }> = [];
  const movErrors: Array<{ itemId: string; title?: string; error: string }> = [];
  coreManager.onTransferError((ev) => coreErrors.push(ev));
  movManager.onTransferError((ev) => movErrors.push(ev));

  try {
    coreClient.connect(wssUrl);
    movClient.connect(wssUrl);
    await waitFor(
      () => coreClient.getState() === 'AUTHENTICATED' && movClient.getState() === 'AUTHENTICATED',
      4000,
      'Autenticación ambos teléfonos'
    );

    const session = coreClient.startCorePairingOffer();
    movClient.claimPairingCode(session!.code);
    await waitFor(
      () =>
        coreClient.getState() === 'LINKED' &&
        movClient.getState() === 'LINKED' &&
        movClient.getSnapshot().peerOnline,
      4000,
      'Emparejamiento completado'
    );

    // 2a. Archivo correcto simple (1 fragmento)
    const smallBytes = makePatternBytes(18_500, 101);
    const smallExpectedHash = await hashBlobIncremental(
      new Blob([toExactArrayBuffer(smallBytes)]),
      VEL_CHUNK_SIZE_BYTES
    );

    await movManager.addFiles([
      {
        name: 'contrato-valido.pdf',
        type: 'application/pdf',
        size: smallBytes.byteLength,
        blob: new Blob([toExactArrayBuffer(smallBytes)], { type: 'application/pdf' })
      }
    ]);

    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === 'contrato-valido.pdf') &&
        movManager.getSnapshot().items.some((i) => i.title === 'contrato-valido.pdf' && i.syncStatus === 'synced'),
      6000,
      'Archivo válido simple sincronizado'
    );

    const movSmall = movManager.getSnapshot().items.find((i) => i.title === 'contrato-valido.pdf')!;
    const coreSmall = (await coreLocalStore.getItem(movSmall.id))!;
    const coreSmallBytes = new Uint8Array(await coreSmall.blob!.arrayBuffer());
    assert(
      movSmall.sha256Hex === smallExpectedHash &&
        coreSmall.sha256Hex === smallExpectedHash &&
        bytesEqual(coreSmallBytes, smallBytes),
      'Archivo válido simple: MÓVIL y CORE coinciden exactamente en contenido y SHA-256'
    );

    // 2b. Archivo correcto fragmentado (> 300 KB, múltiples bloques de 128 KB)
    const fragBytes = makePatternBytes(VEL_CHUNK_SIZE_BYTES * 2 + 65_432, 202);
    const fragExpectedHash = await hashBlobIncremental(
      new Blob([toExactArrayBuffer(fragBytes)]),
      VEL_CHUNK_SIZE_BYTES
    );

    await movManager.addFiles([
      {
        name: 'video-fragmentado.mp4',
        type: 'video/mp4',
        size: fragBytes.byteLength,
        blob: new Blob([toExactArrayBuffer(fragBytes)], { type: 'video/mp4' })
      }
    ]);

    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === 'video-fragmentado.mp4') &&
        movManager
          .getSnapshot()
          .items.some((i) => i.title === 'video-fragmentado.mp4' && i.syncStatus === 'synced'),
      8000,
      'Archivo fragmentado sincronizado'
    );

    const movFrag = movManager.getSnapshot().items.find((i) => i.title === 'video-fragmentado.mp4')!;
    const coreFrag = (await coreLocalStore.getItem(movFrag.id))!;
    const coreFragBytes = new Uint8Array(await coreFrag.blob!.arrayBuffer());
    assert(
      movFrag.sha256Hex === fragExpectedHash &&
        coreFrag.sha256Hex === fragExpectedHash &&
        bytesEqual(coreFragBytes, fragBytes),
      'Archivo fragmentado multi-bloque: contenido reconstruido y SHA-256 verificado bit a bit'
    );

    // Confirmar que ningún mensaje RELAY_DATA en tránsito filtró el sha256Hex ni el título en texto claro
    const relayDataFrames = wireMessages
      .map((raw) => {
        try {
          return JSON.parse(raw);
        } catch {
          return null;
        }
      })
      .filter((m) => m && m.type === 'RELAY_DATA');
    const relayWireJson = JSON.stringify(relayDataFrames);
    assert(
      relayDataFrames.length > 0 &&
        relayDataFrames.every((f) => f.payload?.kind === 'e2ee') &&
        !relayWireJson.includes(smallExpectedHash) &&
        !relayWireJson.includes(fragExpectedHash) &&
        !relayWireJson.includes('contrato-valido.pdf') &&
        !relayWireJson.includes('video-fragmentado.mp4'),
      'E2EE AES-GCM intacto: metadatos, bloques y hashes SHA-256 viajan cifrados en el sobre e2ee'
    );

    // 2c. Archivo alterado en transferencia fragmentada -> CORE rechaza e informa error a MÓVIL
    const badFileBytes = makePatternBytes(VEL_CHUNK_SIZE_BYTES + 12_345, 303);
    const savedBad = await movLocalStore.saveLocalFile('TERMINAL', {
      name: 'archivo-alterado.bin',
      type: 'application/octet-stream',
      size: badFileBytes.byteLength,
      blob: new Blob([toExactArrayBuffer(badFileBytes)], { type: 'application/octet-stream' })
    });
    if (corruptedChunkItemTitles.has(savedBad.title)) {
      corruptTargetItemId = savedBad.id;
    }
    await movManager.refresh();
    void movManager.flushPendingQueue();

    await waitFor(
      () => {
        const found = movManager.getSnapshot().items.find((i) => i.id === savedBad.id);
        return Boolean(found && found.syncStatus === 'error');
      },
      6000,
      'MÓVIL recibe rechazo SHA-256 de CORE'
    );

    const movBadSummary = movManager.getSnapshot().items.find((i) => i.id === savedBad.id)!;
    assert(
      movBadSummary.syncStatus === 'error' &&
        Boolean(movBadSummary.errorMessage?.includes('SHA-256')) &&
        (await coreLocalStore.getItem(savedBad.id)) === null &&
        coreStorage.incomingChunks.size === 0,
      'Archivo alterado en fragmento: CORE rechaza, limpia chunks y MÓVIL pasa a estado error con aviso SHA-256'
    );
    assert(
      coreErrors.some((e) => e.itemId === savedBad.id && e.error.includes('SHA-256')) &&
        movErrors.some((e) => e.itemId === savedBad.id && e.error.includes('SHA-256')),
      'CORE y MÓVIL emiten notificación explícita de error de integridad SHA-256'
    );

    // 2d. Hash inconsistente entre file_start y file_end enviado por canal E2EE -> CORE rechaza
    corruptTargetItemId = null;
    const inconsistentItemId = 'FILE-HASH-MISMATCH-2D';
    const rawChunk = makePatternBytes(1024, 404);
    const realHash = await hashBlobIncremental(new Blob([toExactArrayBuffer(rawChunk)]), VEL_CHUNK_SIZE_BYTES);
    const forgedHash = '0'.repeat(64);

    const ackPromise = new Promise<{ ok: boolean; error?: string }>((resolve) => {
      const prevHandler = (movClient as any).onDataHandler;
      movClient.setDataHandler(async (msg) => {
        if (msg.payload.kind === 'item_ack' && msg.payload.itemId === inconsistentItemId) {
          movClient.setDataHandler(prevHandler);
          resolve({ ok: msg.payload.ok, error: msg.payload.error });
          return;
        }
        if (prevHandler) await prevHandler(msg);
      });
    });

    await movClient.sendRelayPayload({
      kind: 'file_start',
      itemId: inconsistentItemId,
      fileKind: 'file',
      title: 'hash-forjado.bin',
      mimeType: 'application/octet-stream',
      sizeBytes: rawChunk.byteLength,
      totalChunks: 1,
      sha256Hex: realHash,
      createdAt: Date.now()
    });
    await movClient.sendRelayPayload({
      kind: 'file_chunk',
      itemId: inconsistentItemId,
      chunkIndex: 0,
      totalChunks: 1,
      dataBase64: Buffer.from(rawChunk).toString('base64')
    });
    await movClient.sendRelayPayload({
      kind: 'file_end',
      itemId: inconsistentItemId,
      totalChunks: 1,
      sizeBytes: rawChunk.byteLength,
      sha256Hex: forgedHash
    });

    const ack2d = await ackPromise;
    assert(
      !ack2d.ok &&
        Boolean(ack2d.error?.includes('SHA-256')) &&
        (await coreLocalStore.getItem(inconsistentItemId)) === null &&
        coreStorage.incomingChunks.size === 0,
      'Hash inconsistente entre file_start y file_end es rechazado con ACK negativo y limpieza'
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
  console.log(`RESUMEN PRUEBA INTEGRIDAD SHA-256: ${passed} PASS / ${failed} FAIL`);
  console.log('==================================================================');
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('\n[ERROR FATAL SHA-256]:', err);
  process.exit(1);
});
