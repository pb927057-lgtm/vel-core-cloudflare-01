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

function makePatternBytes(size: number, seed = 42): Uint8Array {
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

function createMemoryUnifiedStorage(): VelUnifiedStorageAdapter & {
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
      incomingChunks.set(record.chunkKey, {
        ...record,
        data: record.data.slice(0)
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
      const parsedUrl = new URL(target, 'https://proyecto-vel.netlify.app');
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
  console.log('VEL 0.1 — PRUEBAS DE TRANSFERENCIA DIRECTA MÓVIL -> CORE');
  console.log('==================================================================\n');

  const testDir = path.join(process.cwd(), 'server-vel', 'test-data-stage2');
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

  const coreUid = 'uid-stage2-core';
  const movUid = 'uid-stage2-mov';

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
    WebSocketImpl: WebSocket
  });
  const movClient = new VelRelayClient({
    storage: movStorage,
    getFirebaseIdToken: async () => `valid-token-${movUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket
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
    console.log('--- 1. Conexión y emparejamiento en 1 paso (código numérico) ---');
    coreClient.connect(wssUrl);
    movClient.connect(wssUrl);
    await waitFor(
      () => coreClient.getState() === 'AUTHENTICATED' && movClient.getState() === 'AUTHENTICATED',
      4000,
      'Autenticación ambos clientes'
    );

    const session = coreClient.startCorePairingOffer();
    assert(Boolean(session && /^\d{6}$/.test(session.code)), `CORE genera código 6 dígitos (${session?.code})`);
    const claimed = movClient.claimPairingCode(session!.code);
    assert(claimed, 'MÓVIL envía código numérico de 6 dígitos');

    await waitFor(
      () =>
        coreClient.getState() === 'LINKED' &&
        movClient.getState() === 'LINKED' &&
        movClient.getSnapshot().peerOnline,
      3000,
      'Emparejamiento directo completado'
    );
    assert(true, 'Ambos teléfonos pasan a LINKED y se ven en línea');

    console.log('\n--- 2. Envío de nota: copia en ambos teléfonos y borrado independiente ---');
    await movManager.addNote('Clave WiFi casa', 'Red: CasaVel_5G / Clave: 99887766');

    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === 'Clave WiFi casa') &&
        movManager.getSnapshot().items.some((i) => i.title === 'Clave WiFi casa' && i.syncStatus === 'synced'),
      4000,
      'Nota sincronizada en ambos teléfonos'
    );

    const movNoteSummary = movManager.getSnapshot().items.find((i) => i.title === 'Clave WiFi casa')!;
    const coreNoteRecord = await coreLocalStore.getItem(movNoteSummary.id);
    assert(
      movNoteSummary.syncStatus === 'synced' &&
        coreNoteRecord?.textContent === 'Red: CasaVel_5G / Clave: 99887766',
      'Nota conservada en MÓVIL como synced y copiada en CORE'
    );

    console.log('\n--- 3. Envío de archivo multi-fragmento (>300 KB) ---');
    const binaryPayload = makePatternBytes(VEL_CHUNK_SIZE_BYTES * 2 + 45_123, 123);
    await movManager.addFiles([
      {
        name: 'foto-vacaciones.jpg',
        type: 'image/jpeg',
        size: binaryPayload.byteLength,
        blob: new Blob([toExactArrayBuffer(binaryPayload)], { type: 'image/jpeg' })
      }
    ]);

    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === 'foto-vacaciones.jpg') &&
        movManager.getSnapshot().items.some((i) => i.title === 'foto-vacaciones.jpg' && i.syncStatus === 'synced'),
      6000,
      'Archivo multi-fragmento copiado en CORE'
    );

    const movPhotoSummary = movManager.getSnapshot().items.find((i) => i.title === 'foto-vacaciones.jpg')!;
    const corePhotoRecord = await coreLocalStore.getItem(movPhotoSummary.id);
    const corePhotoBytes = new Uint8Array(await corePhotoRecord!.blob!.arrayBuffer());
    assert(
      bytesEqual(corePhotoBytes, binaryPayload) &&
        (await movLocalStore.getItem(movPhotoSummary.id)) !== null,
      'CORE reconstruye archivo bit a bit y MÓVIL conserva su copia local'
    );

    // Usuario borra del MÓVIL -> CORE conserva intacto
    await movManager.deleteFromThisPhone(movPhotoSummary.id);
    assert(
      (await movLocalStore.getItem(movPhotoSummary.id)) === null &&
        (await coreLocalStore.getItem(movPhotoSummary.id)) !== null,
      'Borrar de este móvil elimina solo en MÓVIL y deja intacta la copia en VEL CORE'
    );

    console.log('\n--- 4. Guardado offline en MÓVIL, conservación local al volver CORE y reintento manual ---');
    coreClient.disconnect();
    await waitFor(() => !movClient.getSnapshot().peerOnline, 3000, 'MÓVIL detecta CORE offline');

    await movManager.addNote('Nota offline', 'Escrita sin conexión con CORE');
    const offlineBytes = makePatternBytes(70_000, 321);
    await movManager.addFiles([
      {
        name: 'documento.pdf',
        type: 'application/pdf',
        size: offlineBytes.byteLength,
        blob: new Blob([toExactArrayBuffer(offlineBytes)], { type: 'application/pdf' })
      }
    ]);

    const pendingItems = movManager.getSnapshot().items.filter((i) => i.syncStatus === 'pending');
    assert(
      pendingItems.length === 2,
      'Los elementos guardados con CORE offline permanecen seguros en MÓVIL como pending'
    );

    // Reconectar CORE -> NO debe auto-enviar elementos pendientes hasta que el usuario toque Reintentar
    coreClient.connect(wssUrl);
    await waitFor(
      () => movClient.getState() === 'LINKED' && movClient.getSnapshot().peerOnline,
      5000,
      'Reconexión de CORE y enlace LINKED restablecido'
    );
    await new Promise((r) => setTimeout(r, 200));
    assert(
      !coreManager.getSnapshot().items.some((i) => i.title === 'Nota offline') &&
        !coreManager.getSnapshot().items.some((i) => i.title === 'documento.pdf') &&
        movManager.getSnapshot().items.filter((i) => i.syncStatus === 'pending').length === 2,
      'Al volver la conexión NO se envían automáticamente los elementos pendientes'
    );

    for (const p of pendingItems) {
      await movManager.retryItem(p.id);
    }
    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === 'Nota offline') &&
        coreManager.getSnapshot().items.some((i) => i.title === 'documento.pdf') &&
        movManager.getSnapshot().items.every((i) => i.syncStatus === 'synced'),
      6000,
      'Envío tras acción explícita Reintentar'
    );
    assert(true, 'Cola pendiente enviada únicamente tras pulsar Reintentar al reconectarse VEL CORE');

    // Verificar cero datos de archivos/notas en Firestore o disco del Relay
    const cloudDump = JSON.stringify({
      devices: Array.from(dbMemory.devices.values()),
      links: Array.from(dbMemory.links.values()),
      authorizations: Array.from(dbMemory.authorizations.values())
    });
    assert(
      !cloudDump.includes('CasaVel_5G') &&
        !cloudDump.includes('Escrita sin conexión') &&
        !cloudDump.includes('foto-vacaciones.jpg') &&
        !fs.existsSync(testDir),
      'Ni Firestore ni el servidor Relay almacenaron jamás notas ni archivos personales'
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
  console.log(`RESUMEN STAGE 2 (TRANSFERENCIA DIRECTA): ${passed} PASS / ${failed} FAIL`);
  console.log('==================================================================');
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('\n[ERROR FATAL STAGE 2]:', err);
  process.exit(1);
});
