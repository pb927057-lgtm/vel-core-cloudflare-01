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
import { isPrivateKeyProtected } from '../src/crypto/deviceCrypto';
import { toExactArrayBuffer } from '../src/crypto/fileHash';
import { VelUnifiedStorageAdapter } from '../src/db/db';
import { VelLocalStore } from '../src/db/velLocalStore';
import { setupNewDeviceIdentity } from '../src/services/deviceIdentityService';
import { VelRelayClient } from '../src/services/relayClient';
import { VelTransferManager } from '../src/services/transferManager';
import { VelRelayServer } from '../server-vel/relay-server';
import { registerDeviceHandler } from '../netlify/functions/register-device';
import { deviceSessionHandler } from '../netlify/functions/device-session';
import { revokeDeviceHandler } from '../netlify/functions/revoke-device';
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

function createMemoryUnifiedStorage(): VelUnifiedStorageAdapter & {
  items: Map<string, VelVaultItemRecord>;
} {
  let identity: LocalDeviceIdentityRecord | null = null;
  const config = new Map<string, any>();
  const auths = new Map<string, AuthorizationRecord>();
  const linksMap = new Map<string, DeviceLinkRecord>();
  const items = new Map<string, VelVaultItemRecord>();
  const incomingChunks = new Map<string, VelIncomingChunkRecord>();

  return {
    items,
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

function makeFetchAdapter(
  dbMemory: ReturnType<typeof createInMemoryFirestoreDeviceStore>,
  options?: { failRevokeEndpoint?: () => boolean }
) {
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
    if (target.startsWith('/api/revoke-device')) {
      if (options?.failRevokeEndpoint?.()) {
        throw new Error('Network unreachable');
      }
      const res = await revokeDeviceHandler(
        { httpMethod: method, headers, body },
        { verifyToken, hasDbCredentials: () => true, getDeviceStore: () => dbMemory.store }
      );
      return new Response(res.body, { status: res.statusCode, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`Endpoint inesperado: ${target}`);
  }) as typeof fetch;
}

async function runTests() {
  console.log('==================================================================');
  console.log('VEL 0.1 — PRUEBAS DE REEMPLAZO DE TELÉFONO MÓVIL DESDE VEL CORE');
  console.log('==================================================================\n');

  const testDir = path.join(process.cwd(), 'server-vel', 'test-data-replace-mobile');
  if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });

  const dbMemory = createInMemoryFirestoreDeviceStore();
  let simulateOfflineServerFailure = false;
  const fetchAdapter = makeFetchAdapter(dbMemory, {
    failRevokeEndpoint: () => simulateOfflineServerFailure
  });
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
  const mov1Storage = createMemoryUnifiedStorage();
  const mov2Storage = createMemoryUnifiedStorage();
  const mov3Storage = createMemoryUnifiedStorage();

  const coreLocalStore = new VelLocalStore(coreStorage);
  const mov1LocalStore = new VelLocalStore(mov1Storage);
  const mov2LocalStore = new VelLocalStore(mov2Storage);

  const coreUid = 'uid-replace-core';
  const mov1Uid = 'uid-replace-mov1';
  const mov2Uid = 'uid-replace-mov2';
  const mov3Uid = 'uid-replace-mov3';

  await setupNewDeviceIdentity('CORE', undefined, {
    storage: coreStorage,
    ensureAnonymousAuth: async () => ({ success: true, uid: coreUid, idToken: `valid-token-${coreUid}` }),
    fetchFn: fetchAdapter
  });
  await setupNewDeviceIdentity('TERMINAL', undefined, {
    storage: mov1Storage,
    ensureAnonymousAuth: async () => ({ success: true, uid: mov1Uid, idToken: `valid-token-${mov1Uid}` }),
    fetchFn: fetchAdapter
  });

  const coreClient = new VelRelayClient({
    storage: coreStorage,
    getFirebaseIdToken: async () => `valid-token-${coreUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket
  });
  const mov1Client = new VelRelayClient({
    storage: mov1Storage,
    getFirebaseIdToken: async () => `valid-token-${mov1Uid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket
  });

  const coreManager = new VelTransferManager({
    relayClient: coreClient,
    role: 'CORE',
    store: coreLocalStore
  });
  const mov1Manager = new VelTransferManager({
    relayClient: mov1Client,
    role: 'TERMINAL',
    store: mov1LocalStore
  });

  const wireSpyEnvelopes: Array<{ linkId: string; senderId: string }> = [];
  class SpyMov2Socket extends WebSocket {
    override send(data: any, ...args: any[]) {
      if (typeof data === 'string') {
        try {
          const parsed = JSON.parse(data);
          if (parsed?.type === 'RELAY_DATA') {
            wireSpyEnvelopes.push({ linkId: parsed.linkId, senderId: parsed.senderId });
          }
        } catch {}
      }
      return (super.send as any)(data, ...args);
    }
  }

  let mov2Client: VelRelayClient | null = null;
  let mov2Manager: VelTransferManager | null = null;

  try {
    console.log('--- 1. Emparejamiento inicial CORE <-> MÓVIL 1 y respaldo previo ---');
    coreClient.connect(wssUrl);
    mov1Client.connect(wssUrl);
    await waitFor(
      () => coreClient.getState() === 'AUTHENTICATED' && mov1Client.getState() === 'AUTHENTICATED',
      4000,
      'Autenticación inicial CORE y MÓVIL 1'
    );

    const offer1 = coreClient.startCorePairingOffer();
    mov1Client.claimPairingCode(offer1!.code);
    await waitFor(
      () => coreClient.getState() === 'LINKED' && mov1Client.getState() === 'LINKED',
      4000,
      'Emparejamiento CORE <-> MÓVIL 1'
    );

    const coreInitial = (await coreStorage.getIdentity())!;
    const mov1Initial = (await mov1Storage.getIdentity())!;
    const link1Id = coreInitial.activeLinkId!;

    await mov1Manager.addNote('Nota histórica CORE', 'Debe sobrevivir al reemplazo de móvil');
    const filePayload = new TextEncoder().encode('archivo-previo-al-reemplazo-vel');
    await mov1Manager.addFiles([
      {
        name: 'respaldo-previo.txt',
        type: 'text/plain',
        size: filePayload.byteLength,
        blob: new Blob([toExactArrayBuffer(filePayload)], { type: 'text/plain' })
      }
    ]);
    await waitFor(
      () =>
        coreManager.getSnapshot().items.length === 2 &&
        mov1Manager.getSnapshot().items.every((i) => i.syncStatus === 'synced'),
      5000,
      'Datos previos copiados en CORE'
    );

    console.log('\n--- 2. Reemplazo exitoso con MÓVIL 1 conectado -> revocación + MÓVIL 2 con E2EE nueva ---');
    const replaceRes = await coreClient.replacePairedMobile();
    await waitFor(() => mov1Client.getState() === 'REVOKED', 3000, 'MÓVIL 1 pasa a REVOKED en vivo');

    assert(
      replaceRes.success &&
        replaceRes.persistedInFirestore &&
        replaceRes.disconnectedLive &&
        replaceRes.revocationStatus === 'CONFIRMED',
      'replacePairedMobile revoca en servidor y desconecta al MÓVIL 1 en vivo'
    );

    const coreAfterRevoke1 = (await coreStorage.getIdentity())!;
    assert(
      coreAfterRevoke1.deviceId === coreInitial.deviceId &&
        coreAfterRevoke1.registrationStatus === 'registered' &&
        coreAfterRevoke1.pairedPeerDeviceId === null &&
        coreAfterRevoke1.activeLinkId === null &&
        coreManager.getSnapshot().items.length === 2,
      'CORE conserva identidad y datos locales tras revocar MÓVIL 1'
    );

    // El nuevo teléfono recibe identidad y credenciales propias
    await setupNewDeviceIdentity('TERMINAL', undefined, {
      storage: mov2Storage,
      ensureAnonymousAuth: async () => ({ success: true, uid: mov2Uid, idToken: `valid-token-${mov2Uid}` }),
      fetchFn: fetchAdapter
    });
    const mov2Initial = (await mov2Storage.getIdentity())!;
    assert(
      mov2Initial.deviceId !== mov1Initial.deviceId &&
        mov2Initial.publicKeySpkiBase64 !== mov1Initial.publicKeySpkiBase64 &&
        isPrivateKeyProtected(mov2Initial.privateEcdhKey),
      'MÓVIL 2 genera identidad y credenciales criptográficas propias'
    );

    mov2Client = new VelRelayClient({
      storage: mov2Storage,
      getFirebaseIdToken: async () => `valid-token-${mov2Uid}`,
      fetchFn: fetchAdapter,
      WebSocketImpl: SpyMov2Socket as any
    });
    mov2Manager = new VelTransferManager({
      relayClient: mov2Client,
      role: 'TERMINAL',
      store: mov2LocalStore
    });

    mov2Client.connect(wssUrl);
    await waitFor(() => mov2Client!.getState() === 'AUTHENTICATED', 4000, 'MÓVIL 2 autenticado');

    const offer2 = coreClient.startCorePairingOffer();
    assert(Boolean(offer2 && /^\d{6}$/.test(offer2.code)), 'CORE genera código habitual para el nuevo MÓVIL 2');
    mov2Client.claimPairingCode(offer2!.code);
    await waitFor(
      () => coreClient.getState() === 'LINKED' && mov2Client!.getState() === 'LINKED',
      4000,
      'Emparejamiento CORE <-> MÓVIL 2'
    );

    const coreLinked2 = (await coreStorage.getIdentity())!;
    const mov2Linked = (await mov2Storage.getIdentity())!;
    assert(
      coreLinked2.activeLinkId !== null &&
        coreLinked2.activeLinkId !== link1Id &&
        coreLinked2.pairedPeerDeviceId === mov2Initial.deviceId &&
        coreLinked2.pairedPeerPublicKeySpkiBase64 === mov2Initial.publicKeySpkiBase64 &&
        mov2Linked.pairedPeerPublicKeySpkiBase64 === coreInitial.publicKeySpkiBase64 &&
        coreClient.getSnapshot().revocationStatus === 'NONE',
      'Nuevo emparejamiento establece nueva sesión vinculada con claves E2EE propias'
    );

    assert(
      mov2Manager.getSnapshot().items.length === 0 && coreManager.getSnapshot().items.length === 2,
      'No se copian datos personales de CORE automáticamente al nuevo MÓVIL 2'
    );

    await mov2Manager.addNote('Desde MÓVIL 2', 'Transferencia cifrada tras reemplazo');
    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.title === 'Desde MÓVIL 2') &&
        mov2Manager!.getSnapshot().items.every((i) => i.syncStatus === 'synced'),
      5000,
      'MÓVIL 2 transfiere datos cifrados a CORE'
    );
    assert(
      wireSpyEnvelopes.some(
        (e) => e.linkId === coreLinked2.activeLinkId && e.senderId === mov2Initial.deviceId
      ) && coreManager.getSnapshot().items.length === 3,
      'MÓVIL 2 transfiere con la nueva sesión E2EE y CORE conserva copias previas + nuevas (3 items)'
    );

    console.log('\n--- 3. Rechazo definitivo del teléfono anterior (MÓVIL 1) ---');
    const mov1ReconnectRejected = await new Promise<boolean>((resolve) => {
      const c = new VelRelayClient({
        storage: mov1Storage,
        getFirebaseIdToken: async () => `valid-token-${mov1Uid}`,
        fetchFn: fetchAdapter,
        WebSocketImpl: WebSocket
      });
      const unsub = c.onStateChange((st) => {
        if (st === 'REVOKED') {
          unsub();
          c.disconnect();
          resolve(true);
        }
      });
      c.connect(wssUrl);
      setTimeout(() => {
        c.disconnect();
        resolve(false);
      }, 3000);
    });
    assert(mov1ReconnectRejected, 'MÓVIL 1 anterior no puede volver a conectarse al Relay (REVOKED)');

    const rawAuthRejection = await new Promise<boolean>((resolve) => {
      const ws = new WebSocket(wssUrl);
      ws.on('message', (raw) => {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'AUTH_CHALLENGE') {
          ws.send(
            JSON.stringify({
              type: 'AUTH',
              deviceId: mov1Initial.deviceId,
              role: 'TERMINAL',
              pairedCoreId: coreInitial.deviceId,
              firebaseIdToken: `valid-token-${mov1Uid}`,
              timestamp: Date.now()
            })
          );
        } else if (msg.type === 'AUTH_ERROR' && msg.error === 'DEVICE_REVOKED') {
          resolve(true);
        }
      });
      setTimeout(() => {
        try {
          ws.close();
        } catch {}
        resolve(false);
      }, 3000);
    });
    assert(rawAuthRejection, 'Relay rechaza intento directo de autenticación o envío del MÓVIL 1 (DEVICE_REVOKED)');

    console.log('\n--- 4. Revocación pendiente cuando el teléfono anterior está desconectado ---');
    mov2Client.disconnect();
    await waitFor(() => mov2Client!.getState() === 'DISCONNECTED', 2000, 'MÓVIL 2 desconectado');

    const offlinePeerRes = await coreClient.replacePairedMobile();
    assert(
      offlinePeerRes.success &&
        offlinePeerRes.persistedInFirestore &&
        !offlinePeerRes.disconnectedLive &&
        coreClient.getSnapshot().revocationStatus === 'PERSISTED_PEER_OFFLINE' &&
        Boolean(coreClient.getSnapshot().revocationDetail?.includes('REVOCACIÓN PENDIENTE')),
      'Con móvil anterior desconectado, CORE muestra REVOCACIÓN PENDIENTE (PERSISTED_PEER_OFFLINE) tras confirmación del servidor'
    );

    // Comprobar que MÓVIL 2 tampoco puede reconectarse tras haber sido revocado estando offline
    const mov2BlockedAfterOfflineRevoke = await new Promise<boolean>((resolve) => {
      const c = new VelRelayClient({
        storage: mov2Storage,
        getFirebaseIdToken: async () => `valid-token-${mov2Uid}`,
        fetchFn: fetchAdapter,
        WebSocketImpl: WebSocket
      });
      const unsub = c.onStateChange((st) => {
        if (st === 'REVOKED') {
          unsub();
          c.disconnect();
          resolve(true);
        }
      });
      c.connect(wssUrl);
      setTimeout(() => {
        c.disconnect();
        resolve(false);
      }, 3000);
    });
    assert(mov2BlockedAfterOfflineRevoke, 'MÓVIL 2 revocado estando offline queda bloqueado al intentar reconectarse');

    // Emparejar un MÓVIL 3 para probar ahora falla de servidor / CORE sin conexión
    await setupNewDeviceIdentity('TERMINAL', undefined, {
      storage: mov3Storage,
      ensureAnonymousAuth: async () => ({ success: true, uid: mov3Uid, idToken: `valid-token-${mov3Uid}` }),
      fetchFn: fetchAdapter
    });
    const mov3Client = new VelRelayClient({
      storage: mov3Storage,
      getFirebaseIdToken: async () => `valid-token-${mov3Uid}`,
      fetchFn: fetchAdapter,
      WebSocketImpl: WebSocket
    });
    mov3Client.connect(wssUrl);
    await waitFor(() => mov3Client.getState() === 'AUTHENTICATED', 3000, 'MÓVIL 3 autenticado');
    const offer3 = coreClient.startCorePairingOffer();
    mov3Client.claimPairingCode(offer3!.code);
    await waitFor(
      () => coreClient.getState() === 'LINKED' && mov3Client.getState() === 'LINKED',
      3000,
      'CORE <-> MÓVIL 3 emparejado'
    );

    console.log('\n--- 5. Sin confirmación del servidor -> ESTADO DESCONOCIDO (no afirma revocación) ---');
    coreClient.disconnect();
    simulateOfflineServerFailure = true;
    const unknownRes = await coreClient.replacePairedMobile();
    const coreAfterFailedRevoke = (await coreStorage.getIdentity())!;
    const mov3Initial = (await mov3Storage.getIdentity())!;

    assert(
      !unknownRes.success &&
        !unknownRes.persistedInFirestore &&
        coreClient.getSnapshot().revocationStatus === 'UNKNOWN' &&
        Boolean(coreClient.getSnapshot().revocationDetail?.includes('ESTADO DESCONOCIDO')) &&
        coreAfterFailedRevoke.pairedPeerDeviceId === mov3Initial.deviceId &&
        coreAfterFailedRevoke.registrationStatus === 'paired',
      'Sin confirmación del servidor, CORE reporta ESTADO DESCONOCIDO y no afirma haber revocado el móvil'
    );

    mov3Client.disconnect();
  } finally {
    coreManager.dispose();
    mov1Manager.dispose();
    mov2Manager?.dispose();
    coreClient.disconnect();
    mov1Client.disconnect();
    mov2Client?.disconnect();
    await server.stop();
    if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });
  }

  console.log('\n==================================================================');
  console.log(`RESUMEN PRUEBA REEMPLAZO DE MÓVIL: ${passed} PASS / ${failed} FAIL`);
  console.log('==================================================================');
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('\n[ERROR FATAL REEMPLAZO DE MÓVIL]:', err);
  process.exit(1);
});
