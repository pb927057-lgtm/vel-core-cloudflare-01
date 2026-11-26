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
import { getVelConnectionDisplayStatus, VelRelayClient } from '../src/services/relayClient';
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

function makePatternBytes(size: number, seed = 91): Uint8Array {
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
    if (target.startsWith('/api/revoke-device')) {
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
  console.log('VEL 0.1 — PRUEBAS DE RECONEXIÓN Y FUNCIONAMIENTO SIN CONEXIÓN');
  console.log('==================================================================\n');

  const testDir = path.join(process.cwd(), 'server-vel', 'test-data-offline-reconnect');
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

  const coreUid = 'uid-offline-core';
  const movUid = 'uid-offline-mov';

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

  let movOnline = true;
  let coreOnline = true;

  const coreClient = new VelRelayClient({
    storage: coreStorage,
    getFirebaseIdToken: async () => `valid-token-${coreUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket,
    reconnectBaseDelayMs: 60,
    reconnectMaxDelayMs: 250,
    isNetworkOnline: () => coreOnline,
    heartbeatIntervalMs: 120,
    heartbeatTimeoutMs: 300
  });

  const movClient = new VelRelayClient({
    storage: movStorage,
    getFirebaseIdToken: async () => `valid-token-${movUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket,
    reconnectBaseDelayMs: 60,
    reconnectMaxDelayMs: 250,
    isNetworkOnline: () => movOnline,
    heartbeatIntervalMs: 120,
    heartbeatTimeoutMs: 300
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
    console.log('--- 1. Estados de conexión claros y emparejamiento inicial ---');
    assert(
      getVelConnectionDisplayStatus({ isNetworkOnline: false, connectionState: 'DISCONNECTED' }).label === 'SIN CONEXIÓN' &&
        getVelConnectionDisplayStatus({ isNetworkOnline: true, connectionState: 'CONNECTING' }).label === 'CONECTANDO' &&
        getVelConnectionDisplayStatus({ isNetworkOnline: true, connectionState: 'RECONNECTING' }).label === 'CONECTANDO' &&
        getVelConnectionDisplayStatus({ isNetworkOnline: true, connectionState: 'LINKED' }).label === 'CONECTADO' &&
        getVelConnectionDisplayStatus({ isNetworkOnline: true, connectionState: 'ERROR' }).label === 'ESTADO DESCONOCIDO' &&
        getVelConnectionDisplayStatus({ isNetworkOnline: true, connectionState: 'LINKED', revocationStatus: 'UNKNOWN' }).label === 'ESTADO DESCONOCIDO',
      'Mapeo correcto de estados: SIN CONEXIÓN, CONECTANDO, CONECTADO y ESTADO DESCONOCIDO'
    );

    const observedStates: string[] = [];
    const unsubMov = movClient.subscribe((s) => {
      observedStates.push(s.connectionState);
    });

    coreClient.connect(wssUrl);
    movClient.connect(wssUrl);
    await waitFor(
      () => coreClient.getState() === 'AUTHENTICATED' && movClient.getState() === 'AUTHENTICATED',
      5000,
      'CORE y MÓVIL autenticados en Relay'
    );

    const offer = coreClient.startCorePairingOffer();
    const claimed = Boolean(offer && movClient.claimPairingCode(offer.code));
    assert(claimed, 'Emparejamiento inicial iniciado correctamente');

    await waitFor(
      () =>
        coreClient.getState() === 'LINKED' &&
        movClient.getState() === 'LINKED' &&
        coreClient.getSnapshot().peerOnline &&
        movClient.getSnapshot().peerOnline,
      5000,
      'Estado LINKED en ambos dispositivos'
    );
    assert(
      observedStates.includes('CONNECTING') &&
        observedStates.includes('AUTHENTICATING') &&
        movClient.getState() === 'LINKED',
      'Transición de estados observada hasta CONECTADO (LINKED)'
    );

    console.log('\n--- 2. Pérdida de conexión, reconexión automática y NO auto-envío ---');
    movOnline = false;
    movClient.notifyNetworkOffline();
    await waitFor(() => movClient.getState() === 'DISCONNECTED', 3000, 'MÓVIL pasa a SIN CONEXIÓN');
    assert(
      getVelConnectionDisplayStatus({
        isNetworkOnline: movOnline,
        connectionState: movClient.getState()
      }).label === 'SIN CONEXIÓN',
      'Al perder Internet muestra SIN CONEXIÓN de inmediato'
    );

    // Esperar que no dispare reconexiones mientras no haya red
    await new Promise((r) => setTimeout(r, 200));
    assert(
      movClient.getState() === 'DISCONNECTED' && server.getActiveClientCount() === 1,
      'Sin red no intenta abrir sesiones duplicadas en Relay'
    );

    // Guardar nota y archivo multi-chunk localmente sin conexión
    await movManager.addNote('Nota offline segura', 'Contenido personal que no debe auto-enviarse');
    const pendingFileBytes = makePatternBytes(VEL_CHUNK_SIZE_BYTES + 12_500, 77);
    const expectedFileSha = await hashBlobIncremental(
      new Blob([toExactArrayBuffer(pendingFileBytes)], { type: 'application/octet-stream' }),
      VEL_CHUNK_SIZE_BYTES
    );
    await movManager.addFiles([
      {
        name: 'archivo-pendiente.bin',
        type: 'application/octet-stream',
        size: pendingFileBytes.byteLength,
        blob: new Blob([toExactArrayBuffer(pendingFileBytes)], { type: 'application/octet-stream' })
      }
    ]);

    const pendingAfterOffline = movManager.getSnapshot().items;
    assert(
      pendingAfterOffline.length === 2 &&
        pendingAfterOffline.every((i) => i.syncStatus === 'pending') &&
        coreManager.getSnapshot().items.length === 0,
      'Elementos creados sin conexión permanecen almacenados localmente en MÓVIL sin enviarse'
    );

    // Vuelve Internet -> reconecta automáticamente SIN duplicar sesiones y SIN auto-enviar
    movOnline = true;
    movClient.notifyNetworkOnline();
    await waitFor(
      () => movClient.getState() === 'LINKED' && movClient.getSnapshot().peerOnline,
      5000,
      'MÓVIL reconecta automáticamente al volver Internet'
    );
    await new Promise((r) => setTimeout(r, 300));
    assert(
      server.getActiveClientCount() === 2,
      `Reconexión automática sin duplicar sesiones en Relay (activas=${server.getActiveClientCount()})`
    );
    assert(
      coreManager.getSnapshot().items.length === 0 &&
        movManager.getSnapshot().items.filter((i) => i.syncStatus === 'pending').length === 2,
      'Tras volver la conexión NO se envía automáticamente la información personal pendiente'
    );

    console.log('\n--- 3. Botón REINTENTAR envía solo el ítem seleccionado con E2EE y SHA-256 ---');
    const pendingNote = movManager.getSnapshot().items.find((i) => i.title === 'Nota offline segura')!;
    const pendingFile = movManager.getSnapshot().items.find((i) => i.title === 'archivo-pendiente.bin')!;

    await movManager.retryItem(pendingNote.id);
    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.id === pendingNote.id) &&
        movManager.getSnapshot().items.find((i) => i.id === pendingNote.id)?.syncStatus === 'synced',
      5000,
      'Nota reintentada sincroniza con E2EE'
    );
    await new Promise((r) => setTimeout(r, 200));
    assert(
      !coreManager.getSnapshot().items.some((i) => i.id === pendingFile.id) &&
        movManager.getSnapshot().items.find((i) => i.id === pendingFile.id)?.syncStatus === 'pending',
      'Reintentar nota envía únicamente la nota elegida; el archivo pendiente sigue esperando acción del usuario'
    );

    await movManager.retryItem(pendingFile.id);
    await waitFor(
      () =>
        coreManager.getSnapshot().items.some((i) => i.id === pendingFile.id) &&
        movManager.getSnapshot().items.find((i) => i.id === pendingFile.id)?.syncStatus === 'synced',
      6000,
      'Archivo reintentado sincroniza con E2EE y SHA-256'
    );
    const coreFileRecord = await coreLocalStore.getItem(pendingFile.id);
    const coreFileBytes = coreFileRecord?.blob ? new Uint8Array(await coreFileRecord.blob.arrayBuffer()) : null;
    assert(
      Boolean(coreFileRecord) &&
        coreFileRecord?.sha256Hex === expectedFileSha &&
        coreFileBytes !== null &&
        bytesEqual(coreFileBytes, pendingFileBytes),
      'Reintento de archivo conserva E2EE y verificación SHA-256 bit a bit en VEL CORE'
    );

    console.log('\n--- 4. Sin confirmación -> ESTADO DESCONOCIDO y sin duplicados al reintentar ---');
    // Interceptar item_ack saliente de CORE para simular confirmación perdida en tránsito
    const originalCoreSend = coreClient.sendRelayPayload.bind(coreClient);
    let dropNextAck = true;
    (coreClient as any).sendRelayPayload = async (payload: any) => {
      if (dropNextAck && payload?.kind === 'item_ack') {
        dropNextAck = false;
        // Cortar conexión en MÓVIL justo antes de confirmar para simular corte previo al ACK
        movOnline = false;
        movClient.notifyNetworkOffline();
        return { routed: false, operationId: 'dropped-ack', reason: 'SIMULATED_ACK_LOSS' };
      }
      return originalCoreSend(payload);
    };

    await movManager.addNote('Nota ACK perdido', 'Contenido único sin duplicar');
    await waitFor(
      () => {
        const found = movManager.getSnapshot().items.find((i) => i.title === 'Nota ACK perdido');
        return (
          Boolean(found) &&
          found?.syncStatus === 'pending' &&
          Boolean(found?.errorMessage?.includes('ESTADO DESCONOCIDO'))
        );
      },
      5000,
      'MÓVIL marca ESTADO DESCONOCIDO cuando se corta antes de confirmar ACK'
    );
    assert(
      coreManager.getSnapshot().items.filter((i) => i.title === 'Nota ACK perdido').length === 1,
      'CORE recibió la nota aunque el ACK se perdió en tránsito'
    );

    // Restaurar red en MÓVIL y verificar que NO reenvía automáticamente ni marca synced
    movOnline = true;
    movClient.notifyNetworkOnline();
    await waitFor(() => movClient.getState() === 'LINKED' && movClient.getSnapshot().peerOnline, 5000, 'Reconexión tras ACK perdido');
    await new Promise((r) => setTimeout(r, 200));
    const unknownAckNote = movManager.getSnapshot().items.find((i) => i.title === 'Nota ACK perdido')!;
    assert(
      unknownAckNote.syncStatus === 'pending' &&
        Boolean(unknownAckNote.errorMessage?.includes('ESTADO DESCONOCIDO')),
      'Sin confirmación no afirma que se completó y conserva ESTADO DESCONOCIDO hasta que el usuario reintente'
    );

    // Usuario pulsa Reintentar -> CORE responde ACK idempotente y NO duplica la nota
    await movManager.retryItem(unknownAckNote.id);
    await waitFor(
      () => movManager.getSnapshot().items.find((i) => i.id === unknownAckNote.id)?.syncStatus === 'synced',
      5000,
      'Nota confirma tras reintento idempotente'
    );
    assert(
      coreManager.getSnapshot().items.filter((i) => i.title === 'Nota ACK perdido').length === 1,
      'Al reintentar tras reconexión NO se duplicó la nota en VEL CORE'
    );

    // Doble toque rápido en Reintentar sobre un archivo offline -> sin archivos duplicados
    coreOnline = false;
    coreClient.notifyNetworkOffline();
    await waitFor(() => !movClient.getSnapshot().peerOnline, 3000, 'CORE offline temporalmente');
    const dupBytes = makePatternBytes(25_000, 123);
    await movManager.addFiles([
      {
        name: 'archivo-sin-duplicar.dat',
        type: 'application/octet-stream',
        size: dupBytes.byteLength,
        blob: new Blob([toExactArrayBuffer(dupBytes)], { type: 'application/octet-stream' })
      }
    ]);
    const dupFileSummary = movManager.getSnapshot().items.find((i) => i.title === 'archivo-sin-duplicar.dat')!;
    coreOnline = true;
    coreClient.notifyNetworkOnline();
    await waitFor(() => movClient.getState() === 'LINKED' && movClient.getSnapshot().peerOnline, 5000, 'CORE vuelve online');

    await Promise.all([movManager.retryItem(dupFileSummary.id), movManager.retryItem(dupFileSummary.id)]);
    await waitFor(
      () => movManager.getSnapshot().items.find((i) => i.id === dupFileSummary.id)?.syncStatus === 'synced',
      5000,
      'Archivo doble-reintento completado'
    );
    assert(
      coreManager.getSnapshot().items.filter((i) => i.title === 'archivo-sin-duplicar.dat').length === 1,
      'Doble toque concurrente en Reintentar NO genera archivos duplicados en VEL CORE'
    );

    console.log('\n--- 5. Dispositivo revocado no puede volver a transferir información ---');
    const movId = movClient.getSnapshot().identity!.deviceId;
    const revokeOutcome = await coreClient.revokePairedTerminal(movId);
    assert(
      revokeOutcome.success && revokeOutcome.revocationStatus === 'CONFIRMED',
      'CORE revoca correctamente al dispositivo MÓVIL'
    );
    await waitFor(
      () => movClient.getState() === 'REVOKED',
      5000,
      'MÓVIL pasa a estado REVOKED'
    );

    const coreCountBeforeRevoked = coreManager.getSnapshot().items.length;
    await movManager.addNote('Nota tras revocación', 'No debe poder enviarse jamás');
    const revokedNote = movManager.getSnapshot().items.find((i) => i.title === 'Nota tras revocación')!;
    await movManager.retryItem(revokedNote.id);
    const directSendAfterRevoke = await movClient.sendRelayPayload({
      kind: 'note',
      itemId: 'blocked-direct',
      title: 'Directo bloqueado',
      textContent: 'No debe pasar',
      createdAt: Date.now()
    });
    await new Promise((r) => setTimeout(r, 200));

    assert(
      revokedNote.syncStatus === 'error' &&
        !directSendAfterRevoke.routed &&
        directSendAfterRevoke.reason === 'DEVICE_REVOKED' &&
        coreManager.getSnapshot().items.length === coreCountBeforeRevoked,
      'Dispositivo revocado queda bloqueado: ni addNote, ni retryItem ni sendRelayPayload transfieren información'
    );

    unsubMov();
  } finally {
    coreManager.dispose();
    movManager.dispose();
    coreClient.disconnect();
    movClient.disconnect();
    await server.stop();
    if (fs.existsSync(testDir)) fs.rmSync(testDir, { recursive: true, force: true });
  }

  console.log('\n==================================================================');
  console.log(`RESUMEN RECONEXIÓN Y OFFLINE: ${passed} PASS / ${failed} FAIL`);
  console.log('==================================================================');
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('\n[ERROR FATAL RECONEXIÓN Y OFFLINE]:', err);
  process.exit(1);
});
