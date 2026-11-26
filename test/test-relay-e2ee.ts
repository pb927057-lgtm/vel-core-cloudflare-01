import WebSocket from 'ws';
import fs from 'fs';
import path from 'path';
import {
  AuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  LocalDeviceIdentityRecord
} from '../src/contracts/velContracts';
import {
  generateDeviceCryptoMaterial,
  isPrivateKeyProtected
} from '../src/crypto/deviceCrypto';
import { VelStorageAdapter } from '../src/db/db';
import { setupNewDeviceIdentity } from '../src/services/deviceIdentityService';
import { VelRelayClient } from '../src/services/relayClient';
import { VelRelayServer } from '../server-vel/relay-server';
import { registerDeviceHandler } from '../netlify/functions/register-device';
import { deviceSessionHandler } from '../netlify/functions/device-session';
import { pairingConfirmHandler } from '../netlify/functions/pairing-confirm';
import { revokeDeviceHandler } from '../netlify/functions/revoke-device';
import { relayConfigHandler } from '../netlify/functions/relay-config';
import {
  DeviceTransactionContext,
  DeviceTransactionStore
} from '../netlify/functions/shared/deviceAuthService';

let passed = 0;
let failed = 0;

function assert(condition: boolean, label: string, detail?: string) {
  if (condition) {
    passed++;
    console.log(`✓ [PASS] ${label}`);
  } else {
    failed++;
    console.error(`✗ [FAIL] ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 4000,
  label = 'condición'
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`Timeout (${timeoutMs}ms) esperando: ${label}`);
}

function createPersistentStorageStub(): VelStorageAdapter {
  let identity: LocalDeviceIdentityRecord | null = null;
  const config = new Map<string, any>();
  const auths = new Map<string, AuthorizationRecord>();
  const linksMap = new Map<string, DeviceLinkRecord>();

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
    }
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
      return {
        authenticated: false as const,
        reason: 'invalid_token' as const,
        message: 'Token Firebase inválido o faltante.'
      };
    }
    const uid = authHeader.replace('Bearer valid-token-', '').trim();
    return { authenticated: true as const, uid, email: '' };
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
    if (target.startsWith('/api/pairing-confirm')) {
      const res = await pairingConfirmHandler(
        { httpMethod: method, headers, body },
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
    throw new Error(`Endpoint no esperado: ${target}`);
  }) as typeof fetch;
}

async function signChallengeInline(privateKey: CryptoKey, challenge: string, deviceId: string, ts: number) {
  const canonical = `VEL-RELAY-AUTH-v1|${challenge}|${deviceId}|${ts}`;
  const sig = await globalThis.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(canonical)
  );
  return Buffer.from(sig).toString('base64');
}

async function runTests() {
  console.log('========================================================================');
  console.log('VEL 0.1 — PRUEBAS DE RELAY DIRECTO, EMPAREJAMIENTO 1-PASO Y REVOCACIÓN');
  console.log('========================================================================\n');

  const testStorageDir = path.join(process.cwd(), 'server-vel', 'test-data-relay-direct');
  if (fs.existsSync(testStorageDir)) {
    fs.rmSync(testStorageDir, { recursive: true, force: true });
  }

  const dbMemory = createInMemoryFirestoreDeviceStore();
  const fetchAdapter = makeFetchAdapter(dbMemory);
  const verifyToken = makeVerifyTokenFn();

  console.log('--- 0. Configuración de /api/relay-config ---');
  const unconfRes = await relayConfigHandler({ httpMethod: 'GET' }, {});
  const unconfJson = JSON.parse(unconfRes.body);
  assert(
    unconfRes.statusCode === 200 && unconfJson.configured === false && unconfJson.wssUrl === null,
    'Sin VEL_RELAY_WSS_URL en entorno de función, /api/relay-config reporta configured=false'
  );

  const server = new VelRelayServer({
    port: 0,
    storageDir: testStorageDir,
    deviceStore: dbMemory.store,
    verifyToken,
    hasDbCredentials: () => true,
    heartbeatIntervalMs: 60_000,
    authTimeoutMs: 5_000
  });
  const port = await server.start();
  const wssUrl = `ws://127.0.0.1:${port}`;

  const confRes = await relayConfigHandler({ httpMethod: 'GET' }, { VEL_RELAY_WSS_URL: 'wss://server-vel.onrender.com/' });
  const confJson = JSON.parse(confRes.body);
  assert(
    confJson.configured === true && confJson.wssUrl === 'wss://server-vel.onrender.com',
    '/api/relay-config entrega URL WSS configurada limpia'
  );

  const healthResp = await fetch(`http://127.0.0.1:${port}/health`);
  const healthJson = await healthResp.json();
  assert(
    healthResp.status === 200 &&
      healthJson.status === 'UP' &&
      healthJson.protocol === 'VEL-RELAY-v3-DIRECT' &&
      healthJson.firebaseAdminConfigured === true,
    'Endpoint /health responde VEL-RELAY-v3-DIRECT operativo'
  );

  const coreStorage = createPersistentStorageStub();
  const movStorage = createPersistentStorageStub();
  const coreUid = 'anon-core-uid-relay-1';
  const movUid = 'anon-mov-uid-relay-2';

  const coreSetup = await setupNewDeviceIdentity('CORE', undefined, {
    storage: coreStorage,
    ensureAnonymousAuth: async () => ({ success: true, uid: coreUid, idToken: `valid-token-${coreUid}` }),
    fetchFn: fetchAdapter
  });
  const movSetup = await setupNewDeviceIdentity('TERMINAL', undefined, {
    storage: movStorage,
    ensureAnonymousAuth: async () => ({ success: true, uid: movUid, idToken: `valid-token-${movUid}` }),
    fetchFn: fetchAdapter
  });
  assert(coreSetup.success && movSetup.success, 'CORE y MÓVIL registrados con identidades independientes en Firestore');

  const coreLocal = (await coreStorage.getIdentity())!;
  const movLocal = (await movStorage.getIdentity())!;

  console.log('\n--- 1. Seguridad de autenticación Firebase en Relay ---');
  const legacyPathReject = await new Promise<boolean>((resolve) => {
    const s = new WebSocket(`${wssUrl}/ws/${coreLocal.deviceId}`);
    s.on('close', (code) => resolve(code === 4001));
  });
  assert(legacyPathReject, 'Ruta heredada sin autenticación /ws/{deviceId} es rechazada (4001)');

  const spoofUidReject = await new Promise<boolean>((resolve) => {
    const s = new WebSocket(wssUrl);
    s.on('message', (raw) => {
      const m = JSON.parse(raw.toString());
      if (m.type === 'AUTH_CHALLENGE') {
        s.send(
          JSON.stringify({
            type: 'AUTH',
            deviceId: coreLocal.deviceId,
            role: 'CORE',
            firebaseIdToken: 'valid-token-attacker-uid',
            timestamp: Date.now()
          })
        );
      }
    });
    s.on('close', (code) => resolve(code === 4003));
  });
  assert(spoofUidReject, 'Rechaza token Firebase cuyo UID no es propietario de dispositivos/{deviceId}');

  const badSigReject = await new Promise<boolean>((resolve) => {
    const s = new WebSocket(wssUrl);
    s.on('message', async (raw) => {
      const m = JSON.parse(raw.toString());
      if (m.type === 'AUTH_CHALLENGE') {
        const fakeSigner = await generateDeviceCryptoMaterial('CORE');
        const ts = Date.now();
        const sig = await signChallengeInline(fakeSigner.signingKeyPair.privateKey, m.challenge, coreLocal.deviceId, ts);
        s.send(
          JSON.stringify({
            type: 'AUTH',
            deviceId: coreLocal.deviceId,
            role: 'CORE',
            firebaseIdToken: `valid-token-${coreUid}`,
            challenge: m.challenge,
            signatureBase64: sig,
            timestamp: ts
          })
        );
      }
    });
    s.on('close', (code) => resolve(code === 4001));
  });
  assert(badSigReject, 'Si un cliente envía firma ECDSA opcional alterada, también se rechaza (4001)');

  console.log('\n--- 2. Conexión directa y emparejamiento 1-paso (código de 6 dígitos) ---');
  const coreClient = new VelRelayClient({
    storage: coreStorage,
    getFirebaseIdToken: async () => `valid-token-${coreUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket,
    reconnectBaseDelayMs: 60,
    reconnectMaxDelayMs: 250
  });
  const movClient = new VelRelayClient({
    storage: movStorage,
    getFirebaseIdToken: async () => `valid-token-${movUid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket,
    reconnectBaseDelayMs: 60,
    reconnectMaxDelayMs: 250
  });

  coreClient.connect(wssUrl);
  movClient.connect(wssUrl);

  await waitFor(
    () => coreClient.getState() === 'AUTHENTICATED' && movClient.getState() === 'AUTHENTICATED',
    4000,
    'Autenticación directa de ambos teléfonos'
  );
  assert(true, 'CORE y MÓVIL autentican directamente con Firebase Auth sin bloqueos por CryptoKey');

  const offerSession = coreClient.startCorePairingOffer();
  assert(Boolean(offerSession && /^\d{6}$/.test(offerSession.code)), `CORE genera código numérico de 6 dígitos (${offerSession?.code})`);

  await waitFor(
    () => coreClient.getSnapshot().pairingSession?.stage === 'OFFERING' && Boolean(coreClient.getSnapshot().pairingSession?.linkId),
    2000,
    'Oferta registrada en Relay'
  );

  const claimStarted = movClient.claimPairingCode(offerSession!.code);
  assert(claimStarted, 'MÓVIL ingresa el código de 6 dígitos en un solo paso');

  await waitFor(
    () => coreClient.getState() === 'LINKED' && movClient.getState() === 'LINKED',
    3000,
    'Emparejamiento en 1 paso completado en ambos teléfonos'
  );

  const persistedCore = dbMemory.devices.get(coreLocal.deviceId)!;
  const persistedMov = dbMemory.devices.get(movLocal.deviceId)!;
  const persistedLink = dbMemory.links.get(persistedCore.activeLinkId!)!;
  const persistedAuth = dbMemory.authorizations.get(persistedCore.activeLinkId!)!;
  assert(
    persistedCore.status === 'paired' &&
      persistedMov.status === 'paired' &&
      persistedLink.status === 'active' &&
      persistedAuth.status === 'active',
    'Vinculación y autorización guardadas atómicamente en Firestore'
  );

  // Reutilización del código ya usado debe fallar
  const reuseRejected = await new Promise<boolean>((resolve) => {
    const s = new WebSocket(wssUrl);
    s.on('message', (raw) => {
      const m = JSON.parse(raw.toString());
      if (m.type === 'PAIRING_ERROR') resolve(true);
    });
    s.on('open', () => {
      s.send(JSON.stringify({ type: 'PAIRING_CLAIM', code: offerSession!.code, claimerDeviceId: 'VEL-MOV-ZZZZZZZZZZZZ' }));
    });
    setTimeout(() => s.close(), 1000);
  });
  assert(reuseRejected, 'Código ya utilizado no puede reutilizarse');

  console.log('\n--- 3. Transmisión directa RELAY_DATA y comportamiento offline honesto ---');
  const receivedOnCore: string[] = [];
  coreClient.setDataHandler(async (msg) => {
    if (msg.payload.kind === 'note') {
      receivedOnCore.push(msg.payload.textContent);
      await coreClient.sendRelayPayload({
        kind: 'item_ack',
        itemId: msg.payload.itemId,
        ok: true,
        confirmedAt: Date.now()
      });
    }
  });

  const ackReceived = new Promise<boolean>((resolve) => {
    movClient.setDataHandler((msg) => {
      if (msg.payload.kind === 'item_ack' && msg.payload.itemId === 'ITEM-TEST-1' && msg.payload.ok) {
        resolve(true);
      }
    });
  });

  const routeRes = await movClient.sendRelayPayload({
    kind: 'note',
    itemId: 'ITEM-TEST-1',
    title: 'Recuerdo',
    textContent: 'DATO_DIRECTO_TELEFONO_A_TELEFONO',
    createdAt: Date.now()
  });

  assert(
    routeRes.routed && (await ackReceived) && receivedOnCore.includes('DATO_DIRECTO_TELEFONO_A_TELEFONO'),
    'Nota viaja directo MÓVIL -> Relay (RAM) -> CORE con ACK de confirmación'
  );

  coreClient.disconnect();
  await waitFor(() => !movClient.getSnapshot().peerOnline, 2000, 'MÓVIL ve a CORE desconectado');

  const offlineRoute = await movClient.sendRelayPayload({
    kind: 'note',
    itemId: 'ITEM-TEST-OFFLINE',
    title: 'Offline',
    textContent: 'NO_GUARDAR_EN_NUBE',
    createdAt: Date.now()
  });
  assert(!offlineRoute.routed && offlineRoute.reason === 'RECIPIENT_OFFLINE', 'Con CORE apagado devuelve RECIPIENT_OFFLINE sin encolar en la nube');

  console.log('\n--- 4. Continuidad tras reinicio del Relay y revocación remota ---');
  movClient.disconnect();
  await server.stop();

  const restartedServer = new VelRelayServer({
    port: 0,
    storageDir: testStorageDir,
    deviceStore: dbMemory.store,
    verifyToken,
    hasDbCredentials: () => true,
    heartbeatIntervalMs: 60_000,
    authTimeoutMs: 5_000
  });
  const port2 = await restartedServer.start();
  const wssUrl2 = `ws://127.0.0.1:${port2}`;

  coreClient.connect(wssUrl2);
  movClient.connect(wssUrl2);
  await waitFor(
    () => coreClient.getState() === 'LINKED' && movClient.getState() === 'LINKED',
    4000,
    'Reconexión automática tras reinicio del Relay'
  );
  assert(true, 'Las vinculaciones en Firestore sobreviven al reinicio del Relay');

  const revokeOutcome = await coreClient.revokePairedTerminal(movLocal.deviceId, 'Pérdida de teléfono');
  assert(
    revokeOutcome.success && revokeOutcome.persistedInFirestore && revokeOutcome.disconnectedLive,
    'Desvincular desde CORE desconecta en vivo y persiste en Firestore'
  );

  await waitFor(() => movClient.getState() === 'REVOKED', 3000, 'MÓVIL pasa a estado REVOKED');

  const revokedReconnectBlocked = await new Promise<boolean>((resolve) => {
    const s = new WebSocket(wssUrl2);
    s.on('message', (raw) => {
      const m = JSON.parse(raw.toString());
      if (m.type === 'AUTH_CHALLENGE') {
        s.send(
          JSON.stringify({
            type: 'AUTH',
            deviceId: movLocal.deviceId,
            role: 'TERMINAL',
            firebaseIdToken: `valid-token-${movUid}`,
            timestamp: Date.now()
          })
        );
      }
    });
    s.on('close', (code) => resolve(code === 4003));
  });
  assert(revokedReconnectBlocked, 'MÓVIL desvinculado queda bloqueado para reconectarse (4003)');

  console.log('\n--- 5. Verificación de cero datos personales y cero claves privadas en la nube ---');
  const finalCoreStored = (await coreStorage.getIdentity())!;
  assert(
    isPrivateKeyProtected(finalCoreStored.privateEcdhKey) &&
      isPrivateKeyProtected(finalCoreStored.privateSigningKey),
    'Claves locales mantienen extractable=false'
  );

  const firestoreSnapshotJson = JSON.stringify({
    devices: Array.from(dbMemory.devices.values()),
    links: Array.from(dbMemory.links.values()),
    authorizations: Array.from(dbMemory.authorizations.values())
  });
  assert(
    !firestoreSnapshotJson.includes('DATO_DIRECTO_TELEFONO_A_TELEFONO') &&
      !firestoreSnapshotJson.includes('NO_GUARDAR_EN_NUBE') &&
      !firestoreSnapshotJson.includes('privateKey') &&
      !fs.existsSync(testStorageDir),
    'Ni Firestore ni el disco del Relay contienen contenido personal ni claves privadas'
  );

  coreClient.disconnect();
  movClient.disconnect();
  await restartedServer.stop();
  if (fs.existsSync(testStorageDir)) {
    fs.rmSync(testStorageDir, { recursive: true, force: true });
  }

  console.log('\n========================================================================');
  console.log(`RESUMEN PRUEBAS RELAY DIRECTO (VEL 0.1): ${passed} PASS / ${failed} FAIL`);
  console.log('========================================================================');
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error('\n[ERROR FATAL EN PRUEBAS RELAY]:', err);
  process.exit(1);
});
