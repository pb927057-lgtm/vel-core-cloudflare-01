import fs from 'fs';
import path from 'path';
import WebSocket from 'ws';
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
import {
  loadPersistedDeviceIdentity,
  savePendingSubscriptionPass,
  setupNewDeviceIdentity,
  syncPersistedDeviceSession
} from '../src/services/deviceIdentityService';
import { VelRelayClient } from '../src/services/relayClient';
import { VelTransferManager } from '../src/services/transferManager';
import { createSubscriptionPass } from '../netlify/functions/shared/subscriptionAccess';
import type { SuscriptorAdminRecord } from '../netlify/functions/shared/types';
import { VelRelayServer } from '../server-vel/relay-server';
import { registerDeviceHandler } from '../netlify/functions/register-device';
import { deviceSessionHandler } from '../netlify/functions/device-session';
import { pairingConfirmHandler } from '../netlify/functions/pairing-confirm';
import { revokeDeviceHandler } from '../netlify/functions/revoke-device';
import { handler as getPricingHandler } from '../netlify/functions/get-pricing';
import { downloadPackageHandler } from '../netlify/functions/download-package';
import {
  DeviceTransactionContext,
  DeviceTransactionStore
} from '../netlify/functions/shared/deviceAuthService';
import {
  CURRENT_CONTRACT_VERSION,
  isDraftContractVersion,
  isTechnicalAccount,
  OFFICIAL_CONTRACT_URL
} from '../src/services/firestore';

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

async function waitFor(predicate: () => boolean, timeoutMs = 4500, label = 'condición'): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`Timeout (${timeoutMs}ms) esperando: ${label}`);
}

function createPersistentStorageStub(): VelUnifiedStorageAdapter & {
  items: Map<string, VelVaultItemRecord>;
} {
  let identity: LocalDeviceIdentityRecord | null = null;
  const config = new Map<string, any>();
  const auths = new Map<string, AuthorizationRecord>();
  const linksMap = new Map<string, DeviceLinkRecord>();
  const items = new Map<string, VelVaultItemRecord>();
  const chunks = new Map<string, VelIncomingChunkRecord>();

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
      return items.get(id) || null;
    },
    async getAllItems() {
      return Array.from(items.values());
    },
    async deleteItem(id) {
      items.delete(id);
    },
    async putIncomingChunk(record) {
      chunks.set(record.chunkKey, { ...record });
    },
    async getIncomingChunksByItemId(itemId) {
      return Array.from(chunks.values())
        .filter((c) => c.itemId === itemId)
        .sort((a, b) => a.chunkIndex - b.chunkIndex);
    },
    async deleteIncomingChunksByItemId(itemId) {
      let n = 0;
      for (const [k, c] of chunks.entries()) {
        if (c.itemId === itemId) {
          chunks.delete(k);
          n++;
        }
      }
      return n;
    },
    async close() {}
  };
}

function createInMemoryFirestoreDeviceStore() {
  const devices = new Map<string, DeviceRecord>();
  const links = new Map<string, DeviceLinkRecord>();
  const authorizations = new Map<string, AuthorizationRecord>();
  const subscribers = new Map<string, SuscriptorAdminRecord>();

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
    },
    async getSubscriber(uid) {
      const found = subscribers.get(uid);
      return found ? { ...found } : null;
    },
    async updateSubscriberStatus(uid, patch) {
      const found = subscribers.get(uid);
      if (found) subscribers.set(uid, { ...found, ...patch });
    }
  };

  return { store, devices, links, authorizations, subscribers };
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
      const parsedUrl = new URL(target, 'https://legendary-pasca-bf280b.netlify.app');
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

async function runIntegrationFinalTests() {
  console.log('========================================================================');
  console.log('VEL 0.1 — PRUEBAS DE INTEGRACIÓN FINAL SIMPLIFICADA');
  console.log('========================================================================\n');

  console.log('--- 1 & 2. Blogger, Manifest PWA, Iconos, Service Worker y App.tsx guiado ---');
  const root = process.cwd();
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'public', 'manifest.json'), 'utf8'));
  const swJs = fs.readFileSync(path.join(root, 'public', 'sw.js'), 'utf8');
  const indexHtml = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const bloggerHtml = fs.readFileSync(path.join(root, 'blogger', 'vel-contratacion-mercadopago.html'), 'utf8');
  const appTsx = fs.readFileSync(path.join(root, 'src', 'App.tsx'), 'utf8');

  assert(
    manifest.name === 'VEL' &&
      manifest.short_name === 'VEL' &&
      manifest.display === 'standalone' &&
      manifest.start_url === '/' &&
      manifest.scope === '/',
    'manifest.json define name="VEL", short_name="VEL", standalone, start_url="/", scope="/"'
  );

  const expectedIcons = ['pwa-192x192.png', 'pwa-512x512.png', 'pwa-maskable-512x512.png', 'apple-touch-icon.png'];
  const allIconsExist = expectedIcons.every((iconFile) =>
    fs.existsSync(path.join(root, 'public', iconFile))
  );
  assert(allIconsExist, 'Existen todos los íconos PWA físicos en /public (192, 512, maskable, apple-touch)');

  assert(
    swJs.includes("pathname.startsWith('/api/')") &&
      !swJs.includes('/.netlify/') &&
      swJs.includes("pathname.endsWith('.zip')") &&
      swJs.includes("request.headers.get('Authorization')") &&
      swJs.includes('SKIP_WAITING'),
    'Service Worker cachea solo estáticos y excluye /api/, .zip y tokens (sin /.netlify/)'
  );

  assert(
    indexHtml.includes('rel="manifest" href="/manifest.json"') &&
      indexHtml.includes("serviceWorker.register('/sw.js'") &&
      indexHtml.includes('vel-sw-update-ready'),
    'index.html enlaza manifest.json, registra /sw.js y detecta actualizaciones del Service Worker'
  );

  assert(
    bloggerHtml.includes('https://proyecto-vel.pages.dev/') &&
      bloggerHtml.includes('Entrar a VEL') &&
      bloggerHtml.includes('ACEPTO Y CONTINUAR') &&
      bloggerHtml.includes("var CONTRACT_VERSION = '1.2'") &&
      bloggerHtml.includes('/api/download-package?format=json') &&
      bloggerHtml.includes('/api/create-preference') &&
      bloggerHtml.includes('/api/account') &&
      bloggerHtml.includes(OFFICIAL_CONTRACT_URL) &&
      !bloggerHtml.toLowerCase().includes('netlify'),
    'Blogger apunta a https://proyecto-vel.pages.dev/ (sin Netlify), integra cuenta única + Alta/Baja (/api/account), exige contrato v1.2, verifica pago vía /api/download-package y enlaza el contrato oficial'
  );

  assert(
    !appTsx.includes('APK Android Nativo') &&
      !appTsx.includes('Descargar ZIP Netlify') &&
      !bloggerHtml.toLowerCase().includes('.apk'),
    'Ni la app ni Blogger presentan APK ni ZIP como instalador móvil'
  );

  assert(
    appTsx.includes('INSTALL_STEP') &&
      appTsx.includes('CHOOSE_ROLE') &&
      appTsx.includes('PAIRING_STEP') &&
      appTsx.includes('VelTransferManager') &&
      appTsx.includes('Copiado en VEL CORE') &&
      appTsx.includes('Borrar de este móvil') &&
      !appTsx.includes('Suscripción comercial') &&
      !appTsx.includes('WEB_PORTAL'),
    'App.tsx implementa flujo guiado de 4 pasos, copias en ambos teléfonos y mantiene comercial en Blogger'
  );

  console.log('\n--- 3. Contratos y versión vigente ---');
  assert(
    CURRENT_CONTRACT_VERSION === '1.2' && !isDraftContractVersion(),
    'Versión de contrato configurada como 1.2 (definitiva)'
  );
  assert(
    isTechnicalAccount(undefined, 'soporte@vel.com') &&
      isTechnicalAccount(undefined, 'admin@vel.com') &&
      !isTechnicalAccount('uid-cliente-real', 'cliente@ejemplo.com'),
    'Cuentas técnicas bloqueadas sin afectar a clientes reales'
  );
  const firestoreTs = fs.readFileSync(path.join(root, 'src', 'services', 'firestore.ts'), 'utf8');
  assert(
    firestoreTs.includes('recordContractAcceptance') &&
      firestoreTs.includes('isTechnicalAccount(uid, userEmail)'),
    'Gestión de contratos en firestore.ts protege cuentas técnicas'
  );

  console.log('\n--- 4..10. Flujo completo CORE + MÓVIL 1 + Transferencia + Reemplazo MÓVIL 2 + Revocaciones ---');
  const testStorageDir = path.join(root, 'server-vel', 'test-data-final');
  if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });

  const dbMemory = createInMemoryFirestoreDeviceStore();
  const fetchAdapter = makeFetchAdapter(dbMemory);
  const verifyToken = makeVerifyTokenFn();

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

  const coreStorage = createPersistentStorageStub();
  const mov1Storage = createPersistentStorageStub();
  const mov2Storage = createPersistentStorageStub();

  const coreUid = 'uid-final-core';
  const mov1Uid = 'uid-final-mov1';
  const mov2Uid = 'uid-final-mov2';

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
  await setupNewDeviceIdentity('TERMINAL', undefined, {
    storage: mov2Storage,
    ensureAnonymousAuth: async () => ({ success: true, uid: mov2Uid, idToken: `valid-token-${mov2Uid}` }),
    fetchFn: fetchAdapter
  });

  const coreLocal = (await loadPersistedDeviceIdentity({ storage: coreStorage }))!;
  const mov1Local = (await loadPersistedDeviceIdentity({ storage: mov1Storage }))!;
  const mov2Local = (await loadPersistedDeviceIdentity({ storage: mov2Storage }))!;

  assert(
    coreLocal.role === 'CORE' && mov1Local.role === 'TERMINAL' && mov2Local.role === 'TERMINAL',
    'Roles persistidos en almacenamiento local tras primer acceso'
  );

  const reopenedCore = await syncPersistedDeviceSession({
    storage: coreStorage,
    getFreshToken: async () => `valid-token-${coreUid}`,
    fetchFn: fetchAdapter
  });
  assert(
    Boolean(reopenedCore?.synced && reopenedCore.identity.deviceId === coreLocal.deviceId),
    'Al reabrir la PWA, reconoce identidad técnica y rol sin volver a preguntar'
  );

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
    store: new VelLocalStore(coreStorage)
  });
  const mov1Manager = new VelTransferManager({
    relayClient: mov1Client,
    role: 'TERMINAL',
    store: new VelLocalStore(mov1Storage)
  });

  coreClient.connect(wssUrl);
  coreClient.connect(wssUrl);
  mov1Client.connect(wssUrl);
  mov1Client.connect(wssUrl);

  await waitFor(
    () => coreClient.getState() === 'AUTHENTICATED' && mov1Client.getState() === 'AUTHENTICATED',
    4000,
    'Autenticación inicial CORE y MÓVIL 1'
  );
  assert(server.getActiveClientCount() === 2, 'Guard anti-duplicado mantiene exactamente 2 sockets activos');

  const offer1 = coreClient.startCorePairingOffer();
  assert(Boolean(offer1 && /^\d{6}$/.test(offer1.code)), 'CORE genera código numérico de 6 dígitos');
  mov1Client.claimPairingCode(offer1!.code);

  await waitFor(
    () => coreClient.getState() === 'LINKED' && mov1Client.getState() === 'LINKED',
    3000,
    'Emparejamiento 1-paso CORE <-> MÓVIL 1'
  );

  // Enviar foto + nota de MÓVIL 1 a CORE
  await mov1Manager.addNote('Dato importante', 'Nota conservada en ambos teléfonos');
  const photoBytes = new Uint8Array(1024).fill(7);
  await mov1Manager.addFiles([
    {
      name: 'comprobante.jpg',
      type: 'image/jpeg',
      size: photoBytes.byteLength,
      blob: new Blob([toExactArrayBuffer(photoBytes)], { type: 'image/jpeg' })
    }
  ]);

  await waitFor(
    () =>
      coreManager.getSnapshot().items.length === 2 &&
      mov1Manager.getSnapshot().items.every((i) => i.syncStatus === 'synced'),
    5000,
    'Entrega de nota y foto MÓVIL 1 -> CORE'
  );

  const noteInMov1 = mov1Manager.getSnapshot().items.find((i) => i.kind === 'note')!;
  await mov1Manager.deleteFromThisPhone(noteInMov1.id);
  assert(
    mov1Manager.getSnapshot().items.length === 1 && coreManager.getSnapshot().items.length === 2,
    'El usuario decide borrar en MÓVIL 1 y VEL CORE conserva ambas copias intactas'
  );

  // Desconectar MÓVIL 1 antes de desvincularlo -> PERSISTED_PEER_OFFLINE
  mov1Client.disconnect();
  await waitFor(() => mov1Client.getState() === 'DISCONNECTED', 2000, 'Desconexión de MÓVIL 1');

  const offlineRevoke = await coreClient.revokePairedTerminal(mov1Local.deviceId, 'Reemplazo con MÓVIL 1 offline');
  assert(
    offlineRevoke.success &&
      offlineRevoke.persistedInFirestore &&
      !offlineRevoke.disconnectedLive &&
      coreClient.getSnapshot().revocationStatus === 'PERSISTED_PEER_OFFLINE',
    'Desvinculación con móvil offline reporta PERSISTED_PEER_OFFLINE'
  );

  const mov1Blocked = await new Promise<boolean>((resolve) => {
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
    setTimeout(() => resolve(false), 3000);
  });
  assert(mov1Blocked, 'MÓVIL 1 desvinculado offline queda bloqueado al intentar reconectar');

  // Vincular MÓVIL 2 conservando identidad y copias de VEL CORE
  const mov2Client = new VelRelayClient({
    storage: mov2Storage,
    getFirebaseIdToken: async () => `valid-token-${mov2Uid}`,
    fetchFn: fetchAdapter,
    WebSocketImpl: WebSocket
  });
  mov2Client.connect(wssUrl);
  await waitFor(() => mov2Client.getState() === 'AUTHENTICATED', 3000, 'Autenticación de MÓVIL 2');

  const offer2 = coreClient.startCorePairingOffer();
  mov2Client.claimPairingCode(offer2!.code);
  await waitFor(
    () => coreClient.getState() === 'LINKED' && mov2Client.getState() === 'LINKED',
    3000,
    'LINKED CORE <-> MÓVIL 2'
  );

  const coreAfterReplace = (await coreStorage.getIdentity())!;
  assert(
    coreAfterReplace.deviceId === coreLocal.deviceId &&
      isPrivateKeyProtected(coreAfterReplace.privateEcdhKey) &&
      coreAfterReplace.pairedPeerDeviceId === mov2Local.deviceId &&
      coreManager.getSnapshot().items.length === 2,
    'Reemplazar por MÓVIL 2 conserva identidad y todas las copias previas de VEL CORE'
  );

  const liveRevoke = await coreClient.revokePairedTerminal(mov2Local.deviceId, 'Emergencia con móvil en línea');
  await waitFor(() => mov2Client.getState() === 'REVOKED', 3000, 'MÓVIL 2 recibe REVOCATION_NOTICE en vivo');
  assert(
    liveRevoke.success &&
      liveRevoke.persistedInFirestore &&
      liveRevoke.disconnectedLive &&
      coreClient.getSnapshot().revocationStatus === 'CONFIRMED',
    'Desvinculación con móvil online reporta CONFIRMED y cierra socket en vivo'
  );

  console.log('\n--- 11. Independencia comercial vs copias guardadas en VEL CORE ---');
  const fakeSubscribers: Record<string, any> = {
    'uid-comercial-test': {
      uid: 'uid-comercial-test',
      email: 'cliente@vel.test',
      estado: 'suspendido',
      plan: 'Plan Oficial VEL (2 Teléfonos: CORE + MÓVIL)',
      precioContratado: 4500,
      moneda: 'ARS',
      venceEl: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString()
    }
  };
  const pricingRes = await getPricingHandler({ httpMethod: 'GET' });
  assert(
    pricingRes.statusCode === 200 || pricingRes.statusCode === 503,
    `get-pricing responde de forma controlada (HTTP ${pricingRes.statusCode})`
  );

  const dlRes = await downloadPackageHandler(
    { httpMethod: 'GET', headers: { Authorization: 'Bearer valid-tok' } },
    {
      verifyToken: async () => ({ authenticated: true, uid: 'uid-comercial-test', email: 'cliente@vel.test' }),
      getSubscriber: async (uid) => fakeSubscribers[uid] || null,
      updateSubscriberStatus: async () => {}
    }
  );
  assert(
    dlRes.statusCode === 403 &&
      dbMemory.devices.get(coreLocal.deviceId)?.status !== 'revoked' &&
      coreManager.getSnapshot().items.length === 2,
    'Suspensión comercial bloquea descarga web (403) SIN revocar VEL CORE ni borrar sus copias'
  );

  console.log('\n--- 12. Pausa automática al vencer suscripción mensual y reactivación con envío pendiente ---');
  const prevSecret = process.env.MP_WEBHOOK_SECRET;
  process.env.MP_WEBHOOK_SECRET = 'vel_integration_pass_secret_001';
  try {
    const subUid = 'uid-suscriptor-ciclo-completo';
    dbMemory.subscribers.set(subUid, {
      uid: subUid,
      email: 'ciclo@vel.com',
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: new Date(Date.now() - 10 * 86_400_000).toISOString(),
      venceEl: new Date(Date.now() + 20 * 86_400_000).toISOString()
    });

    const coreSubStorage = createPersistentStorageStub();
    const movSubStorage = createPersistentStorageStub();
    const velPass = createSubscriptionPass(subUid)!;
    await savePendingSubscriptionPass(velPass, coreSubStorage);

    await setupNewDeviceIdentity('CORE', undefined, {
      storage: coreSubStorage,
      ensureAnonymousAuth: async () => ({ success: true, uid: 'anon-sub-c', idToken: 'valid-token-anon-sub-c' }),
      fetchFn: fetchAdapter
    });
    await setupNewDeviceIdentity('TERMINAL', undefined, {
      storage: movSubStorage,
      ensureAnonymousAuth: async () => ({ success: true, uid: 'anon-sub-m', idToken: 'valid-token-anon-sub-m' }),
      fetchFn: fetchAdapter
    });

    const subCoreClient = new VelRelayClient({
      storage: coreSubStorage,
      getFirebaseIdToken: async () => 'valid-token-anon-sub-c',
      fetchFn: fetchAdapter,
      WebSocketImpl: WebSocket
    });
    const subMovClient = new VelRelayClient({
      storage: movSubStorage,
      getFirebaseIdToken: async () => 'valid-token-anon-sub-m',
      fetchFn: fetchAdapter,
      WebSocketImpl: WebSocket
    });

    const subCoreMgr = new VelTransferManager({
      relayClient: subCoreClient,
      role: 'CORE',
      store: new VelLocalStore(coreSubStorage)
    });
    const subMovMgr = new VelTransferManager({
      relayClient: subMovClient,
      role: 'TERMINAL',
      store: new VelLocalStore(movSubStorage)
    });

    subCoreClient.connect(wssUrl);
    subMovClient.connect(wssUrl);
    await waitFor(
      () => subCoreClient.getState() === 'AUTHENTICATED' && subMovClient.getState() === 'AUTHENTICATED',
      3000,
      'Autenticación ciclo suscripción'
    );

    const subOffer = subCoreClient.startCorePairingOffer();
    subMovClient.claimPairingCode(subOffer!.code);
    await waitFor(
      () => subCoreClient.getState() === 'LINKED' && subMovClient.getState() === 'LINKED',
      3000,
      'Emparejamiento heredando subscriptionUid a ambos teléfonos'
    );

    const movIdentityPaired = (await loadPersistedDeviceIdentity({ storage: movSubStorage }))!;
    assert(
      dbMemory.devices.get(movIdentityPaired.deviceId)?.subscriptionUid === subUid,
      'Al vincular con CORE que abrió VEL desde Blogger, MÓVIL hereda automáticamente el subscriptionUid'
    );

    await subMovMgr.addNote('Antes de vencer', 'Copia enviada con suscripción activa');
    await waitFor(
      () => subCoreMgr.getSnapshot().items.length === 1 && subMovMgr.getSnapshot().items[0].syncStatus === 'synced',
      4000,
      'Entrega normal con suscripción activa'
    );

    // Simular vencimiento de los 30 días y pausa en el Relay
    dbMemory.subscribers.set(subUid, {
      uid: subUid,
      email: 'ciclo@vel.com',
      estado: 'vencido',
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: new Date(Date.now() - 31 * 86_400_000).toISOString(),
      venceEl: new Date(Date.now() - 86_400_000).toISOString()
    });
    subMovClient.forceReconnect();
    subCoreClient.forceReconnect();
    await waitFor(
      () =>
        subMovClient.getState() === 'LINKED' &&
        subMovClient.getSnapshot().subscriptionStatus?.linked === true &&
        subMovClient.getSnapshot().subscriptionStatus?.active === false,
      3000,
      'Reconocimiento automático de suscripción vencida en Relay'
    );

    await subMovMgr.addNote('Mientras vencido', 'Guardado en móvil en espera de renovación');
    await new Promise((r) => setTimeout(r, 150));
    assert(
      subCoreMgr.getSnapshot().items.length === 1 &&
        subMovMgr.getSnapshot().items.length === 2 &&
        subCoreClient.getState() === 'LINKED',
      'Al vencer el mes, se pausa el envío nuevo pero NO se borra ninguna copia local ni se revocan los teléfonos'
    );

    // Simular nuevo pago en Mercado Pago (renovación) y toque de reactivación
    dbMemory.subscribers.set(subUid, {
      uid: subUid,
      email: 'ciclo@vel.com',
      estado: 'activo',
      plan: 'Suscripción mensual VEL',
      modalidadComercial: 'manual_30d',
      fechaAlta: new Date(Date.now() - 31 * 86_400_000).toISOString(),
      venceEl: new Date(Date.now() + 30 * 86_400_000).toISOString()
    });
    subCoreClient.forceReconnect();
    subMovClient.forceReconnect();
    await waitFor(
      () =>
        subMovClient.getState() === 'LINKED' &&
        subMovClient.getSnapshot().subscriptionStatus?.active === true &&
        subMovClient.getSnapshot().peerOnline,
      5000,
      'Reactivación de enlace tras renovar suscripción'
    );
    await new Promise((r) => setTimeout(r, 200));
    const pendingNote = subMovMgr
      .getSnapshot()
      .items.find((i) => i.title === 'Mientras vencido');
    assert(
      Boolean(pendingNote) &&
        pendingNote?.syncStatus === 'pending' &&
        subCoreMgr.getSnapshot().items.length === 1,
      'Al renovar y reconectar, la nota pendiente permanece guardada localmente sin auto-envío'
    );

    if (pendingNote) {
      await subMovMgr.retryItem(pendingNote.id);
    }
    await waitFor(
      () =>
        subCoreMgr.getSnapshot().items.length === 2 &&
        subMovMgr.getSnapshot().items.every((i) => i.syncStatus === 'synced'),
      5000,
      'Envío explícito de nota pendiente tras pulsar Reintentar'
    );
    assert(true, 'Al renovar el pago en Mercado Pago, VEL reactiva el enlace y envía la nota pendiente solo tras Reintentar');

    subCoreMgr.dispose();
    subMovMgr.dispose();
    subCoreClient.disconnect();
    subMovClient.disconnect();
  } finally {
    if (prevSecret !== undefined) process.env.MP_WEBHOOK_SECRET = prevSecret;
    else delete process.env.MP_WEBHOOK_SECRET;
  }

  coreManager.dispose();
  mov1Manager.dispose();
  coreClient.disconnect();
  mov1Client.disconnect();
  mov2Client.disconnect();
  await server.stop();
  if (fs.existsSync(testStorageDir)) fs.rmSync(testStorageDir, { recursive: true, force: true });

  console.log('\n========================================================================');
  console.log(`RESUMEN PRUEBAS INTEGRACIÓN FINAL: ${passed} PASS / ${failed} FAIL`);
  console.log('========================================================================');
  if (failed > 0) process.exit(1);
}

runIntegrationFinalTests().catch((err) => {
  console.error('\n[ERROR FATAL EN INTEGRACIÓN FINAL]:', err);
  process.exit(1);
});
