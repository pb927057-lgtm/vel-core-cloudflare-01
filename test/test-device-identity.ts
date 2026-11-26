import { createHash } from 'crypto';
import {
  AuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  LocalDeviceIdentityRecord
} from '../src/contracts/velContracts';
import {
  computeFingerprintFromBase64Spki,
  generateDeviceCryptoMaterial,
  generateRandomDeviceId,
  isPrivateKeyProtected,
  signTechnicalChallenge
} from '../src/crypto/deviceCrypto';
import { VelStorageAdapter } from '../src/db/db';
import {
  executeControlledRoleChange,
  loadPersistedDeviceIdentity,
  retryPendingDeviceRegistration,
  setupNewDeviceIdentity,
  syncPersistedDeviceSession
} from '../src/services/deviceIdentityService';
import { VelRelayClient } from '../src/services/relayClient';
import {
  createPreferenceHandler
} from '../netlify/functions/create-preference';
import {
  deviceSessionHandler
} from '../netlify/functions/device-session';
import {
  registerDeviceHandler
} from '../netlify/functions/register-device';
import {
  DEVICE_ID_PATTERN,
  DeviceTransactionContext,
  DeviceTransactionStore,
  findForbiddenFields
} from '../netlify/functions/shared/deviceAuthService';
import { verifyDeviceTokenHandler } from '../netlify/functions/verify-device-token';
import { resolveEffectiveSubscriberPricing } from '../netlify/functions/shared/paymentRenewalService';
import { SuscriptorAdminRecord } from '../netlify/functions/shared/types';

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
        async getAuthorizationByLink(linkId) {
          const found = authorizations.get(linkId);
          return found ? { ...found } : null;
        }
      };
      return fn(ctx);
    }
  };

  return { store, devices, links, authorizations };
}

async function runTests() {
  console.log('==================================================================');
  console.log('VEL 0.1 — PRUEBAS AUTOMATIZADAS INTERVENCIÓN 1/3 (IDENTIDAD Y AUTH)');
  console.log('==================================================================\n');

  // ------------------------------------------------------------------
  // 1. Generación de identidad única (aleatoria, formato estricto, sin PII)
  // ------------------------------------------------------------------
  console.log('--- 1. Generación de identidad técnica única ---');
  const generatedIds = new Set<string>();
  for (let i = 0; i < 40; i++) {
    const coreId = generateRandomDeviceId('CORE');
    const movId = generateRandomDeviceId('TERMINAL');
    assert(DEVICE_ID_PATTERN.test(coreId) && coreId.startsWith('VEL-CORE-'), `Formato CORE válido (${coreId})`);
    assert(DEVICE_ID_PATTERN.test(movId) && movId.startsWith('VEL-MOV-'), `Formato MÓVIL válido (${movId})`);
    generatedIds.add(coreId);
    generatedIds.add(movId);
  }
  assert(generatedIds.size === 80, '80 identificadores generados sin colisiones ni patrones fijos');
  assert(!generatedIds.has('VEL-CORE-7B42') && !generatedIds.has('VEL-MOV-991A'), 'No genera IDs mock históricos');

  // ------------------------------------------------------------------
  // 2 & 3. Persistencia del rol e identidad tras cierre y reapertura
  // ------------------------------------------------------------------
  console.log('\n--- 2 y 3. Persistencia de rol e identidad entre cierres ---');
  const dbMemory = createInMemoryFirestoreDeviceStore();
  const browserStorage = createPersistentStorageStub();
  const coreUid = 'firebase-anon-core-uid-001';

  const makeFetchAdapter = (authUid: string) => {
    return (async (url: RequestInfo | URL, init?: RequestInit) => {
      const target = String(url);
      const method = (init?.method || 'GET').toUpperCase();
      const headers = (init?.headers || {}) as Record<string, string>;
      const verifyToken = async (authHeader?: string) => {
        if (!authHeader || !authHeader.startsWith('Bearer valid-token-')) {
          return { authenticated: false as const, reason: 'invalid_token' as const, message: 'Token inválido' };
        }
        const uid = authHeader.replace('Bearer valid-token-', '').trim();
        return { authenticated: true as const, uid, email: '' };
      };

      if (target.startsWith('/api/register-device')) {
        const res = await registerDeviceHandler(
          {
            httpMethod: method,
            headers,
            body: typeof init?.body === 'string' ? init.body : undefined
          },
          {
            verifyToken,
            hasDbCredentials: () => true,
            getDeviceStore: () => dbMemory.store
          }
        );
        return new Response(res.body, { status: res.statusCode, headers: { 'Content-Type': 'application/json' } });
      }

      if (target.startsWith('/api/device-session')) {
        const parsedUrl = new URL(target, 'https://proyecto-vel.netlify.app');
        const queryStringParameters = Object.fromEntries(parsedUrl.searchParams.entries());
        const res = await deviceSessionHandler(
          {
            httpMethod: method,
            headers,
            queryStringParameters,
            body: typeof init?.body === 'string' ? init.body : undefined
          },
          {
            verifyToken,
            hasDbCredentials: () => true,
            getDeviceStore: () => dbMemory.store
          }
        );
        return new Response(res.body, { status: res.statusCode, headers: { 'Content-Type': 'application/json' } });
      }

      throw new Error(`Endpoint inesperado en prueba: ${target}`);
    }) as typeof fetch;
  };

  const setupOutcome = await setupNewDeviceIdentity('CORE', undefined, {
    storage: browserStorage,
    ensureAnonymousAuth: async () => ({
      success: true,
      uid: coreUid,
      idToken: `valid-token-${coreUid}`
    }),
    fetchFn: makeFetchAdapter(coreUid)
  });

  assert(setupOutcome.success && setupOutcome.registeredInServer, 'Configuración inicial CORE completada y registrada en servidor');
  assert(Boolean(setupOutcome.identity?.deviceId.startsWith('VEL-CORE-')), 'Identidad asignada como CORE');

  // Simular cierre y reapertura de la PWA (solo leyendo storage persistente + sync)
  const restoredIdentity = await loadPersistedDeviceIdentity({ storage: browserStorage });
  assert(restoredIdentity !== null, 'La identidad sobrevive al cierre del navegador/PWA');
  assert(restoredIdentity?.role === 'CORE', 'El rol CORE persiste sin volver a preguntarse');
  assert(restoredIdentity?.deviceId === setupOutcome.identity?.deviceId, 'El mismo deviceId se conserva tras reabrir');
  assert(restoredIdentity?.fingerprint === setupOutcome.identity?.fingerprint, 'La huella pública se conserva intacta');
  assert(restoredIdentity?.firebaseAuthUid === coreUid, 'El UID técnico se conserva correctamente');

  const syncOutcome = await syncPersistedDeviceSession({
    storage: browserStorage,
    getFreshToken: async () => `valid-token-${coreUid}`,
    fetchFn: makeFetchAdapter(coreUid)
  });
  assert(Boolean(syncOutcome?.synced), 'Sincronización de sesión al reabrir la PWA confirmada en backend');
  assert(syncOutcome?.identity.registrationStatus === 'registered', 'Estado en Firestore permanece registered');

  // ------------------------------------------------------------------
  // 4. Registro autorizado y rechazo sin credenciales / UID suplantado
  // ------------------------------------------------------------------
  console.log('\n--- 4. Registro autorizado en Netlify + Firestore ---');
  const movMaterial = await generateDeviceCryptoMaterial('TERMINAL');
  const movUid = 'firebase-anon-mov-uid-002';

  // Intento sin token -> 401
  const unauthRes = await registerDeviceHandler(
    {
      httpMethod: 'POST',
      headers: {},
      body: JSON.stringify({
        deviceId: movMaterial.deviceId,
        role: 'TERMINAL',
        publicKeySpkiBase64: movMaterial.publicKeySpkiBase64,
        signingPublicKeySpkiBase64: movMaterial.signingPublicKeySpkiBase64,
        fingerprint: movMaterial.fingerprint
      })
    },
    {
      verifyToken: async () => ({ authenticated: false, reason: 'missing_token', message: 'Token faltante' }),
      hasDbCredentials: () => true,
      getDeviceStore: () => dbMemory.store
    }
  );
  assert(unauthRes.statusCode === 401, 'Registro sin token Firebase es rechazado (HTTP 401)');

  // Registro legítimo con token válido (incluyendo un authUid falso en body que el servidor debe ignorar)
  const movRes = await registerDeviceHandler(
    {
      httpMethod: 'POST',
      headers: { Authorization: `Bearer valid-token-${movUid}` },
      body: JSON.stringify({
        deviceId: movMaterial.deviceId,
        role: 'TERMINAL',
        authUid: 'spoofed-attacker-uid',
        publicKeySpkiBase64: movMaterial.publicKeySpkiBase64,
        signingPublicKeySpkiBase64: movMaterial.signingPublicKeySpkiBase64,
        fingerprint: movMaterial.fingerprint
      })
    },
    {
      verifyToken: async () => ({ authenticated: true, uid: movUid, email: '' }),
      hasDbCredentials: () => true,
      getDeviceStore: () => dbMemory.store
    }
  );
  const movBody = JSON.parse(movRes.body);
  assert(movRes.statusCode === 201 && movBody.success, 'Registro autorizado de VEL MÓVIL exitoso (HTTP 201)');
  assert(movBody.device.authUid === movUid, 'El servidor asigna authUid del token verificado, ignorando el body');
  assert(
    dbMemory.devices.get(movMaterial.deviceId)?.fingerprint === movMaterial.fingerprint,
    'Documento guardado en dispositivos/{deviceId} con huella verificada'
  );

  // Verificación de token para Intervención 2 (/api/verify-device-token)
  const verifyRes = await verifyDeviceTokenHandler(
    {
      httpMethod: 'POST',
      headers: { Authorization: `Bearer valid-token-${movUid}` },
      body: JSON.stringify({ deviceId: movMaterial.deviceId })
    },
    {
      verifyToken: async () => ({ authenticated: true, uid: movUid, email: '' }),
      hasDbCredentials: () => true,
      getDeviceStore: () => dbMemory.store
    }
  );
  assert(verifyRes.statusCode === 200 && JSON.parse(verifyRes.body).valid === true, 'Endpoint /api/verify-device-token valida identidad técnica real');

  // ------------------------------------------------------------------
  // 5. Rechazo de identificadores duplicados (HTTP 409)
  // ------------------------------------------------------------------
  console.log('\n--- 5. Rechazo de identificadores duplicados ---');
  const dupRes = await registerDeviceHandler(
    {
      httpMethod: 'POST',
      headers: { Authorization: 'Bearer valid-token-attacker' },
      body: JSON.stringify({
        deviceId: movMaterial.deviceId,
        role: 'TERMINAL',
        publicKeySpkiBase64: movMaterial.publicKeySpkiBase64,
        signingPublicKeySpkiBase64: movMaterial.signingPublicKeySpkiBase64,
        fingerprint: movMaterial.fingerprint
      })
    },
    {
      verifyToken: async () => ({ authenticated: true, uid: 'attacker-uid-999', email: '' }),
      hasDbCredentials: () => true,
      getDeviceStore: () => dbMemory.store
    }
  );
  const dupBody = JSON.parse(dupRes.body);
  assert(dupRes.statusCode === 409 && dupBody.code === 'DUPLICATE_DEVICE_ID', 'Re-registro de deviceId existente rechazado con HTTP 409');
  assert(dbMemory.devices.get(movMaterial.deviceId)?.authUid === movUid, 'El registro original en Firestore permanece intacto');

  // ------------------------------------------------------------------
  // 6. Protección de claves privadas (extractable: false, fuera de Firestore/localStorage)
  // ------------------------------------------------------------------
  console.log('\n--- 6. Protección criptográfica de claves privadas ---');
  const storedLocal = await browserStorage.getIdentity();
  assert(storedLocal !== null, 'Identidad local presente en almacenamiento');
  assert(isPrivateKeyProtected(storedLocal!.privateEcdhKey), 'Clave privada ECDH tiene extractable === false');
  assert(isPrivateKeyProtected(storedLocal!.privateSigningKey), 'Clave privada ECDSA tiene extractable === false');

  let ecdhExportBlocked = false;
  try {
    await globalThis.crypto.subtle.exportKey('pkcs8', storedLocal!.privateEcdhKey);
  } catch {
    ecdhExportBlocked = true;
  }
  assert(ecdhExportBlocked, 'Web Crypto bloquea exportKey() sobre la clave privada ECDH');

  let ecdsaExportBlocked = false;
  try {
    await globalThis.crypto.subtle.exportKey('pkcs8', storedLocal!.privateSigningKey);
  } catch {
    ecdsaExportBlocked = true;
  }
  assert(ecdsaExportBlocked, 'Web Crypto bloquea exportKey() sobre la clave privada ECDSA');

  const signature = await signTechnicalChallenge(storedLocal!.privateSigningKey, 'vel-auth-challenge-001');
  assert(signature.length > 20, 'La clave privada ECDSA protegida firma desafíos criptográficos sin exportarse');

  const firestoreCoreRecord = dbMemory.devices.get(storedLocal!.deviceId) as Record<string, any>;
  assert(
    !('privateKey' in firestoreCoreRecord) &&
      !('privateEcdhKey' in firestoreCoreRecord) &&
      !('privateSigningKey' in firestoreCoreRecord),
    'Ninguna clave privada se almacena en el registro de Firestore'
  );

  // Verificar rechazo si se intenta enviar clave privada al backend
  const privKeyRejectRes = await registerDeviceHandler(
    {
      httpMethod: 'POST',
      headers: { Authorization: 'Bearer valid-token-x' },
      body: JSON.stringify({
        deviceId: generateRandomDeviceId('CORE'),
        role: 'CORE',
        publicKeySpkiBase64: movMaterial.publicKeySpkiBase64,
        signingPublicKeySpkiBase64: movMaterial.signingPublicKeySpkiBase64,
        fingerprint: movMaterial.fingerprint,
        privateKey: 'SECRET-LEAK'
      })
    },
    {
      verifyToken: async () => ({ authenticated: true, uid: 'uid-x', email: '' }),
      hasDbCredentials: () => true,
      getDeviceStore: () => dbMemory.store
    }
  );
  assert(
    privKeyRejectRes.statusCode === 400 && JSON.parse(privKeyRejectRes.body).code === 'FORBIDDEN_FIELDS',
    'El servidor rechaza explícitamente solicitudes que incluyan claves privadas'
  );

  // ------------------------------------------------------------------
  // 7. Compatibilidad con suscriptores anteriores (UID histórico, tarifa, vigencia)
  // ------------------------------------------------------------------
  console.log('\n--- 7. Compatibilidad con suscriptores históricos ---');
  const legacySubscriberUid = 'legacy-password-user-uid-777';
  const legacySubscriber: SuscriptorAdminRecord = {
    uid: legacySubscriberUid,
    email: 'historico@cliente-vel.com',
    estado: 'activo',
    plan: 'oficial',
    fechaAlta: '2026-06-01T10:00:00.000Z',
    venceEl: '2026-12-01T00:00:00.000Z',
    precioContratado: 3200,
    moneda: 'ARS',
    fechaUltimoPago: '2026-11-01T00:00:00.000Z',
    ultimoPagoId: 'mp-pay-998877',
    modalidadComercial: 'manual_30d'
  };

  // El dispositivo anónimo usa otro UID completamente separado; nunca reasigna al suscriptor
  assert(coreUid !== legacySubscriber.uid, 'El authUid anónimo del dispositivo está aislado del UID comercial histórico');

  const effectivePricing = resolveEffectiveSubscriberPricing(legacySubscriber, {
    monto: 6500,
    moneda: 'ARS',
    periodicidad: 'mensual',
    actualizadoEl: new Date().toISOString(),
    actualizadoPor: 'admin@vel.com'
  });
  assert(
    effectivePricing.isHistorical && effectivePricing.monto === 3200 && effectivePricing.moneda === 'ARS',
    'Suscriptor histórico conserva su tarifa contratada original ($3.200) sin perderla frente a tarifas nuevas'
  );

  // Conocer el correo electrónico sin token Firebase válido NO da acceso comercial
  const fakeEmailAttackRes = await createPreferenceHandler(
    {
      httpMethod: 'POST',
      headers: { Origin: 'https://proyecto-vel.netlify.app' },
      body: JSON.stringify({ email: legacySubscriber.email, uid: legacySubscriber.uid })
    },
    {
      verifyToken: async () => ({
        authenticated: false,
        reason: 'missing_token',
        message: 'Se requiere token autenticado de Firebase.'
      })
    }
  );
  assert(
    fakeEmailAttackRes.statusCode === 401,
    'Conocer únicamente el correo de un suscriptor histórico no otorga acceso sin enlace/token Firebase verificado (HTTP 401)'
  );

  // Con token Firebase verificado del mismo UID histórico (tras Email Link), conserva tarifa en preferencia
  let capturedAmount = 0;
  const legacyPrefRes = await createPreferenceHandler(
    {
      httpMethod: 'POST',
      headers: {
        Origin: 'https://proyecto-vel.netlify.app',
        Authorization: 'Bearer verified-email-link-token'
      },
      body: JSON.stringify({})
    },
    {
      verifyToken: async () => ({
        authenticated: true,
        uid: legacySubscriberUid,
        email: legacySubscriber.email
      }),
      getPricing: async () => ({
        monto: 6500,
        moneda: 'ARS',
        periodicidad: 'mensual',
        actualizadoEl: new Date().toISOString(),
        actualizadoPor: 'admin@vel.com'
      }),
      getSubscriber: async () => legacySubscriber,
      createPreference: async (params) => {
        capturedAmount = params.amount;
        return {
          success: true,
          data: { id: 'pref-legacy-01', init_point: 'https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=pref-legacy-01' }
        };
      },
      recordPreferenceIntent: async () => {}
    }
  );
  assert(legacyPrefRes.statusCode === 200 && capturedAmount === 3200, 'Suscriptor histórico autenticado conserva exactamente su tarifa histórica al renovar');

  // ------------------------------------------------------------------
  // 8. Ausencia de datos personales en Firebase / rechazo de PII + cambio de rol controlado
  // ------------------------------------------------------------------
  console.log('\n--- 8. Ausencia de datos personales en Firebase y cambio controlado de rol ---');
  const piiAttempts = ['email', 'name', 'phone', 'photos', 'videos', 'messages', 'chats', 'documents'];
  for (const field of piiAttempts) {
    const payload = {
      deviceId: generateRandomDeviceId('CORE'),
      role: 'CORE',
      publicKeySpkiBase64: movMaterial.publicKeySpkiBase64,
      signingPublicKeySpkiBase64: movMaterial.signingPublicKeySpkiBase64,
      fingerprint: movMaterial.fingerprint,
      [field]: 'personal-sensitive-value'
    };
    const detected = findForbiddenFields(payload);
    assert(detected.includes(field), `Validador de servidor detecta campo prohibido "${field}"`);
  }

  // Cambio controlado de rol: exige palabra exacta CAMBIAR ROL
  const deniedRoleChange = await executeControlledRoleChange('cambiar', {
    storage: browserStorage,
    getFreshToken: async () => `valid-token-${coreUid}`,
    fetchFn: makeFetchAdapter(coreUid)
  });
  assert(!deniedRoleChange.success, 'Cambio de rol rechazado si no se ingresa la confirmación textual exacta');
  assert((await browserStorage.getIdentity()) !== null, 'La identidad persistida permanece intacta tras rechazo de cambio de rol');

  const allowedRoleChange = await executeControlledRoleChange('CAMBIAR ROL', {
    storage: browserStorage,
    getFreshToken: async () => `valid-token-${coreUid}`,
    signOutAnonymous: async () => {},
    fetchFn: makeFetchAdapter(coreUid)
  });
  assert(allowedRoleChange.success, 'Cambio controlado de rol ejecutado tras confirmación explícita');
  assert((await browserStorage.getIdentity()) === null, 'Identidad local limpiada tras cambio de rol');
  assert(
    dbMemory.devices.get(storedLocal!.deviceId)?.status === 'revoked',
    'Identidad anterior revocada limpiamente en Firestore al cambiar rol'
  );

  // Verificar coincidencia SHA-256 cliente vs servidor
  const digestHex = createHash('sha256')
    .update(Buffer.from(movMaterial.publicKeySpkiBase64, 'base64'))
    .digest();
  const nodeFp = Array.from(digestHex)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
  const webFp = await computeFingerprintFromBase64Spki(movMaterial.publicKeySpkiBase64);
  assert(nodeFp === webFp, 'Huella SHA-256 calculada por Web Crypto coincide bit a bit con Node crypto');

  // ------------------------------------------------------------------
  // 9. Protección estricta contra "Illegal invocation" al invocar fetch
  // ------------------------------------------------------------------
  console.log('\n--- 9. Contexto seguro de Window/globalThis al invocar fetch ---');
  const originalGlobalFetch = globalThis.fetch;
  const strictBrowserStorage = createPersistentStorageStub();
  const strictUid = 'uid-strict-fetch-core-01';
  const strictFetchAdapter = makeFetchAdapter(strictUid);

  try {
    // Simula exactamente la validación WebIDL de Chrome/Window.fetch sobre `this`
    (globalThis as any).fetch = async function strictWindowFetch(
      this: unknown,
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> {
      if (this !== globalThis) {
        throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
      }
      return strictFetchAdapter(input, init);
    };

    const strictSetup = await setupNewDeviceIdentity('CORE', undefined, {
      storage: strictBrowserStorage,
      ensureAnonymousAuth: async () => ({
        success: true,
        uid: strictUid,
        idToken: `valid-token-${strictUid}`
      })
    });
    assert(
      strictSetup.success && strictSetup.registeredInServer && Boolean(strictSetup.identity?.deviceId),
      'setupNewDeviceIdentity registra CORE sin lanzar Illegal invocation usando globalThis.fetch'
    );

    const strictSync = await syncPersistedDeviceSession({
      storage: strictBrowserStorage,
      getFreshToken: async () => `valid-token-${strictUid}`,
      ensureAnonymousAuth: async () => ({
        success: true,
        uid: strictUid,
        idToken: `valid-token-${strictUid}`
      })
    });
    assert(
      Boolean(strictSync?.synced && strictSync.identity.deviceId === strictSetup.identity?.deviceId),
      'syncPersistedDeviceSession consulta /api/device-session sin lanzar Illegal invocation'
    );

    // También probar retryPendingDeviceRegistration pasando explícitamente window/globalThis.fetch sin .bind()
    const pendingStorage = createPersistentStorageStub();
    const pendingUid = 'uid-strict-retry-core-02';
    const pendingAdapter = makeFetchAdapter(pendingUid);
    (globalThis as any).fetch = async function strictWindowFetchRetry(
      this: unknown,
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> {
      if (this !== globalThis) {
        throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
      }
      return pendingAdapter(input, init);
    };

    const initialMaterial = await generateDeviceCryptoMaterial('CORE');
    await pendingStorage.saveIdentity({
      id: 'current',
      deviceId: initialMaterial.deviceId,
      role: 'CORE',
      fingerprint: initialMaterial.fingerprint,
      publicKeySpkiBase64: initialMaterial.publicKeySpkiBase64,
      signingPublicKeySpkiBase64: initialMaterial.signingPublicKeySpkiBase64,
      privateEcdhKey: initialMaterial.ecdhKeyPair.privateKey,
      privateSigningKey: initialMaterial.signingKeyPair.privateKey,
      firebaseAuthUid: pendingUid,
      registrationStatus: 'pending_local',
      activeLinkId: null,
      pairedPeerDeviceId: null,
      lastServerError: "Failed to execute 'fetch' on 'Window': Illegal invocation",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    const retryStrict = await retryPendingDeviceRegistration({
      storage: pendingStorage,
      ensureAnonymousAuth: async () => ({
        success: true,
        uid: pendingUid,
        idToken: `valid-token-${pendingUid}`
      }),
      fetchFn: globalThis.fetch
    });
    assert(
      retryStrict.success &&
        retryStrict.registeredInServer &&
        retryStrict.identity?.deviceId === initialMaterial.deviceId,
      'retryPendingDeviceRegistration conserva deviceId existente y registra sin Illegal invocation incluso con fetchFn: globalThis.fetch'
    );

    // Verificar también VelRelayClient.revokePairedTerminal con fallback HTTP sin fetchFn personalizado
    const strictClient = new VelRelayClient({
      storage: strictBrowserStorage,
      getFirebaseIdToken: async () => `valid-token-${strictUid}`
    });
    let sawRevokeRoute = false;
    (globalThis as any).fetch = async function strictWindowFetchRevoke(
      this: unknown,
      input: RequestInfo | URL
    ): Promise<Response> {
      if (this !== globalThis) {
        throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
      }
      if (String(input).startsWith('/api/revoke-device')) {
        sawRevokeRoute = true;
      }
      return new Response(JSON.stringify({ success: false, error: 'Terminal no especificado (prueba contexto)' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    };
    await strictClient.revokePairedTerminal('VEL-MOV-NOEXISTE1234', 'Prueba contexto fetch');
    assert(
      sawRevokeRoute,
      'VelRelayClient invoca this.fetchFn(/api/revoke-device) con contexto globalThis sin Illegal invocation'
    );
  } finally {
    (globalThis as any).fetch = originalGlobalFetch;
  }

  // ------------------------------------------------------------------
  // 11. Regresión: "Completar registro en la nube" real, errores explícitos y recuperación 409 mismo UID
  // ------------------------------------------------------------------
  console.log('\n--- 11. Regresión de reintento real y diagnóstico de configuración ---');
  const diagStorage = createPersistentStorageStub();
  const diagMaterial = await generateDeviceCryptoMaterial('CORE');
  const diagUid = 'anon-uid-core-retry-diag-1';
  await diagStorage.saveIdentity({
    id: 'current',
    deviceId: diagMaterial.deviceId,
    role: 'CORE',
    fingerprint: diagMaterial.fingerprint,
    publicKeySpkiBase64: diagMaterial.publicKeySpkiBase64,
    signingPublicKeySpkiBase64: diagMaterial.signingPublicKeySpkiBase64,
    privateEcdhKey: diagMaterial.ecdhKeyPair.privateKey,
    privateSigningKey: diagMaterial.signingKeyPair.privateKey,
    firebaseAuthUid: null,
    registrationStatus: 'pending_local',
    activeLinkId: null,
    pairedPeerDeviceId: null,
    lastServerError: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });

  // 11a. Error real si Firebase Anonymous Auth está deshabilitado en consola (nunca inventa éxito)
  const disabledAuthRetry = await retryPendingDeviceRegistration({
    storage: diagStorage,
    ensureAnonymousAuth: async () => ({
      success: false,
      providerDisabled: true,
      errorCode: 'auth/operation-not-allowed',
      errorMessage: 'Firebase Anonymous Authentication no está habilitado en Firebase Console para proyecto-vel (auth/operation-not-allowed).'
    })
  });
  assert(
    !disabledAuthRetry.success &&
      !disabledAuthRetry.registeredInServer &&
      disabledAuthRetry.requiresExternalConfig === true &&
      (disabledAuthRetry.error || '').includes('Anonymous Authentication') &&
      disabledAuthRetry.identity?.registrationStatus === 'pending_local',
    'Fallo de Firebase Anonymous Auth no simula éxito, marca requiresExternalConfig y conserva pending_local'
  );

  // 11b. Error real 503 FIREBASE_SERVICE_ACCOUNT pendiente en Netlify (incluye variable faltante)
  const missingSaRetry = await retryPendingDeviceRegistration({
    storage: diagStorage,
    ensureAnonymousAuth: async () => ({
      success: true,
      uid: diagUid,
      idToken: `valid-token-${diagUid}`
    }),
    fetchFn: async (input, init) => {
      const url = String(input);
      if (url.startsWith('/api/register-device')) {
        const res = await registerDeviceHandler(
          {
            httpMethod: init?.method || 'POST',
            headers: init?.headers || {},
            body: typeof init?.body === 'string' ? init.body : undefined
          },
          {
            verifyToken: async () => ({ authenticated: true, uid: diagUid, email: '' }),
            hasDbCredentials: () => false
          }
        );
        return new Response(res.body, { status: res.statusCode, headers: (res.headers || { 'Content-Type': 'application/json' }) as Record<string, string> });
      }
      throw new Error(`Ruta inesperada: ${url}`);
    }
  });
  assert(
    !missingSaRetry.success &&
      !missingSaRetry.registeredInServer &&
      missingSaRetry.requiresExternalConfig === true &&
      (missingSaRetry.error || '').includes('FIREBASE_SERVICE_ACCOUNT') &&
      missingSaRetry.identity?.registrationStatus === 'pending_local',
    'HTTP 503 por FIREBASE_SERVICE_ACCOUNT faltante informa variable exacta y no simula registro exitoso'
  );

  // 11c. Recuperación legítima cuando Firestore ya tiene el documento del mismo authUid (409 -> /api/device-session 200)
  await registerDeviceHandler(
    {
      httpMethod: 'POST',
      headers: { Authorization: `Bearer valid-token-${diagUid}` },
      body: JSON.stringify({
        deviceId: diagMaterial.deviceId,
        role: 'CORE',
        publicKeySpkiBase64: diagMaterial.publicKeySpkiBase64,
        signingPublicKeySpkiBase64: diagMaterial.signingPublicKeySpkiBase64,
        fingerprint: diagMaterial.fingerprint
      })
    },
    {
      verifyToken: async () => ({ authenticated: true, uid: diagUid, email: '' }),
      hasDbCredentials: () => true,
      getDeviceStore: () => dbMemory.store
    }
  );

  // Primero comprobar que otro UID distinto NO puede recuperar ese 409
  const hijacked409Retry = await retryPendingDeviceRegistration({
    storage: diagStorage,
    ensureAnonymousAuth: async () => ({
      success: true,
      uid: 'different-attacker-uid',
      idToken: 'valid-token-attacker'
    }),
    fetchFn: async (input, init) => {
      const url = String(input);
      const authHeader = (init?.headers as Record<string, string>)?.Authorization || '';
      if (url.startsWith('/api/register-device')) {
        const res = await registerDeviceHandler(
          {
            httpMethod: 'POST',
            headers: { Authorization: authHeader },
            body: typeof init?.body === 'string' ? init.body : undefined
          },
          {
            verifyToken: async () => ({ authenticated: true, uid: 'different-attacker-uid', email: '' }),
            hasDbCredentials: () => true,
            getDeviceStore: () => dbMemory.store
          }
        );
        return new Response(res.body, { status: res.statusCode, headers: (res.headers || { 'Content-Type': 'application/json' }) as Record<string, string> });
      }
      if (url.startsWith('/api/device-session')) {
        const query = url.includes('?') ? url.split('?')[1] : '';
        const params = new URLSearchParams(query);
        const res = await deviceSessionHandler(
          {
            httpMethod: 'GET',
            headers: { Authorization: authHeader },
            queryStringParameters: Object.fromEntries(params.entries())
          },
          {
            verifyToken: async () => ({ authenticated: true, uid: 'different-attacker-uid', email: '' }),
            hasDbCredentials: () => true,
            getDeviceStore: () => dbMemory.store
          }
        );
        return new Response(res.body, { status: res.statusCode, headers: (res.headers || { 'Content-Type': 'application/json' }) as Record<string, string> });
      }
      throw new Error(`Ruta inesperada: ${url}`);
    }
  });
  assert(
    !hijacked409Retry.success && hijacked409Retry.identity?.registrationStatus === 'pending_local',
    'Un UID distinto que recibe 409 sigue siendo rechazado y no obtiene acceso al dispositivo'
  );

  // Ahora el mismo authUid propietario sí sincroniza su estado real en Firestore
  const sameUid409Retry = await retryPendingDeviceRegistration({
    storage: diagStorage,
    ensureAnonymousAuth: async () => ({
      success: true,
      uid: diagUid,
      idToken: `valid-token-${diagUid}`
    }),
    fetchFn: async (input, init) => {
      const url = String(input);
      const authHeader = (init?.headers as Record<string, string>)?.Authorization || '';
      if (url.startsWith('/api/register-device')) {
        const res = await registerDeviceHandler(
          {
            httpMethod: 'POST',
            headers: { Authorization: authHeader },
            body: typeof init?.body === 'string' ? init.body : undefined
          },
          {
            verifyToken: async () => ({ authenticated: true, uid: diagUid, email: '' }),
            hasDbCredentials: () => true,
            getDeviceStore: () => dbMemory.store
          }
        );
        return new Response(res.body, { status: res.statusCode, headers: (res.headers || { 'Content-Type': 'application/json' }) as Record<string, string> });
      }
      if (url.startsWith('/api/device-session')) {
        const query = url.includes('?') ? url.split('?')[1] : '';
        const params = new URLSearchParams(query);
        const res = await deviceSessionHandler(
          {
            httpMethod: 'GET',
            headers: { Authorization: authHeader },
            queryStringParameters: Object.fromEntries(params.entries())
          },
          {
            verifyToken: async () => ({ authenticated: true, uid: diagUid, email: '' }),
            hasDbCredentials: () => true,
            getDeviceStore: () => dbMemory.store
          }
        );
        return new Response(res.body, { status: res.statusCode, headers: (res.headers || { 'Content-Type': 'application/json' }) as Record<string, string> });
      }
      throw new Error(`Ruta inesperada: ${url}`);
    }
  });
  assert(
    sameUid409Retry.success &&
      sameUid409Retry.registeredInServer &&
      sameUid409Retry.identity?.registrationStatus === 'registered' &&
      sameUid409Retry.identity?.lastServerError === null,
    'Si Firestore ya registró el deviceId del mismo authUid (409 tras caída de red), /api/device-session recupera el estado real registered'
  );

  console.log('\n==================================================================');
  console.log(`RESUMEN DE PRUEBAS IDENTIDAD Y FIREBASE: ${passed} PASS / ${failed} FAIL`);
  console.log('==================================================================');
  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Error fatal ejecutando pruebas de identidad:', err);
  process.exit(1);
});
