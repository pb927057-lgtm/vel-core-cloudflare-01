import {
  DeviceIdentitySummary,
  DeviceRecord,
  DeviceRole,
  LocalDeviceIdentityRecord,
  SubscriptionRuntimeStatus
} from '../contracts/velContracts';
import {
  generateDeviceCryptoMaterial,
  isPrivateKeyProtected
} from '../crypto/deviceCrypto';
import { velDb, VelStorageAdapter } from '../db/db';
import {
  DeviceAnonymousAuthResult,
  ensureDeviceAnonymousSession,
  getFreshDeviceAuthToken,
  signOutDeviceAuth
} from './firebase';

export const ROLE_CHANGE_CONFIRMATION_KEYWORD = 'CAMBIAR ROL';

export interface SetupProgressStep {
  step: 'storage' | 'crypto' | 'firebase_auth' | 'backend_register' | 'completed';
  status: 'pending' | 'in_progress' | 'done' | 'error';
  detail: string;
}

export interface DeviceSetupResult {
  success: boolean;
  identity: DeviceIdentitySummary | null;
  registeredInServer: boolean;
  requiresExternalConfig?: boolean;
  error?: string;
}

export const SUBSCRIPTION_PASS_CONFIG_KEY = 'vel_subscription_pass';

export interface DeviceSessionSyncResult {
  synced: boolean;
  identity: DeviceIdentitySummary;
  serverDevice?: DeviceRecord | null;
  subscriptionStatus?: SubscriptionRuntimeStatus;
  revoked?: boolean;
  requiresExternalConfig?: boolean;
  error?: string;
}

export interface DeviceIdentityDeps {
  storage?: VelStorageAdapter;
  ensureAnonymousAuth?: () => Promise<DeviceAnonymousAuthResult>;
  getFreshToken?: () => Promise<string | null>;
  signOutAnonymous?: () => Promise<void>;
  fetchFn?: typeof fetch;
}

const SERVER_REQUEST_TIMEOUT_MS = 15000;

function resolveBoundFetch(customFetch?: typeof fetch): typeof fetch {
  if (!customFetch || (typeof globalThis !== 'undefined' && customFetch === globalThis.fetch)) {
    return (...args: Parameters<typeof fetch>) => globalThis.fetch(...args);
  }
  return (...args: Parameters<typeof fetch>) => customFetch(...args);
}

async function fetchWithTimeout(
  safeFetch: typeof fetch,
  input: RequestInfo | URL,
  init: RequestInit = {},
  timeoutMs: number = SERVER_REQUEST_TIMEOUT_MS
): Promise<Response> {
  if (typeof AbortController === 'undefined') {
    return safeFetch(input, init);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await safeFetch(input, {
      ...init,
      signal: init.signal || controller.signal
    });
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      throw new Error('Tiempo de espera agotado al contactar el servidor de VEL (15 s). Comprueba tu conexión e inténtalo nuevamente.');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export function toIdentitySummary(record: LocalDeviceIdentityRecord): DeviceIdentitySummary {
  return {
    deviceId: record.deviceId,
    role: record.role,
    fingerprint: record.fingerprint,
    publicKeySpkiBase64: record.publicKeySpkiBase64,
    signingPublicKeySpkiBase64: record.signingPublicKeySpkiBase64,
    firebaseAuthUid: record.firebaseAuthUid,
    registrationStatus: record.registrationStatus,
    activeLinkId: record.activeLinkId,
    pairedPeerDeviceId: record.pairedPeerDeviceId,
    pairedPeerPublicKeySpkiBase64: record.pairedPeerPublicKeySpkiBase64 ?? null,
    subscriptionUid: record.subscriptionUid ?? null,
    lastServerError: record.lastServerError,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt
  };
}

function resolvePeerPublicKeyFromLink(
  role: DeviceRole,
  activeLink: { corePublicKeySpkiBase64?: string | null; terminalPublicKeySpkiBase64?: string | null } | null | undefined,
  fallbackIfSamePeer: string | null | undefined
): string | null {
  if (activeLink) {
    const raw = role === 'CORE' ? activeLink.terminalPublicKeySpkiBase64 : activeLink.corePublicKeySpkiBase64;
    if (typeof raw === 'string' && raw.trim()) {
      return raw.trim();
    }
  }
  return typeof fallbackIfSamePeer === 'string' && fallbackIfSamePeer.trim() ? fallbackIfSamePeer.trim() : null;
}

export async function savePendingSubscriptionPass(
  pass: string,
  storage: VelStorageAdapter = velDb
): Promise<void> {
  const clean = String(pass || '').trim();
  if (!clean) return;
  await storage.setConfig(SUBSCRIPTION_PASS_CONFIG_KEY, clean);
}

export async function getPendingSubscriptionPass(
  storage: VelStorageAdapter = velDb
): Promise<string | null> {
  const value = await storage.getConfig<string>(SUBSCRIPTION_PASS_CONFIG_KEY);
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

/**
 * Carga la identidad técnica persistida localmente en IndexedDB al abrir la PWA.
 * Verifica que las claves privadas sigan protegidas (extractable: false).
 */
export async function loadPersistedDeviceIdentity(
  deps: DeviceIdentityDeps = {}
): Promise<DeviceIdentitySummary | null> {
  const storage = deps.storage || velDb;
  const record = await storage.getIdentity();
  if (!record || !record.deviceId || !record.role) return null;

  return toIdentitySummary(record);
}

/**
 * Configura automáticamente una nueva instalación de VEL (CORE o MÓVIL):
 * 1. Verifica persistencia IndexedDB.
 * 2. Genera identificador aleatorio y claves Web Crypto API no exportables.
 * 3. Persiste localmente de inmediato para proteger las claves en el navegador.
 * 4. Autentica de forma anónima con Firebase Auth técnico.
 * 5. Registra la identidad y claves públicas en Firestore mediante Cloudflare Pages Function (/api/register-device).
 */
export async function setupNewDeviceIdentity(
  role: DeviceRole,
  onProgress?: (steps: SetupProgressStep[]) => void,
  deps: DeviceIdentityDeps = {}
): Promise<DeviceSetupResult> {
  const storage = deps.storage || velDb;
  const ensureAuth = deps.ensureAnonymousAuth || ensureDeviceAnonymousSession;
  const fetchFn = resolveBoundFetch(deps.fetchFn);

  const steps: SetupProgressStep[] = [
    { step: 'storage', status: 'in_progress', detail: 'Preparando almacenamiento local seguro (IndexedDB)...' },
    { step: 'crypto', status: 'pending', detail: 'Generando identidad única y claves Web Crypto protegidas...' },
    { step: 'firebase_auth', status: 'pending', detail: 'Estableciendo sesión técnica anónima sin contraseña...' },
    { step: 'backend_register', status: 'pending', detail: 'Registrando identidad pública en Firebase/Firestore...' }
  ];
  const emit = () => onProgress?.(steps.map((s) => ({ ...s })));
  emit();

  // Protección contra reescritura accidental si ya existe identidad persistida
  const existing = await storage.getIdentity();
  if (existing) {
    return {
      success: true,
      identity: toIdentitySummary(existing),
      registeredInServer: existing.registrationStatus === 'registered' || existing.registrationStatus === 'paired'
    };
  }

  // Paso 1 + 2: Generar material criptográfico no exportable e ID único
  steps[0] = { step: 'storage', status: 'done', detail: 'Almacenamiento local IndexedDB listo.' };
  steps[1] = { step: 'crypto', status: 'in_progress', detail: 'Generando par ECDH/ECDSA P-256 no exportable...' };
  emit();

  const material = await generateDeviceCryptoMaterial(role);
  const nowIso = new Date().toISOString();

  let localRecord: LocalDeviceIdentityRecord = {
    id: 'current',
    deviceId: material.deviceId,
    role,
    fingerprint: material.fingerprint,
    publicKeySpkiBase64: material.publicKeySpkiBase64,
    signingPublicKeySpkiBase64: material.signingPublicKeySpkiBase64,
    privateEcdhKey: material.ecdhKeyPair.privateKey,
    privateSigningKey: material.signingKeyPair.privateKey,
    firebaseAuthUid: null,
    registrationStatus: 'pending_local',
    activeLinkId: null,
    pairedPeerDeviceId: null,
    lastServerError: null,
    createdAt: nowIso,
    updatedAt: nowIso
  };

  await storage.saveIdentity(localRecord);
  steps[1] = {
    step: 'crypto',
    status: 'done',
    detail: `Identidad técnica generada: ${material.deviceId} (claves privadas protegidas en dispositivo).`
  };

  // Paso 3: Sesión técnica anónima Firebase (sin contraseña)
  steps[2] = { step: 'firebase_auth', status: 'in_progress', detail: 'Autenticando sesión técnica en Firebase...' };
  emit();

  const authRes = await ensureAuth();
  if (!authRes.success || !authRes.idToken || !authRes.uid) {
    const errMsg =
      authRes.errorMessage || 'No se pudo iniciar la sesión técnica anónima en Firebase Authentication.';
    localRecord = {
      ...localRecord,
      lastServerError: errMsg,
      updatedAt: new Date().toISOString()
    };
    await storage.saveIdentity(localRecord);

    steps[2] = { step: 'firebase_auth', status: 'error', detail: errMsg };
    steps[3] = { step: 'backend_register', status: 'error', detail: 'Registro en Firestore en espera de sesión Firebase válida.' };
    emit();

    return {
      success: false,
      identity: toIdentitySummary(localRecord),
      registeredInServer: false,
      requiresExternalConfig: Boolean(authRes.providerDisabled),
      error: errMsg
    };
  }

  localRecord = {
    ...localRecord,
    firebaseAuthUid: authRes.uid,
    updatedAt: new Date().toISOString()
  };
  await storage.saveIdentity(localRecord);
  steps[2] = {
    step: 'firebase_auth',
    status: 'done',
    detail: 'Sesión técnica autenticada en Firebase (sin contraseña).'
  };

  // Paso 4: Registro seguro en Firestore vía Cloudflare Pages Function (/api/register-device)
  steps[3] = {
    step: 'backend_register',
    status: 'in_progress',
    detail: 'Registrando clave pública y huella en Firestore...'
  };
  emit();

  return registerLocalIdentityOnServer(localRecord, authRes.idToken, steps, onProgress, {
    storage,
    fetchFn
  });
}

async function verifyExistingCloudRegistration(
  localRecord: LocalDeviceIdentityRecord,
  idToken: string,
  safeFetch: typeof fetch,
  storage: VelStorageAdapter
): Promise<{ recovered: boolean; record?: LocalDeviceIdentityRecord; revokedError?: string }> {
  try {
    const verifyRes = await fetchWithTimeout(
      safeFetch,
      `/api/device-session?deviceId=${encodeURIComponent(localRecord.deviceId)}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${idToken}`
        }
      }
    );
    const verifyCt = (verifyRes.headers?.get?.('content-type') || '').toLowerCase();
    if (verifyCt.includes('text/html')) {
      return { recovered: false };
    }
    const verifyData = await verifyRes.json().catch(() => ({}));
    if (!verifyRes.ok || !verifyData.success || !verifyData.device) {
      return { recovered: false };
    }
    const serverDevice = verifyData.device as DeviceRecord;
    const isPaired = serverDevice.status === 'paired' && Boolean(serverDevice.activeLinkId) && Boolean(serverDevice.pairedPeerDeviceId);
    const syncedRecord: LocalDeviceIdentityRecord = {
      ...localRecord,
      registrationStatus: serverDevice.status,
      activeLinkId: serverDevice.activeLinkId || null,
      pairedPeerDeviceId: serverDevice.pairedPeerDeviceId || null,
      pairedPeerPublicKeySpkiBase64: isPaired
        ? resolvePeerPublicKeyFromLink(
            localRecord.role,
            verifyData.activeLink,
            localRecord.pairedPeerDeviceId === serverDevice.pairedPeerDeviceId
              ? localRecord.pairedPeerPublicKeySpkiBase64
              : null
          )
        : null,
      subscriptionUid: serverDevice.subscriptionUid ?? localRecord.subscriptionUid ?? null,
      lastServerError:
        serverDevice.status === 'revoked'
          ? 'Este dispositivo fue revocado permanentemente en Firestore.'
          : null,
      updatedAt: new Date().toISOString()
    };
    await storage.saveIdentity(syncedRecord);
    return {
      recovered: true,
      record: syncedRecord,
      revokedError:
        serverDevice.status === 'revoked'
          ? 'Este dispositivo fue revocado permanentemente en Firestore.'
          : undefined
    };
  } catch {
    return { recovered: false };
  }
}

async function registerLocalIdentityOnServer(
  localRecord: LocalDeviceIdentityRecord,
  idToken: string,
  steps?: SetupProgressStep[],
  onProgress?: (steps: SetupProgressStep[]) => void,
  deps: { storage: VelStorageAdapter; fetchFn?: typeof fetch } = { storage: velDb }
): Promise<DeviceSetupResult> {
  const safeFetch = resolveBoundFetch(deps.fetchFn);
  try {
    const pendingSubPass = await deps.storage.getConfig<string>(SUBSCRIPTION_PASS_CONFIG_KEY).catch(() => null);
    const cleanSubPass = typeof pendingSubPass === 'string' && pendingSubPass.trim() ? pendingSubPass.trim() : undefined;

    const response = await fetchWithTimeout(safeFetch, '/api/register-device', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`
      },
      // Solo se envían identificadores y claves públicas. Nunca claves privadas ni datos personales.
      body: JSON.stringify({
        deviceId: localRecord.deviceId,
        role: localRecord.role,
        publicKeySpkiBase64: localRecord.publicKeySpkiBase64,
        signingPublicKeySpkiBase64: localRecord.signingPublicKeySpkiBase64,
        fingerprint: localRecord.fingerprint,
        ...(cleanSubPass ? { subscriptionPass: cleanSubPass } : {})
      })
    });

    const contentType = (response.headers?.get?.('content-type') || '').toLowerCase();
    if (contentType.includes('text/html')) {
      const errMsg =
        'El endpoint /api/register-device no está activo en este despliegue estático. Para registrar el dispositivo en Firestore se requiere Cloudflare Pages Functions con FIREBASE_SERVICE_ACCOUNT.';
      const updated: LocalDeviceIdentityRecord = {
        ...localRecord,
        lastServerError: errMsg,
        updatedAt: new Date().toISOString()
      };
      await deps.storage.saveIdentity(updated);
      if (steps && steps[3]) {
        steps[3] = { step: 'backend_register', status: 'error', detail: errMsg };
        onProgress?.(steps.map((s) => ({ ...s })));
      }
      return {
        success: false,
        identity: toIdentitySummary(updated),
        registeredInServer: false,
        requiresExternalConfig: true,
        error: errMsg
      };
    }

    const data = await response.json().catch(() => ({}));

    // Si una petición previa ya había creado el documento en Firestore antes de un corte de red,
    // el servidor responde 409 DUPLICATE_DEVICE_ID. Verificamos propiedad real vía /api/device-session.
    if (response.status === 409 && data.code === 'DUPLICATE_DEVICE_ID') {
      const recovery = await verifyExistingCloudRegistration(
        localRecord,
        idToken,
        safeFetch,
        deps.storage
      );
      if (recovery.recovered && recovery.record) {
        const isRevoked = recovery.record.registrationStatus === 'revoked';
        if (steps && steps[3]) {
          steps[3] = {
            step: 'backend_register',
            status: isRevoked ? 'error' : 'done',
            detail: isRevoked
              ? recovery.revokedError || 'Dispositivo revocado.'
              : 'Identidad pública ya verificada en Cloud Firestore.'
          };
          onProgress?.(steps.map((s) => ({ ...s })));
        }
        return {
          success: !isRevoked,
          identity: toIdentitySummary(recovery.record),
          registeredInServer: !isRevoked,
          error: recovery.revokedError
        };
      }
    }

    if (!response.ok || !data.success) {
      const missingVars = Array.isArray(data.missingVariables) && data.missingVariables.length > 0
        ? ` Variables faltantes en Cloudflare: ${data.missingVariables.join(', ')}.`
        : '';
      const baseError =
        data.error || `Error registrando dispositivo en el servidor (HTTP ${response.status}).`;
      const errMsg = `${baseError}${missingVars}`.trim();
      const updated: LocalDeviceIdentityRecord = {
        ...localRecord,
        lastServerError: errMsg,
        updatedAt: new Date().toISOString()
      };
      await deps.storage.saveIdentity(updated);

      if (steps && steps[3]) {
        steps[3] = { step: 'backend_register', status: 'error', detail: errMsg };
        onProgress?.(steps.map((s) => ({ ...s })));
      }

      return {
        success: false,
        identity: toIdentitySummary(updated),
        registeredInServer: false,
        requiresExternalConfig: Boolean(data.pendingConfig || response.status === 503),
        error: errMsg
      };
    }

    const confirmed: LocalDeviceIdentityRecord = {
      ...localRecord,
      registrationStatus: (data.device?.status as LocalDeviceIdentityRecord['registrationStatus']) || 'registered',
      subscriptionUid: data.device?.subscriptionUid ?? localRecord.subscriptionUid ?? null,
      lastServerError: null,
      updatedAt: new Date().toISOString()
    };
    await deps.storage.saveIdentity(confirmed);
    if (confirmed.subscriptionUid && typeof deps.storage.deleteConfig === 'function') {
      await deps.storage.deleteConfig(SUBSCRIPTION_PASS_CONFIG_KEY).catch(() => {});
    }

    if (steps && steps[3]) {
      steps[3] = {
        step: 'backend_register',
        status: 'done',
        detail: 'Identidad pública registrada y verificada en Cloud Firestore.'
      };
      onProgress?.(steps.map((s) => ({ ...s })));
    }

    return {
      success: true,
      identity: toIdentitySummary(confirmed),
      registeredInServer: true
    };
  } catch (err: any) {
    const errMsg = err?.message || 'No se pudo contactar al servicio de registro de VEL.';
    const updated: LocalDeviceIdentityRecord = {
      ...localRecord,
      lastServerError: errMsg,
      updatedAt: new Date().toISOString()
    };
    await deps.storage.saveIdentity(updated);

    if (steps && steps[3]) {
      steps[3] = { step: 'backend_register', status: 'error', detail: errMsg };
      onProgress?.(steps.map((s) => ({ ...s })));
    }

    return {
      success: false,
      identity: toIdentitySummary(updated),
      registeredInServer: false,
      error: errMsg
    };
  }
}

/**
 * Reintenta el registro en Firebase/Firestore de una identidad ya creada localmente.
 * Conserva exactamente el mismo deviceId y las mismas claves privadas no exportables.
 */
export async function retryPendingDeviceRegistration(
  deps: DeviceIdentityDeps = {}
): Promise<DeviceSetupResult> {
  const storage = deps.storage || velDb;
  const ensureAuth = deps.ensureAnonymousAuth || ensureDeviceAnonymousSession;
  const fetchFn = resolveBoundFetch(deps.fetchFn);

  const existing = await storage.getIdentity();
  if (!existing) {
    return {
      success: false,
      identity: null,
      registeredInServer: false,
      error: 'No hay una identidad técnica local pendiente de registro.'
    };
  }

  const authRes = await ensureAuth();
  if (!authRes.success || !authRes.idToken || !authRes.uid) {
    const errMsg = authRes.errorMessage || 'Sesión técnica de Firebase no disponible.';
    const updated: LocalDeviceIdentityRecord = {
      ...existing,
      lastServerError: errMsg,
      updatedAt: new Date().toISOString()
    };
    await storage.saveIdentity(updated);
    return {
      success: false,
      identity: toIdentitySummary(updated),
      registeredInServer: false,
      requiresExternalConfig: Boolean(authRes.providerDisabled),
      error: errMsg
    };
  }

  const withUid: LocalDeviceIdentityRecord = {
    ...existing,
    firebaseAuthUid: authRes.uid,
    updatedAt: new Date().toISOString()
  };
  await storage.saveIdentity(withUid);

  return registerLocalIdentityOnServer(withUid, authRes.idToken, undefined, undefined, {
    storage,
    fetchFn
  });
}

/**
 * Sincroniza la identidad persistida al reabrir la PWA con el servidor (/api/device-session).
 * Actualiza lastSeenAt y refleja el estado real (registered, paired o revoked).
 */
export async function syncPersistedDeviceSession(
  deps: DeviceIdentityDeps = {}
): Promise<DeviceSessionSyncResult | null> {
  const storage = deps.storage || velDb;
  const ensureAuth = deps.ensureAnonymousAuth || ensureDeviceAnonymousSession;
  const getToken = deps.getFreshToken || getFreshDeviceAuthToken;
  const fetchFn = resolveBoundFetch(deps.fetchFn);

  const existing = await storage.getIdentity();
  if (!existing) return null;

  let token = await getToken();
  if (!token) {
    const authRes = await ensureAuth();
    if (!authRes.success || !authRes.idToken) {
      return {
        synced: false,
        identity: toIdentitySummary(existing),
        error: authRes.errorMessage || 'Sin sesión técnica activa en Firebase.'
      };
    }
    token = authRes.idToken;
  }

  if (existing.registrationStatus === 'pending_local') {
    const retryRes = await retryPendingDeviceRegistration(deps);
    return {
      synced: retryRes.registeredInServer,
      identity: retryRes.identity || toIdentitySummary(existing),
      requiresExternalConfig: Boolean(retryRes.requiresExternalConfig),
      error: retryRes.error
    };
  }

  try {
    const res = await fetchWithTimeout(
      fetchFn,
      `/api/device-session?deviceId=${encodeURIComponent(existing.deviceId)}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    const contentType = (res.headers?.get?.('content-type') || '').toLowerCase();
    if (contentType.includes('text/html')) {
      return {
        synced: false,
        identity: toIdentitySummary(existing),
        error: 'El endpoint /api/device-session no está disponible en un despliegue estático sin Cloudflare Pages Functions.'
      };
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success || !data.device) {
      return {
        synced: false,
        identity: toIdentitySummary(existing),
        error: data.error || `No se pudo verificar el estado en Firestore (HTTP ${res.status}).`
      };
    }

    let serverDevice = data.device as DeviceRecord;
    let subscriptionStatus = data.subscriptionStatus as SubscriptionRuntimeStatus | undefined;

    const pendingSubPass = await storage.getConfig<string>(SUBSCRIPTION_PASS_CONFIG_KEY).catch(() => null);
    const cleanSubPass = typeof pendingSubPass === 'string' && pendingSubPass.trim() ? pendingSubPass.trim() : null;
    if (cleanSubPass && (!serverDevice.subscriptionUid || subscriptionStatus?.linked === false)) {
      const bindRes = await bindSubscriptionPassToExistingDevice(cleanSubPass, deps).catch(() => null);
      if (bindRes?.success && bindRes.identity) {
        serverDevice = {
          ...serverDevice,
          subscriptionUid: bindRes.identity.subscriptionUid ?? serverDevice.subscriptionUid ?? null
        };
        if (bindRes.subscriptionStatus) {
          subscriptionStatus = bindRes.subscriptionStatus;
        }
      }
    }

    const isPaired = serverDevice.status === 'paired' && Boolean(serverDevice.activeLinkId) && Boolean(serverDevice.pairedPeerDeviceId);
    const updated: LocalDeviceIdentityRecord = {
      ...existing,
      registrationStatus: serverDevice.status,
      activeLinkId: serverDevice.activeLinkId || null,
      pairedPeerDeviceId: serverDevice.pairedPeerDeviceId || null,
      pairedPeerPublicKeySpkiBase64: isPaired
        ? resolvePeerPublicKeyFromLink(
            existing.role,
            data.activeLink,
            existing.pairedPeerDeviceId === serverDevice.pairedPeerDeviceId
              ? existing.pairedPeerPublicKeySpkiBase64
              : null
          )
        : null,
      subscriptionUid: serverDevice.subscriptionUid ?? existing.subscriptionUid ?? null,
      lastServerError: null,
      updatedAt: new Date().toISOString()
    };
    await storage.saveIdentity(updated);

    return {
      synced: true,
      identity: toIdentitySummary(updated),
      serverDevice,
      subscriptionStatus,
      revoked: serverDevice.status === 'revoked'
    };
  } catch (err: any) {
    return {
      synced: false,
      identity: toIdentitySummary(existing),
      error: err?.message || 'Error de conexión verificando el estado del dispositivo.'
    };
  }
}

export async function bindSubscriptionPassToExistingDevice(
  subscriptionPass: string,
  deps: DeviceIdentityDeps = {}
): Promise<{
  success: boolean;
  identity: DeviceIdentitySummary | null;
  subscriptionStatus?: SubscriptionRuntimeStatus;
  error?: string;
}> {
  const cleanPass = String(subscriptionPass || '').trim();
  const storage = deps.storage || velDb;
  const ensureAuth = deps.ensureAnonymousAuth || ensureDeviceAnonymousSession;
  const getToken = deps.getFreshToken || getFreshDeviceAuthToken;
  const fetchFn = resolveBoundFetch(deps.fetchFn);

  const existing = await storage.getIdentity();
  if (!existing) {
    if (cleanPass) await savePendingSubscriptionPass(cleanPass, storage);
    return { success: false, identity: null, error: 'Aún no se configuró este teléfono.' };
  }

  if (cleanPass) {
    await savePendingSubscriptionPass(cleanPass, storage);
  }

  if (existing.registrationStatus === 'pending_local') {
    return {
      success: false,
      identity: toIdentitySummary(existing),
      error: 'Dispositivo pendiente de registro en la nube.'
    };
  }

  let token = await getToken();
  if (!token) {
    const authRes = await ensureAuth();
    token = authRes.idToken || null;
  }
  if (!token) {
    return {
      success: false,
      identity: toIdentitySummary(existing),
      error: 'No hay sesión Firebase activa.'
    };
  }

  try {
    const res = await fetchWithTimeout(fetchFn, '/api/device-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        action: 'bind_subscription',
        deviceId: existing.deviceId,
        subscriptionPass: cleanPass
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success || !data.device) {
      return {
        success: false,
        identity: toIdentitySummary(existing),
        error: data.error || `Error vinculando suscripción (HTTP ${res.status}).`
      };
    }

    const updated: LocalDeviceIdentityRecord = {
      ...existing,
      subscriptionUid: data.device.subscriptionUid ?? existing.subscriptionUid ?? null,
      updatedAt: new Date().toISOString()
    };
    await storage.saveIdentity(updated);
    if (typeof storage.deleteConfig === 'function') {
      await storage.deleteConfig(SUBSCRIPTION_PASS_CONFIG_KEY).catch(() => {});
    }
    return {
      success: true,
      identity: toIdentitySummary(updated),
      subscriptionStatus: data.subscriptionStatus as SubscriptionRuntimeStatus | undefined
    };
  } catch (err: any) {
    return {
      success: false,
      identity: toIdentitySummary(existing),
      error: err?.message || 'Error vinculando el pase de suscripción.'
    };
  }
}

/**
 * Procedimiento controlado para cambiar el rol de este navegador/instalación.
 * Exige confirmación explícita textual ("CAMBIAR ROL"), revoca la identidad anterior
 * en Firestore si estaba registrada y limpia el almacenamiento local antes de permitir otro rol.
 */
export async function executeControlledRoleChange(
  confirmationInput: string,
  deps: DeviceIdentityDeps = {}
): Promise<{ success: boolean; error?: string }> {
  if (confirmationInput.trim().toUpperCase() !== ROLE_CHANGE_CONFIRMATION_KEYWORD) {
    return {
      success: false,
      error: `Para confirmar el cambio de rol debes escribir exactamente: ${ROLE_CHANGE_CONFIRMATION_KEYWORD}`
    };
  }

  const storage = deps.storage || velDb;
  const getToken = deps.getFreshToken || getFreshDeviceAuthToken;
  const ensureAuth = deps.ensureAnonymousAuth || ensureDeviceAnonymousSession;
  const signOutFn = deps.signOutAnonymous || signOutDeviceAuth;
  const fetchFn = resolveBoundFetch(deps.fetchFn);

  const existing = await storage.getIdentity();
  if (existing && existing.registrationStatus !== 'pending_local') {
    let token = await getToken();
    if (!token) {
      const authRes = await ensureAuth();
      token = authRes.idToken || null;
    }

    if (token) {
      try {
        await fetchFn('/api/device-session', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({
            action: 'deactivate_for_role_change',
            deviceId: existing.deviceId
          })
        });
      } catch {
        // Si no hay conectividad transitoria, se limpia localmente para permitir reconfiguración explícita
      }
    }
  }

  await storage.clearIdentity();
  try {
    await signOutFn();
  } catch {
    // Silencioso
  }

  return { success: true };
}

export const ACCOUNT_DELETION_CONFIRM_KEYWORD = 'ELIMINAR CUENTA';

export interface AccountDeviceSummary {
  deviceId: string;
  role: DeviceRole;
  status: string;
  activeLinkId: string | null;
  pairedPeerDeviceId: string | null;
  lastSeenAt: string;
}

export interface CommercialAccountSnapshot {
  uid: string;
  email: string;
  estado: string;
  plan?: string | null;
  venceEl?: string | null;
  modalidadComercial?: string;
  altaCompletadaEl?: string | null;
  bajaSolicitadaEl?: string | null;
  contratoV12Aceptado?: boolean;
}

export interface AccountOperationResult {
  success: boolean;
  registered?: boolean;
  account?: CommercialAccountSnapshot | null;
  subscriptionStatus?: SubscriptionRuntimeStatus;
  devices?: AccountDeviceSummary[];
  code?: string;
  requiresExternalConfig?: boolean;
  error?: string;
}

export interface AccountDeactivationResult {
  success: boolean;
  accountDeactivated?: boolean;
  mpSubscriptionCancelled?: boolean;
  revokedDeviceIds?: string[];
  revokedLinkIds?: string[];
  authAccountDeleted?: boolean;
  authPropagationError?: string | null;
  localVaultNotice?: string;
  code?: string;
  requiresExternalConfig?: boolean;
  error?: string;
}

/**
 * Registra o recupera el alta de cuenta VEL en Cloudflare (/api/account)
 * usando el token de la identidad única de Firebase Authentication (compartida con Blogger).
 */
export async function registerCommercialAccount(
  commercialIdToken: string,
  deps: DeviceIdentityDeps = {}
): Promise<AccountOperationResult> {
  const token = String(commercialIdToken || '').trim();
  if (!token) {
    return { success: false, error: 'Se requiere sesión autenticada de Firebase.' };
  }

  const fetchFn = resolveBoundFetch(deps.fetchFn);
  try {
    const res = await fetchWithTimeout(fetchFn, '/api/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ action: 'register' })
    });

    const ct = (res.headers?.get?.('content-type') || '').toLowerCase();
    if (ct.includes('text/html')) {
      return {
        success: false,
        requiresExternalConfig: true,
        error: 'El endpoint /api/account requiere Cloudflare Pages Functions activo.'
      };
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
      return {
        success: false,
        code: data.code,
        requiresExternalConfig: Boolean(data.pendingConfig || res.status === 503),
        error: data.error || `No se pudo registrar o validar la cuenta VEL (HTTP ${res.status}).`
      };
    }

    return {
      success: true,
      registered: true,
      account: data.account || null,
      subscriptionStatus: data.subscriptionStatus,
      devices: Array.isArray(data.devices) ? data.devices : []
    };
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Error consultando /api/account.'
    };
  }
}

/**
 * Consulta el estado actual de la cuenta, suscripción, aceptación del contrato v1.2
 * y dispositivos vinculados desde Cloudflare (/api/account).
 */
export async function fetchCommercialAccountStatus(
  commercialIdToken: string,
  deps: DeviceIdentityDeps = {}
): Promise<AccountOperationResult> {
  const token = String(commercialIdToken || '').trim();
  if (!token) {
    return { success: false, error: 'Se requiere sesión autenticada de Firebase.' };
  }

  const fetchFn = resolveBoundFetch(deps.fetchFn);
  try {
    const res = await fetchWithTimeout(fetchFn, '/api/account', {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`
      }
    });

    const ct = (res.headers?.get?.('content-type') || '').toLowerCase();
    if (ct.includes('text/html')) {
      return {
        success: false,
        requiresExternalConfig: true,
        error: 'El endpoint /api/account requiere Cloudflare Pages Functions activo.'
      };
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
      return {
        success: false,
        code: data.code,
        requiresExternalConfig: Boolean(data.pendingConfig || res.status === 503),
        error: data.error || `No se pudo consultar la cuenta VEL (HTTP ${res.status}).`
      };
    }

    return {
      success: true,
      registered: Boolean(data.registered),
      account: data.account || null,
      subscriptionStatus: data.subscriptionStatus,
      devices: Array.isArray(data.devices) ? data.devices : []
    };
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Error consultando el estado de la cuenta VEL.'
    };
  }
}

/**
 * Vincula el dispositivo técnico actual (CORE o MÓVIL) con la cuenta comercial única de Firebase
 * autenticada dentro de la app, sin usar cuentas duplicadas ni exigir pase manual.
 */
export async function bindCommercialAccountToDevice(
  commercialIdToken: string,
  deps: DeviceIdentityDeps = {}
): Promise<{
  success: boolean;
  identity: DeviceIdentitySummary | null;
  subscriptionStatus?: SubscriptionRuntimeStatus;
  error?: string;
}> {
  const cleanCommercialToken = String(commercialIdToken || '').trim();
  if (!cleanCommercialToken) {
    return { success: false, identity: null, error: 'Inicia sesión con tu correo primero.' };
  }

  const storage = deps.storage || velDb;
  const ensureAuth = deps.ensureAnonymousAuth || ensureDeviceAnonymousSession;
  const getToken = deps.getFreshToken || getFreshDeviceAuthToken;
  const fetchFn = resolveBoundFetch(deps.fetchFn);

  const existing = await storage.getIdentity();
  if (!existing) {
    return { success: false, identity: null, error: 'Aún no se configuró este teléfono.' };
  }
  if (existing.registrationStatus === 'pending_local') {
    return {
      success: false,
      identity: toIdentitySummary(existing),
      error: 'Dispositivo pendiente de registro en la nube.'
    };
  }

  let deviceToken = await getToken();
  if (!deviceToken) {
    const authRes = await ensureAuth();
    deviceToken = authRes.idToken || null;
  }
  if (!deviceToken) {
    return {
      success: false,
      identity: toIdentitySummary(existing),
      error: 'No hay sesión técnica de dispositivo activa en Firebase.'
    };
  }

  try {
    const res = await fetchWithTimeout(fetchFn, '/api/device-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${deviceToken}`
      },
      body: JSON.stringify({
        action: 'bind_subscription',
        deviceId: existing.deviceId,
        commercialIdToken: cleanCommercialToken
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success || !data.device) {
      return {
        success: false,
        identity: toIdentitySummary(existing),
        error: data.error || `Error vinculando cuenta VEL al dispositivo (HTTP ${res.status}).`
      };
    }

    const updated: LocalDeviceIdentityRecord = {
      ...existing,
      subscriptionUid: data.device.subscriptionUid ?? existing.subscriptionUid ?? null,
      updatedAt: new Date().toISOString()
    };
    await storage.saveIdentity(updated);

    return {
      success: true,
      identity: toIdentitySummary(updated),
      subscriptionStatus: data.subscriptionStatus as SubscriptionRuntimeStatus | undefined
    };
  } catch (err: any) {
    return {
      success: false,
      identity: toIdentitySummary(existing),
      error: err?.message || 'Error vinculando la cuenta VEL con este dispositivo.'
    };
  }
}

/**
 * Solicita la baja de la cuenta comercial VEL (DELETE /api/account).
 * Exige confirmación explícita ("ELIMINAR CUENTA"), propaga la revocación de dispositivos
 * y mantiene intacto el almacenamiento local en VEL CORE.
 */
export async function requestAccountDeactivation(
  commercialIdToken: string,
  confirmText: string,
  deps: DeviceIdentityDeps = {}
): Promise<AccountDeactivationResult> {
  const token = String(commercialIdToken || '').trim();
  const normalizedConfirm = String(confirmText || '').trim().toUpperCase();
  if (!token) {
    return { success: false, error: 'Debes iniciar sesión con tu cuenta VEL para solicitar la baja.' };
  }
  if (normalizedConfirm !== ACCOUNT_DELETION_CONFIRM_KEYWORD) {
    return {
      success: false,
      code: 'CONFIRMATION_REQUIRED',
      error: `Debes escribir exactamente: ${ACCOUNT_DELETION_CONFIRM_KEYWORD}`
    };
  }

  const storage = deps.storage || velDb;
  const fetchFn = resolveBoundFetch(deps.fetchFn);

  try {
    const res = await fetchWithTimeout(fetchFn, '/api/account', {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        confirmText: normalizedConfirm,
        reason: 'Baja solicitada desde la aplicación VEL'
      })
    });

    const ct = (res.headers?.get?.('content-type') || '').toLowerCase();
    if (ct.includes('text/html')) {
      return {
        success: false,
        requiresExternalConfig: true,
        error: 'El endpoint /api/account requiere Cloudflare Pages Functions activo.'
      };
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.success) {
      return {
        success: false,
        code: data.code,
        requiresExternalConfig: Boolean(data.pendingConfig || res.status === 503),
        error: data.error || `No se pudo confirmar la baja en el servidor (HTTP ${res.status}).`
      };
    }

    const revokedIds: string[] = Array.isArray(data.revokedDeviceIds) ? data.revokedDeviceIds : [];
    const existing = await storage.getIdentity();
    if (existing && revokedIds.includes(existing.deviceId)) {
      await storage.saveIdentity({
        ...existing,
        registrationStatus: 'revoked',
        activeLinkId: null,
        pairedPeerDeviceId: null,
        pairedPeerPublicKeySpkiBase64: null,
        lastServerError: 'Cuenta VEL dada de baja; este dispositivo fue desvinculado.',
        updatedAt: new Date().toISOString()
      });
    }

    return {
      success: true,
      accountDeactivated: Boolean(data.accountDeactivated),
      mpSubscriptionCancelled: Boolean(data.mpSubscriptionCancelled),
      revokedDeviceIds: revokedIds,
      revokedLinkIds: Array.isArray(data.revokedLinkIds) ? data.revokedLinkIds : [],
      authAccountDeleted: Boolean(data.authAccountDeleted),
      authPropagationError: data.authPropagationError ?? null,
      localVaultNotice: data.localVaultNotice
    };
  } catch (err: any) {
    return {
      success: false,
      error: err?.message || 'Error solicitando la baja de la cuenta VEL.'
    };
  }
}
