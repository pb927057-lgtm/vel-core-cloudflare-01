import type { FirestoreRestClient } from './firebaseRest';
import type {
  AccountDeviceSummary,
  AuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  DeviceRole,
  SuscriptorAdminRecord
} from './types';
import { base64ToBytes, sha256Bytes } from './webCrypto';

export const DEVICE_ID_PATTERN = /^VEL-(CORE|MOV)-[A-Z0-9]{12}$/;

const FORBIDDEN_FIELDS = new Set([
  'privatekey',
  'privateecdhkey',
  'privatesigningkey',
  'private_key',
  'jwk',
  'd',
  'secret',
  'email',
  'correo',
  'phone',
  'telefono',
  'name',
  'nombre',
  'password',
  'contrasena',
  'photos',
  'fotos',
  'videos',
  'messages',
  'mensajes',
  'chats',
  'documents',
  'documentos',
  'contacts',
  'contactos'
]);

export interface RegisterDeviceInput {
  deviceId: string;
  role: DeviceRole;
  publicKeySpkiBase64: string;
  signingPublicKeySpkiBase64: string;
  fingerprint: string;
}

export interface DeviceTransactionContext {
  getDevice: (deviceId: string) => Promise<DeviceRecord | null>;
  createDevice: (record: DeviceRecord) => void;
  updateDevice: (deviceId: string, patch: Partial<DeviceRecord>) => void;
  getLink: (linkId: string) => Promise<DeviceLinkRecord | null>;
  createLink?: (record: DeviceLinkRecord) => void;
  updateLink?: (linkId: string, patch: Partial<DeviceLinkRecord>) => void;
  getAuthorizationByLink: (linkId: string) => Promise<AuthorizationRecord | null>;
  createAuthorization?: (record: AuthorizationRecord) => void;
  updateAuthorization?: (authorizationId: string, patch: Partial<AuthorizationRecord>) => void;
  getSubscriberInTx?: (uid: string) => Promise<SuscriptorAdminRecord | null>;
  findSubscribersByEmailInTx?: (normalizedEmail: string) => Promise<SuscriptorAdminRecord[]>;
  setSubscriberInTx?: (uid: string, record: Partial<SuscriptorAdminRecord>, merge?: boolean) => void;
  findDevicesBySubscriptionUidInTx?: (subscriptionUid: string) => Promise<DeviceRecord[]>;
}

export interface DeviceTransactionStore {
  runTransaction: <T>(fn: (ctx: DeviceTransactionContext) => Promise<T>) => Promise<T>;
  getSubscriber?: (uid: string) => Promise<SuscriptorAdminRecord | null>;
  updateSubscriberStatus?: (uid: string, patch: Partial<SuscriptorAdminRecord>) => Promise<void>;
  listDevicesBySubscriptionUid?: (subscriptionUid: string) => Promise<DeviceRecord[]>;
  hasAcceptedContract?: (uid: string, version: string) => Promise<boolean>;
}

export function isValidDeviceIdForRole(deviceId: string, role: DeviceRole): boolean {
  if (typeof deviceId !== 'string' || !DEVICE_ID_PATTERN.test(deviceId)) {
    return false;
  }
  if (role === 'CORE') return deviceId.startsWith('VEL-CORE-');
  if (role === 'TERMINAL') return deviceId.startsWith('VEL-MOV-');
  return false;
}

export function isValidBase64Spki(val: unknown): val is string {
  if (typeof val !== 'string') return false;
  const trimmed = val.trim();
  if (trimmed.length < 40 || trimmed.length > 2048) return false;
  return /^[A-Za-z0-9+/=]+$/.test(trimmed);
}

export async function computeSha256FingerprintServer(spkiBase64: string): Promise<string> {
  const bytes = base64ToBytes(spkiBase64);
  const digest = await sha256Bytes(bytes);
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}

export function findForbiddenFields(payload: Record<string, any>): string[] {
  if (!payload || typeof payload !== 'object') return [];
  const found: string[] = [];
  for (const key of Object.keys(payload)) {
    if (FORBIDDEN_FIELDS.has(key.toLowerCase().trim())) {
      found.push(key);
    }
  }
  return found;
}

export async function validateDeviceRegistrationPayload(rawPayload: Record<string, any>): Promise<{
  valid: boolean;
  reason?: string;
  code?: string;
  sanitized?: RegisterDeviceInput;
}> {
  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    return { valid: false, code: 'INVALID_BODY', reason: 'Cuerpo de solicitud JSON inválido.' };
  }

  const forbidden = findForbiddenFields(rawPayload);
  if (forbidden.length > 0) {
    return {
      valid: false,
      code: 'FORBIDDEN_FIELDS',
      reason: `Campos prohibidos detectados (${forbidden.join(', ')}). VEL nunca almacena claves privadas ni datos personales en Firebase.`
    };
  }

  const role = rawPayload.role;
  if (role !== 'CORE' && role !== 'TERMINAL') {
    return { valid: false, code: 'INVALID_ROLE', reason: 'Rol técnico inválido. Debe ser CORE o TERMINAL.' };
  }

  const deviceId = String(rawPayload.deviceId || '').trim();
  if (!isValidDeviceIdForRole(deviceId, role)) {
    return {
      valid: false,
      code: 'INVALID_DEVICE_ID',
      reason: 'Identificador técnico inválido o incompatible con el rol seleccionado.'
    };
  }

  if (
    !isValidBase64Spki(rawPayload.publicKeySpkiBase64) ||
    !isValidBase64Spki(rawPayload.signingPublicKeySpkiBase64)
  ) {
    return {
      valid: false,
      code: 'INVALID_PUBLIC_KEY',
      reason: 'Claves públicas SPKI inválidas o incompletas.'
    };
  }

  const publicKeySpkiBase64 = rawPayload.publicKeySpkiBase64.trim();
  const signingPublicKeySpkiBase64 = rawPayload.signingPublicKeySpkiBase64.trim();
  const providedFingerprint = String(rawPayload.fingerprint || '').trim().toUpperCase();

  let expectedFingerprint: string;
  try {
    expectedFingerprint = await computeSha256FingerprintServer(publicKeySpkiBase64);
  } catch {
    return {
      valid: false,
      code: 'INVALID_PUBLIC_KEY',
      reason: 'No se pudo decodificar la clave pública SPKI.'
    };
  }

  if (!providedFingerprint || providedFingerprint !== expectedFingerprint) {
    return {
      valid: false,
      code: 'FINGERPRINT_MISMATCH',
      reason: 'La huella SHA-256 no coincide con la clave pública proporcionada.'
    };
  }

  return {
    valid: true,
    sanitized: {
      deviceId,
      role,
      publicKeySpkiBase64,
      signingPublicKeySpkiBase64,
      fingerprint: expectedFingerprint
    }
  };
}

export interface RegisterDeviceAtomicOutcome {
  ok: boolean;
  statusCode: number;
  code?: string;
  reason?: string;
  device?: DeviceRecord;
}

export async function registerDeviceAtomic(
  store: DeviceTransactionStore,
  authenticatedUid: string,
  input: RegisterDeviceInput,
  now: Date = new Date(),
  subscriptionUid?: string | null
): Promise<RegisterDeviceAtomicOutcome> {
  if (!authenticatedUid || !authenticatedUid.trim()) {
    return {
      ok: false,
      statusCode: 401,
      code: 'UNAUTHENTICATED',
      reason: 'UID autenticado de Firebase requerido.'
    };
  }

  const nowIso = now.toISOString();

  return store.runTransaction(async (ctx) => {
    const existing = await ctx.getDevice(input.deviceId);
    if (existing) {
      return {
        ok: false,
        statusCode: 409,
        code: 'DUPLICATE_DEVICE_ID',
        reason: `El identificador técnico ${input.deviceId} ya se encuentra registrado en Firestore.`
      };
    }

    const cleanSubUid = subscriptionUid ? String(subscriptionUid).trim() || null : null;

    const record: DeviceRecord = {
      deviceId: input.deviceId,
      role: input.role,
      authUid: authenticatedUid,
      publicKeySpkiBase64: input.publicKeySpkiBase64,
      signingPublicKeySpkiBase64: input.signingPublicKeySpkiBase64,
      fingerprint: input.fingerprint,
      status: 'registered',
      activeLinkId: null,
      pairedPeerDeviceId: null,
      subscriptionUid: cleanSubUid,
      createdAt: nowIso,
      lastSeenAt: nowIso,
      updatedAt: nowIso,
      revokedAt: null,
      revokedReason: null
    };

    ctx.createDevice(record);

    return {
      ok: true,
      statusCode: 201,
      device: record
    };
  });
}

export interface DeviceSessionOutcome {
  ok: boolean;
  statusCode: number;
  code?: string;
  reason?: string;
  device?: DeviceRecord;
  activeLink?: DeviceLinkRecord | null;
  activeAuthorization?: AuthorizationRecord | null;
}

export async function getAndRefreshDeviceSessionAtomic(
  store: DeviceTransactionStore,
  authenticatedUid: string,
  deviceId: string,
  now: Date = new Date()
): Promise<DeviceSessionOutcome> {
  const cleanId = String(deviceId || '').trim();
  if (!cleanId) {
    return { ok: false, statusCode: 400, code: 'MISSING_DEVICE_ID', reason: 'Falta deviceId.' };
  }

  return store.runTransaction(async (ctx) => {
    const device = await ctx.getDevice(cleanId);
    if (!device) {
      return {
        ok: false,
        statusCode: 404,
        code: 'DEVICE_NOT_FOUND',
        reason: 'Dispositivo técnico no registrado en Firestore.'
      };
    }

    if (device.authUid !== authenticatedUid) {
      return {
        ok: false,
        statusCode: 403,
        code: 'AUTH_UID_MISMATCH',
        reason: 'El token de Firebase no corresponde al propietario técnico de este dispositivo.'
      };
    }

    const nowIso = now.toISOString();
    ctx.updateDevice(cleanId, {
      lastSeenAt: nowIso,
      updatedAt: nowIso
    });

    const refreshedDevice: DeviceRecord = {
      ...device,
      lastSeenAt: nowIso,
      updatedAt: nowIso
    };

    let activeLink: DeviceLinkRecord | null = null;
    let activeAuthorization: AuthorizationRecord | null = null;

    if (device.activeLinkId) {
      activeLink = await ctx.getLink(device.activeLinkId);
      activeAuthorization = await ctx.getAuthorizationByLink(device.activeLinkId);
    }

    return {
      ok: true,
      statusCode: 200,
      device: refreshedDevice,
      activeLink,
      activeAuthorization
    };
  });
}

export async function deactivateDeviceForRoleChangeAtomic(
  store: DeviceTransactionStore,
  authenticatedUid: string,
  deviceId: string,
  now: Date = new Date()
): Promise<DeviceSessionOutcome> {
  const cleanId = String(deviceId || '').trim();
  if (!cleanId) {
    return { ok: false, statusCode: 400, code: 'MISSING_DEVICE_ID', reason: 'Falta deviceId.' };
  }

  return store.runTransaction(async (ctx) => {
    const device = await ctx.getDevice(cleanId);
    if (!device) {
      return {
        ok: false,
        statusCode: 404,
        code: 'DEVICE_NOT_FOUND',
        reason: 'Dispositivo técnico no encontrado.'
      };
    }

    if (device.authUid !== authenticatedUid) {
      return {
        ok: false,
        statusCode: 403,
        code: 'AUTH_UID_MISMATCH',
        reason: 'Solo el dispositivo propietario puede desactivar su identidad actual.'
      };
    }

    const nowIso = now.toISOString();
    const patch: Partial<DeviceRecord> = {
      status: 'revoked',
      revokedAt: nowIso,
      revokedReason: 'controlled_role_change',
      updatedAt: nowIso
    };
    ctx.updateDevice(cleanId, patch);

    return {
      ok: true,
      statusCode: 200,
      device: { ...device, ...patch }
    };
  });
}

export async function bindDeviceSubscriptionAtomic(
  store: DeviceTransactionStore,
  authenticatedUid: string,
  deviceId: string,
  subscriptionUid: string,
  now: Date = new Date()
): Promise<DeviceSessionOutcome> {
  const cleanId = String(deviceId || '').trim();
  const cleanSubUid = String(subscriptionUid || '').trim();
  if (!cleanId || !cleanSubUid) {
    return {
      ok: false,
      statusCode: 400,
      code: 'MISSING_PARAMS',
      reason: 'Falta deviceId o suscripción válida.'
    };
  }

  return store.runTransaction(async (ctx) => {
    const device = await ctx.getDevice(cleanId);
    if (!device) {
      return {
        ok: false,
        statusCode: 404,
        code: 'DEVICE_NOT_FOUND',
        reason: 'Dispositivo técnico no encontrado.'
      };
    }

    if (device.authUid !== authenticatedUid) {
      return {
        ok: false,
        statusCode: 403,
        code: 'AUTH_UID_MISMATCH',
        reason: 'Solo el dispositivo propietario puede asociar su suscripción.'
      };
    }

    const activeLink = device.activeLinkId ? await ctx.getLink(device.activeLinkId) : null;
    const activeAuth = device.activeLinkId ? await ctx.getAuthorizationByLink(device.activeLinkId) : null;
    const peerDevice =
      device.pairedPeerDeviceId && device.pairedPeerDeviceId !== cleanId
        ? await ctx.getDevice(device.pairedPeerDeviceId)
        : null;

    const nowIso = now.toISOString();
    const devicePatch: Partial<DeviceRecord> = {
      subscriptionUid: cleanSubUid,
      updatedAt: nowIso
    };
    ctx.updateDevice(cleanId, devicePatch);

    if (peerDevice && peerDevice.status !== 'revoked') {
      ctx.updateDevice(peerDevice.deviceId, {
        subscriptionUid: cleanSubUid,
        updatedAt: nowIso
      });
    }

    if (activeLink && activeLink.status === 'active') {
      ctx.updateLink?.(activeLink.linkId, {
        subscriptionUid: cleanSubUid
      });
    }
    if (activeAuth && activeAuth.status === 'active') {
      ctx.updateAuthorization?.(activeAuth.authorizationId, {
        subscriptionUid: cleanSubUid,
        lastActivityAt: nowIso
      });
    }

    return {
      ok: true,
      statusCode: 200,
      device: { ...device, ...devicePatch },
      activeLink: activeLink ? { ...activeLink, subscriptionUid: cleanSubUid } : null,
      activeAuthorization: activeAuth ? { ...activeAuth, subscriptionUid: cleanSubUid } : null
    };
  });
}

export interface ConfirmPairingInput {
  linkId: string;
  coreDeviceId: string;
  terminalDeviceId: string;
  corePublicKeySpkiBase64?: string;
  terminalPublicKeySpkiBase64?: string;
  sasVerified: boolean;
}

export interface ConfirmPairingOutcome {
  ok: boolean;
  statusCode: number;
  code?: string;
  reason?: string;
  coreDevice?: DeviceRecord;
  terminalDevice?: DeviceRecord;
  link?: DeviceLinkRecord;
  authorization?: AuthorizationRecord;
}

export async function confirmDevicePairingAtomic(
  store: DeviceTransactionStore,
  authenticatedUid: string,
  input: ConfirmPairingInput,
  now: Date = new Date()
): Promise<ConfirmPairingOutcome> {
  if (!authenticatedUid || !authenticatedUid.trim()) {
    return {
      ok: false,
      statusCode: 401,
      code: 'UNAUTHENTICATED',
      reason: 'Token Firebase requerido para confirmar vinculación.'
    };
  }

  const linkId = String(input.linkId || '').trim();
  const coreDeviceId = String(input.coreDeviceId || '').trim();
  const terminalDeviceId = String(input.terminalDeviceId || '').trim();

  if (!linkId || !isValidDeviceIdForRole(coreDeviceId, 'CORE') || !isValidDeviceIdForRole(terminalDeviceId, 'TERMINAL')) {
    return {
      ok: false,
      statusCode: 400,
      code: 'INVALID_PAIRING_PARAMS',
      reason: 'Identificadores técnicos inválidos para vincular CORE y MÓVIL.'
    };
  }

  if (!input.sasVerified) {
    return {
      ok: false,
      statusCode: 400,
      code: 'SAS_NOT_VERIFIED',
      reason: 'La confirmación explícita del código SAS de 6 dígitos es obligatoria antes de vincular.'
    };
  }

  const nowIso = now.toISOString();

  return store.runTransaction(async (ctx) => {
    const core = await ctx.getDevice(coreDeviceId);
    if (!core || core.role !== 'CORE') {
      return {
        ok: false,
        statusCode: 404,
        code: 'CORE_NOT_FOUND',
        reason: 'El dispositivo VEL CORE no está registrado en Firestore.'
      };
    }

    if (core.authUid !== authenticatedUid) {
      return {
        ok: false,
        statusCode: 403,
        code: 'AUTH_UID_MISMATCH',
        reason: 'Solo el dispositivo VEL CORE propietario puede autorizar una vinculación.'
      };
    }

    if (core.status === 'revoked') {
      return {
        ok: false,
        statusCode: 403,
        code: 'CORE_REVOKED',
        reason: 'El dispositivo VEL CORE se encuentra revocado.'
      };
    }

    const terminal = await ctx.getDevice(terminalDeviceId);
    if (!terminal || terminal.role !== 'TERMINAL') {
      return {
        ok: false,
        statusCode: 404,
        code: 'TERMINAL_NOT_FOUND',
        reason: 'El dispositivo VEL MÓVIL no está registrado en Firestore.'
      };
    }

    if (terminal.status === 'revoked') {
      return {
        ok: false,
        statusCode: 403,
        code: 'TERMINAL_REVOKED',
        reason: 'Este VEL MÓVIL fue revocado previamente y no puede volver a vincularse.'
      };
    }

    if (input.corePublicKeySpkiBase64 && input.corePublicKeySpkiBase64.trim() !== core.publicKeySpkiBase64) {
      return {
        ok: false,
        statusCode: 409,
        code: 'CORE_KEY_MISMATCH',
        reason: 'La clave pública recibida del CORE no coincide con la registrada en Firestore.'
      };
    }

    if (input.terminalPublicKeySpkiBase64 && input.terminalPublicKeySpkiBase64.trim() !== terminal.publicKeySpkiBase64) {
      return {
        ok: false,
        statusCode: 409,
        code: 'TERMINAL_KEY_MISMATCH',
        reason: 'La clave pública recibida del MÓVIL no coincide con la registrada en Firestore.'
      };
    }

    if (core.activeLinkId === linkId && terminal.activeLinkId === linkId) {
      const existingLink = await ctx.getLink(linkId);
      const existingAuth = await ctx.getAuthorizationByLink(linkId);
      if (
        existingLink &&
        existingLink.status === 'active' &&
        existingLink.coreDeviceId === coreDeviceId &&
        existingLink.terminalDeviceId === terminalDeviceId &&
        existingAuth &&
        existingAuth.status === 'active'
      ) {
        return {
          ok: true,
          statusCode: 200,
          coreDevice: core,
          terminalDevice: terminal,
          link: existingLink,
          authorization: existingAuth
        };
      }
    }

    if (core.activeLinkId && core.activeLinkId !== linkId) {
      const prevLink = await ctx.getLink(core.activeLinkId);
      if (prevLink && prevLink.status === 'active') {
        ctx.updateLink?.(prevLink.linkId, {
          status: 'revoked',
          revokedAt: nowIso,
          revokedByDeviceId: coreDeviceId,
          revocationReason: 'replaced_by_new_pairing'
        });
        ctx.updateAuthorization?.(prevLink.linkId, {
          status: 'revoked',
          revokedAt: nowIso,
          revokedByDeviceId: coreDeviceId,
          lastActivityAt: nowIso
        });
        if (prevLink.terminalDeviceId !== terminalDeviceId) {
          const prevTerm = await ctx.getDevice(prevLink.terminalDeviceId);
          if (prevTerm && prevTerm.activeLinkId === prevLink.linkId) {
            ctx.updateDevice(prevTerm.deviceId, {
              status: 'revoked',
              activeLinkId: null,
              pairedPeerDeviceId: null,
              revokedAt: nowIso,
              revokedReason: 'replaced_by_new_pairing',
              updatedAt: nowIso
            });
          }
        }
      }
    }

    const resolvedSubscriptionUid = core.subscriptionUid || terminal.subscriptionUid || null;

    const linkRecord: DeviceLinkRecord = {
      linkId,
      coreDeviceId,
      terminalDeviceId,
      coreAuthUid: core.authUid,
      terminalAuthUid: terminal.authUid,
      coreFingerprint: core.fingerprint,
      terminalFingerprint: terminal.fingerprint,
      corePublicKeySpkiBase64: core.publicKeySpkiBase64,
      terminalPublicKeySpkiBase64: terminal.publicKeySpkiBase64,
      subscriptionUid: resolvedSubscriptionUid,
      status: 'active',
      sasVerified: true,
      createdAt: nowIso,
      activatedAt: nowIso,
      revokedAt: null,
      revokedByDeviceId: null,
      revocationReason: null
    };

    const authorizationRecord: AuthorizationRecord = {
      authorizationId: linkId,
      linkId,
      coreDeviceId,
      terminalDeviceId,
      coreAuthUid: core.authUid,
      terminalAuthUid: terminal.authUid,
      subscriptionUid: resolvedSubscriptionUid,
      status: 'active',
      permissions: ['RELAY_CONNECT', 'E2EE_SESSION', 'SYNC_STATUS', 'REVOKE_PEER'],
      grantedAt: nowIso,
      revokedAt: null,
      revokedByDeviceId: null,
      lastActivityAt: nowIso
    };

    ctx.createLink?.(linkRecord);
    ctx.createAuthorization?.(authorizationRecord);

    const corePatch: Partial<DeviceRecord> = {
      status: 'paired',
      activeLinkId: linkId,
      pairedPeerDeviceId: terminalDeviceId,
      ...(resolvedSubscriptionUid ? { subscriptionUid: resolvedSubscriptionUid } : {}),
      lastSeenAt: nowIso,
      updatedAt: nowIso
    };
    const terminalPatch: Partial<DeviceRecord> = {
      status: 'paired',
      activeLinkId: linkId,
      pairedPeerDeviceId: coreDeviceId,
      ...(resolvedSubscriptionUid ? { subscriptionUid: resolvedSubscriptionUid } : {}),
      lastSeenAt: nowIso,
      updatedAt: nowIso
    };

    ctx.updateDevice(coreDeviceId, corePatch);
    ctx.updateDevice(terminalDeviceId, terminalPatch);

    return {
      ok: true,
      statusCode: 200,
      coreDevice: { ...core, ...corePatch },
      terminalDevice: { ...terminal, ...terminalPatch },
      link: linkRecord,
      authorization: authorizationRecord
    };
  });
}

export interface RevokeDeviceInput {
  coreDeviceId: string;
  targetTerminalId?: string | null;
  reason?: string;
}

export interface RevokeDeviceOutcome {
  ok: boolean;
  statusCode: number;
  code?: string;
  reason?: string;
  revokedTerminalId?: string | null;
  revokedLinkId?: string | null;
  coreDevice?: DeviceRecord;
}

export async function revokeDeviceAuthorizationAtomic(
  store: DeviceTransactionStore,
  authenticatedUid: string,
  input: RevokeDeviceInput,
  now: Date = new Date()
): Promise<RevokeDeviceOutcome> {
  if (!authenticatedUid || !authenticatedUid.trim()) {
    return { ok: false, statusCode: 401, code: 'UNAUTHENTICATED', reason: 'UID autenticado requerido.' };
  }

  const coreDeviceId = String(input.coreDeviceId || '').trim();
  if (!isValidDeviceIdForRole(coreDeviceId, 'CORE')) {
    return { ok: false, statusCode: 400, code: 'INVALID_CORE_ID', reason: 'Identificador de VEL CORE inválido.' };
  }

  const nowIso = now.toISOString();
  const revReason = (input.reason || 'Revocado por el titular desde VEL CORE').trim().slice(0, 200);

  return store.runTransaction(async (ctx) => {
    const core = await ctx.getDevice(coreDeviceId);
    if (!core || core.role !== 'CORE') {
      return { ok: false, statusCode: 404, code: 'CORE_NOT_FOUND', reason: 'VEL CORE no encontrado.' };
    }

    if (core.authUid !== authenticatedUid) {
      return {
        ok: false,
        statusCode: 403,
        code: 'AUTH_UID_MISMATCH',
        reason: 'Solo el dispositivo VEL CORE titular puede revocar un terminal.'
      };
    }

    const targetTerminalId = String(input.targetTerminalId || core.pairedPeerDeviceId || '').trim();
    const activeLinkId = core.activeLinkId || null;

    const terminal = targetTerminalId ? await ctx.getDevice(targetTerminalId) : null;
    if (terminal && terminal.authUid && terminal.status !== 'revoked') {
      ctx.updateDevice(terminal.deviceId, {
        status: 'revoked',
        activeLinkId: null,
        pairedPeerDeviceId: null,
        revokedAt: nowIso,
        revokedReason: revReason,
        updatedAt: nowIso
      });
    } else if (terminal && (terminal.activeLinkId || terminal.pairedPeerDeviceId)) {
      ctx.updateDevice(terminal.deviceId, {
        status: 'revoked',
        activeLinkId: null,
        pairedPeerDeviceId: null,
        revokedAt: terminal.revokedAt || nowIso,
        revokedReason: terminal.revokedReason || revReason,
        updatedAt: nowIso
      });
    }

    const linkIdToRevoke = activeLinkId || terminal?.activeLinkId || null;
    if (linkIdToRevoke) {
      const existingLink = await ctx.getLink(linkIdToRevoke);
      if (existingLink) {
        ctx.updateLink?.(linkIdToRevoke, {
          status: 'revoked',
          revokedAt: nowIso,
          revokedByDeviceId: coreDeviceId,
          revocationReason: revReason
        });
      }
      const existingAuth = await ctx.getAuthorizationByLink(linkIdToRevoke);
      if (existingAuth) {
        ctx.updateAuthorization?.(linkIdToRevoke, {
          status: 'revoked',
          revokedAt: nowIso,
          revokedByDeviceId: coreDeviceId,
          lastActivityAt: nowIso
        });
      }
    }

    const corePatch: Partial<DeviceRecord> = {
      status: core.status === 'revoked' ? 'revoked' : 'registered',
      activeLinkId: null,
      pairedPeerDeviceId: null,
      updatedAt: nowIso
    };
    ctx.updateDevice(coreDeviceId, corePatch);

    return {
      ok: true,
      statusCode: 200,
      revokedTerminalId: targetTerminalId || null,
      revokedLinkId: linkIdToRevoke,
      coreDevice: { ...core, ...corePatch }
    };
  });
}

export interface PeerCommunicationCheckResult {
  authorized: boolean;
  reasonCode:
    | 'AUTHORIZED'
    | 'DEVICE_NOT_FOUND'
    | 'DEVICE_REVOKED'
    | 'PEER_REVOKED'
    | 'NOT_LINKED'
    | 'LINK_INACTIVE'
    | 'AUTHORIZATION_INACTIVE'
    | 'PEER_MISMATCH';
  device?: DeviceRecord;
  peerDevice?: DeviceRecord;
  link?: DeviceLinkRecord | null;
  authorization?: AuthorizationRecord | null;
}

export async function verifyPeerCommunicationAuthorization(
  store: DeviceTransactionStore,
  deviceId: string,
  peerDeviceId?: string
): Promise<PeerCommunicationCheckResult> {
  return store.runTransaction(async (ctx) => {
    const device = await ctx.getDevice(deviceId);
    if (!device) {
      return { authorized: false, reasonCode: 'DEVICE_NOT_FOUND' };
    }
    if (device.status === 'revoked') {
      return { authorized: false, reasonCode: 'DEVICE_REVOKED', device };
    }

    let link: DeviceLinkRecord | null = null;
    let authorization: AuthorizationRecord | null = null;

    if (device.activeLinkId) {
      link = await ctx.getLink(device.activeLinkId);
      authorization = await ctx.getAuthorizationByLink(device.activeLinkId);
    }

    if (!peerDeviceId) {
      return {
        authorized: true,
        reasonCode: 'AUTHORIZED',
        device,
        link,
        authorization
      };
    }

    const peer = await ctx.getDevice(peerDeviceId);
    if (!peer) {
      return { authorized: false, reasonCode: 'DEVICE_NOT_FOUND', device };
    }
    if (peer.status === 'revoked') {
      return { authorized: false, reasonCode: 'PEER_REVOKED', device, peerDevice: peer };
    }

    if (!device.activeLinkId || !peer.activeLinkId || device.activeLinkId !== peer.activeLinkId) {
      return { authorized: false, reasonCode: 'NOT_LINKED', device, peerDevice: peer, link, authorization };
    }

    if (!link || link.status !== 'active' || !link.sasVerified) {
      return { authorized: false, reasonCode: 'LINK_INACTIVE', device, peerDevice: peer, link, authorization };
    }

    if (!authorization || authorization.status !== 'active') {
      return {
        authorized: false,
        reasonCode: 'AUTHORIZATION_INACTIVE',
        device,
        peerDevice: peer,
        link,
        authorization
      };
    }

    const matchesPair =
      (link.coreDeviceId === device.deviceId && link.terminalDeviceId === peer.deviceId) ||
      (link.terminalDeviceId === device.deviceId && link.coreDeviceId === peer.deviceId);

    if (!matchesPair) {
      return { authorized: false, reasonCode: 'PEER_MISMATCH', device, peerDevice: peer, link, authorization };
    }

    return {
      authorized: true,
      reasonCode: 'AUTHORIZED',
      device,
      peerDevice: peer,
      link,
      authorization
    };
  });
}

export interface EnsureSubscriberOutcome {
  ok: boolean;
  statusCode: number;
  created?: boolean;
  alreadyExisted?: boolean;
  code?: string;
  reason?: string;
  subscriber?: SuscriptorAdminRecord;
}

export async function ensureSubscriberAccountAtomic(
  store: DeviceTransactionStore,
  input: { uid: string; email: string },
  now: Date = new Date()
): Promise<EnsureSubscriberOutcome> {
  const cleanUid = String(input.uid || '').trim();
  const cleanEmail = String(input.email || '').trim().toLowerCase();

  if (!cleanUid) {
    return {
      ok: false,
      statusCode: 401,
      code: 'UNAUTHENTICATED',
      reason: 'UID de Firebase requerido.'
    };
  }
  if (!cleanEmail || !cleanEmail.includes('@')) {
    return {
      ok: false,
      statusCode: 400,
      code: 'EMAIL_REQUIRED',
      reason: 'La cuenta comercial requiere un correo electrónico verificado en Firebase.'
    };
  }

  const nowIso = now.toISOString();

  return store.runTransaction(async (ctx) => {
    const existingByUid = ctx.getSubscriberInTx
      ? await ctx.getSubscriberInTx(cleanUid)
      : store.getSubscriber
      ? await store.getSubscriber(cleanUid)
      : null;

    if (existingByUid) {
      if (existingByUid.estado === 'cancelado' && existingByUid.bajaSolicitadaEl) {
        return {
          ok: false,
          statusCode: 403,
          code: 'ACCOUNT_DEACTIVATED',
          reason: 'Esta cuenta fue dada de baja previamente.',
          subscriber: existingByUid
        };
      }
      return {
        ok: true,
        statusCode: 200,
        created: false,
        alreadyExisted: true,
        subscriber: existingByUid
      };
    }

    if (ctx.findSubscribersByEmailInTx) {
      const sameEmailDocs = await ctx.findSubscribersByEmailInTx(cleanEmail);
      const conflict = sameEmailDocs.find(
        (doc) =>
          doc.uid !== cleanUid &&
          doc.estado !== 'cancelado' &&
          !doc.bajaSolicitadaEl
      );
      if (conflict) {
        return {
          ok: false,
          statusCode: 409,
          code: 'DUPLICATE_ACCOUNT_EMAIL',
          reason:
            'Ya existe una cuenta VEL registrada con este correo electrónico bajo otra sesión. Utiliza tu cuenta original para evitar duplicados.'
        };
      }
    }

    const newRecord: SuscriptorAdminRecord = {
      uid: cleanUid,
      email: cleanEmail,
      estado: 'pendiente_pago',
      plan: null,
      fechaAlta: nowIso,
      venceEl: null,
      modalidadComercial: 'manual_30d',
      altaCompletadaEl: nowIso,
      ultimaActualizacion: nowIso
    };

    if (ctx.setSubscriberInTx) {
      ctx.setSubscriberInTx(cleanUid, newRecord, false);
    } else if (store.updateSubscriberStatus) {
      await store.updateSubscriberStatus(cleanUid, newRecord);
    }

    return {
      ok: true,
      statusCode: 201,
      created: true,
      alreadyExisted: false,
      subscriber: newRecord
    };
  });
}

export function toAccountDeviceSummary(device: DeviceRecord): AccountDeviceSummary {
  return {
    deviceId: device.deviceId,
    role: device.role,
    status: device.status,
    activeLinkId: device.activeLinkId,
    pairedPeerDeviceId: device.pairedPeerDeviceId,
    lastSeenAt: device.lastSeenAt
  };
}

export interface DeactivateAccountOutcome {
  ok: boolean;
  statusCode: number;
  code?: string;
  reason?: string;
  subscriber?: SuscriptorAdminRecord | null;
  revokedDeviceIds: string[];
  revokedLinkIds: string[];
}

export async function deactivateAccountAndDevicesAtomic(
  store: DeviceTransactionStore,
  subscriptionUid: string,
  reason: string = 'account_deactivated',
  now: Date = new Date()
): Promise<DeactivateAccountOutcome> {
  const cleanUid = String(subscriptionUid || '').trim();
  if (!cleanUid) {
    return {
      ok: false,
      statusCode: 401,
      code: 'UNAUTHENTICATED',
      reason: 'UID autenticado requerido.',
      revokedDeviceIds: [],
      revokedLinkIds: []
    };
  }

  const nowIso = now.toISOString();
  const cleanReason = String(reason || 'account_deactivated').trim().slice(0, 200);

  return store.runTransaction(async (ctx) => {
    const existingSub = ctx.getSubscriberInTx
      ? await ctx.getSubscriberInTx(cleanUid)
      : store.getSubscriber
      ? await store.getSubscriber(cleanUid)
      : null;

    const linkedDevices = ctx.findDevicesBySubscriptionUidInTx
      ? await ctx.findDevicesBySubscriptionUidInTx(cleanUid)
      : store.listDevicesBySubscriptionUid
      ? await store.listDevicesBySubscriptionUid(cleanUid)
      : [];

    const revokedDeviceIds: string[] = [];
    const linkIdsToRevoke = new Set<string>();

    for (const dev of linkedDevices) {
      if (dev.activeLinkId) {
        linkIdsToRevoke.add(dev.activeLinkId);
      }
      if (dev.status !== 'revoked' || dev.activeLinkId || dev.pairedPeerDeviceId) {
        ctx.updateDevice(dev.deviceId, {
          status: 'revoked',
          activeLinkId: null,
          pairedPeerDeviceId: null,
          revokedAt: dev.revokedAt || nowIso,
          revokedReason: dev.revokedReason || cleanReason,
          updatedAt: nowIso
        });
      }
      revokedDeviceIds.push(dev.deviceId);
    }

    const revokedLinkIds: string[] = [];
    for (const linkId of linkIdsToRevoke) {
      const link = await ctx.getLink(linkId);
      if (link && link.status !== 'revoked') {
        ctx.updateLink?.(linkId, {
          status: 'revoked',
          revokedAt: nowIso,
          revokedByDeviceId: cleanUid,
          revocationReason: cleanReason
        });
      }
      if (link) {
        for (const peerId of [link.coreDeviceId, link.terminalDeviceId]) {
          if (peerId && !revokedDeviceIds.includes(peerId)) {
            const peer = await ctx.getDevice(peerId);
            if (peer && (peer.status !== 'revoked' || peer.activeLinkId === linkId)) {
              ctx.updateDevice(peerId, {
                status: 'revoked',
                activeLinkId: null,
                pairedPeerDeviceId: null,
                revokedAt: peer.revokedAt || nowIso,
                revokedReason: peer.revokedReason || cleanReason,
                updatedAt: nowIso
              });
              revokedDeviceIds.push(peerId);
            }
          }
        }
      }

      const auth = await ctx.getAuthorizationByLink(linkId);
      if (auth && auth.status !== 'revoked') {
        ctx.updateAuthorization?.(linkId, {
          status: 'revoked',
          revokedAt: nowIso,
          revokedByDeviceId: cleanUid,
          lastActivityAt: nowIso
        });
      }
      revokedLinkIds.push(linkId);
    }

    let updatedSubscriber: SuscriptorAdminRecord | null = existingSub;
    if (existingSub) {
      const patch: Partial<SuscriptorAdminRecord> = {
        estado: 'cancelado',
        venceEl: null,
        fechaProximoPago: null,
        mpPreferenceId: null,
        canceladoEl: existingSub.canceladoEl || nowIso,
        bajaSolicitadaEl: nowIso,
        ultimaActualizacion: nowIso
      };
      if (ctx.setSubscriberInTx) {
        ctx.setSubscriberInTx(cleanUid, patch, true);
      } else if (store.updateSubscriberStatus) {
        await store.updateSubscriberStatus(cleanUid, patch);
      }
      updatedSubscriber = { ...existingSub, ...patch };
    }

    return {
      ok: true,
      statusCode: 200,
      subscriber: updatedSubscriber,
      revokedDeviceIds,
      revokedLinkIds
    };
  });
}

export function createFirestoreRestDeviceStore(client: FirestoreRestClient): DeviceTransactionStore {
  return {
    async runTransaction<T>(fn: (ctx: DeviceTransactionContext) => Promise<T>): Promise<T> {
      return client.runTransaction(async (tx) => {
        const ctx: DeviceTransactionContext = {
          async getDevice(deviceId: string): Promise<DeviceRecord | null> {
            return tx.getDocument<DeviceRecord>(`dispositivos/${deviceId}`);
          },
          createDevice(record: DeviceRecord): void {
            tx.createDocument(`dispositivos/${record.deviceId}`, record);
          },
          updateDevice(deviceId: string, patch: Partial<DeviceRecord>): void {
            tx.updateDocument(`dispositivos/${deviceId}`, patch);
          },
          async getLink(linkId: string): Promise<DeviceLinkRecord | null> {
            return tx.getDocument<DeviceLinkRecord>(`vinculaciones/${linkId}`);
          },
          createLink(record: DeviceLinkRecord): void {
            tx.createDocument(`vinculaciones/${record.linkId}`, record);
          },
          updateLink(linkId: string, patch: Partial<DeviceLinkRecord>): void {
            tx.updateDocument(`vinculaciones/${linkId}`, patch);
          },
          async getAuthorizationByLink(linkId: string): Promise<AuthorizationRecord | null> {
            return tx.getDocument<AuthorizationRecord>(`autorizaciones/${linkId}`);
          },
          createAuthorization(record: AuthorizationRecord): void {
            tx.createDocument(`autorizaciones/${record.authorizationId}`, record);
          },
          updateAuthorization(authorizationId: string, patch: Partial<AuthorizationRecord>): void {
            tx.updateDocument(`autorizaciones/${authorizationId}`, patch);
          },
          async getSubscriberInTx(uid: string): Promise<SuscriptorAdminRecord | null> {
            return tx.getDocument<SuscriptorAdminRecord>(`suscriptores/${uid}`);
          },
          async findSubscribersByEmailInTx(normalizedEmail: string): Promise<SuscriptorAdminRecord[]> {
            const rows = await tx.runQuery<SuscriptorAdminRecord>('', {
              from: [{ collectionId: 'suscriptores' }],
              where: {
                fieldFilter: {
                  field: { fieldPath: 'email' },
                  op: 'EQUAL',
                  value: { stringValue: normalizedEmail }
                }
              }
            });
            return rows.map((r) => r.data);
          },
          setSubscriberInTx(
            uid: string,
            record: Partial<SuscriptorAdminRecord>,
            merge: boolean = true
          ): void {
            tx.setDocument(`suscriptores/${uid}`, record as Record<string, any>, merge);
          },
          async findDevicesBySubscriptionUidInTx(subscriptionUid: string): Promise<DeviceRecord[]> {
            const rows = await tx.runQuery<DeviceRecord>('', {
              from: [{ collectionId: 'dispositivos' }],
              where: {
                fieldFilter: {
                  field: { fieldPath: 'subscriptionUid' },
                  op: 'EQUAL',
                  value: { stringValue: subscriptionUid }
                }
              }
            });
            return rows.map((r) => r.data);
          }
        };

        return fn(ctx);
      });
    },
    async getSubscriber(uid: string): Promise<SuscriptorAdminRecord | null> {
      return client.getDocument<SuscriptorAdminRecord>(`suscriptores/${uid}`);
    },
    async updateSubscriberStatus(uid: string, patch: Partial<SuscriptorAdminRecord>): Promise<void> {
      await client.updateDocument(`suscriptores/${uid}`, patch);
    },
    async listDevicesBySubscriptionUid(subscriptionUid: string): Promise<DeviceRecord[]> {
      const rows = await client.runQuery<DeviceRecord>('', {
        from: [{ collectionId: 'dispositivos' }],
        where: {
          fieldFilter: {
            field: { fieldPath: 'subscriptionUid' },
            op: 'EQUAL',
            value: { stringValue: subscriptionUid }
          }
        }
      });
      return rows.map((r) => r.data);
    },
    async hasAcceptedContract(uid: string, version: string): Promise<boolean> {
      const doc = await client.getDocument<Record<string, any>>(
        `suscriptores/${uid}/historial_contratos/${version}`
      );
      return Boolean(doc && doc.uid === uid && doc.versionContrato === version && doc.aceptado === true);
    }
  };
}
