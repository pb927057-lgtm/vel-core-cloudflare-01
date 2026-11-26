import { inspectFirebaseAdminConfig } from './firebaseRest';
import type { CloudflareEnv, SubscriberStatus, SuscriptorAdminRecord } from './types';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToUtf8,
  hmacSha256Bytes,
  sha256Hex,
  timingSafeEqualBytes,
  utf8ToBytes
} from './webCrypto';

export const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_SUBSCRIPTION_PASS_TTL_MS = 48 * 60 * 60 * 1000;

export interface SubscriberAccessEvaluation {
  active: boolean;
  estado: SubscriberStatus | 'no_registrado';
  venceEl: string | null;
  reason: string;
  shouldPersistEstado?: 'vencido' | 'suspendido';
}

export function evaluateSubscriberAccess(
  subData: SuscriptorAdminRecord | null | undefined,
  now: Date = new Date()
): SubscriberAccessEvaluation {
  if (!subData) {
    return {
      active: false,
      estado: 'no_registrado',
      venceEl: null,
      reason:
        'No se encontró suscripción activa para esta cuenta. Contrata tu mes en Blogger con Mercado Pago.'
    };
  }

  const nowMs = now.getTime();
  const estado = subData.estado || 'pendiente_pago';

  if (estado === 'activo') {
    const venceMs = subData.venceEl ? Date.parse(subData.venceEl) : NaN;
    if (!Number.isNaN(venceMs) && venceMs > nowMs) {
      return {
        active: true,
        estado: 'activo',
        venceEl: subData.venceEl || null,
        reason: 'Suscripción mensual vigente.'
      };
    }

    const elapsedSinceExpiry = Number.isNaN(venceMs) ? GRACE_PERIOD_MS : nowMs - venceMs;
    const nextEstado: 'vencido' | 'suspendido' =
      elapsedSinceExpiry >= GRACE_PERIOD_MS ? 'suspendido' : 'vencido';

    return {
      active: false,
      estado: nextEstado,
      venceEl: subData.venceEl || null,
      shouldPersistEstado: nextEstado,
      reason:
        'Tu período mensual de 30 días venció. Tus copias locales siguen intactas; renueva en Blogger con Mercado Pago para reactivar el envío.'
    };
  }

  if (estado === 'en_gracia') {
    const graceStartMs = subData.fechaInicioGracia
      ? Date.parse(subData.fechaInicioGracia)
      : subData.venceEl
      ? Date.parse(subData.venceEl)
      : NaN;

    if (!Number.isNaN(graceStartMs) && nowMs - graceStartMs < GRACE_PERIOD_MS) {
      return {
        active: true,
        estado: 'en_gracia',
        venceEl: subData.venceEl || null,
        reason: 'Suscripción dentro del período de gracia de 7 días.'
      };
    }

    return {
      active: false,
      estado: 'suspendido',
      venceEl: subData.venceEl || null,
      shouldPersistEstado: 'suspendido',
      reason:
        'El período de gracia de 7 días ha finalizado. Renueva en Blogger con Mercado Pago para reactivar el envío entre tus teléfonos.'
    };
  }

  return {
    active: false,
    estado,
    venceEl: subData.venceEl || null,
    reason:
      estado === 'pendiente_pago'
        ? 'Tu suscripción está pendiente de pago en Mercado Pago.'
        : 'Tu suscripción mensual no está activa. Renueva 30 días en Blogger con Mercado Pago para reactivar el envío.'
  };
}

export async function resolveSubscriptionSigningSecret(
  env: CloudflareEnv = {}
): Promise<string | null> {
  const explicit = String(env.VEL_ACTIVATION_SECRET || '').trim();
  if (explicit.length >= 16) {
    return sha256Hex(`vel-pass|${explicit}`);
  }

  const mpSecret = String(env.MP_WEBHOOK_SECRET || '').trim();
  if (mpSecret.length >= 12) {
    return sha256Hex(`vel-pass|${mpSecret}`);
  }

  const fbDiag = inspectFirebaseAdminConfig(env);
  if (fbDiag.ok && fbDiag.credentials?.privateKey) {
    return sha256Hex(
      `vel-pass|${fbDiag.credentials.clientEmail}|${fbDiag.credentials.privateKey}`
    );
  }

  return null;
}

export async function createSubscriptionPass(
  uid: string,
  now: Date = new Date(),
  ttlMs: number = DEFAULT_SUBSCRIPTION_PASS_TTL_MS,
  secretOverride?: string,
  env: CloudflareEnv = {}
): Promise<string | null> {
  const cleanUid = String(uid || '').trim();
  if (!cleanUid) return null;

  const secret = secretOverride || (await resolveSubscriptionSigningSecret(env));
  if (!secret) return null;

  const payloadObj = {
    u: cleanUid,
    exp: now.getTime() + ttlMs
  };
  const payloadB64 = bytesToBase64Url(utf8ToBytes(JSON.stringify(payloadObj)));
  const sigBytes = await hmacSha256Bytes(secret, payloadB64);
  const sigB64 = bytesToBase64Url(sigBytes);
  return `${payloadB64}.${sigB64}`;
}

export async function verifySubscriptionPass(
  token: string,
  now: Date = new Date(),
  secretOverride?: string,
  env: CloudflareEnv = {}
): Promise<{ valid: boolean; uid?: string; reason?: string }> {
  const raw = String(token || '').trim();
  const dotIdx = raw.indexOf('.');
  if (!raw || dotIdx <= 0) {
    return { valid: false, reason: 'Formato de pase de activación inválido.' };
  }

  const secret = secretOverride || (await resolveSubscriptionSigningSecret(env));
  if (!secret) {
    return {
      valid: false,
      reason: 'No hay secreto de servidor disponible para validar el pase de suscripción.'
    };
  }

  const payloadB64 = raw.slice(0, dotIdx);
  const sigB64 = raw.slice(dotIdx + 1);
  if (!payloadB64 || !sigB64) {
    return { valid: false, reason: 'Pase de activación incompleto.' };
  }

  let providedBytes: Uint8Array;
  try {
    providedBytes = base64UrlToBytes(sigB64);
  } catch {
    return { valid: false, reason: 'Firma de pase de activación mal formada.' };
  }

  const expectedBytes = await hmacSha256Bytes(secret, payloadB64);
  if (!timingSafeEqualBytes(providedBytes, expectedBytes)) {
    return { valid: false, reason: 'Firma de pase de activación inválida.' };
  }

  try {
    const parsed = JSON.parse(bytesToUtf8(base64UrlToBytes(payloadB64)));
    const uid = typeof parsed?.u === 'string' ? parsed.u.trim() : '';
    const exp = Number(parsed?.exp || 0);
    if (!uid || !Number.isFinite(exp)) {
      return { valid: false, reason: 'Contenido del pase de activación inválido.' };
    }
    if (now.getTime() > exp) {
      return {
        valid: false,
        reason: 'El pase de activación expiró. Vuelve a abrir VEL desde Blogger.'
      };
    }
    return { valid: true, uid };
  } catch {
    return { valid: false, reason: 'No se pudo decodificar el pase de activación.' };
  }
}
