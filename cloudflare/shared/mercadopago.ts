import type { CloudflareEnv } from './types';
import {
  hexToBytes,
  hmacSha256Bytes,
  timingSafeEqualBytes
} from './webCrypto';

const MP_BASE_URL = 'https://api.mercadopago.com';

export function getMpAccessToken(env: CloudflareEnv = {}): string {
  const token = env.MP_ACCESS_TOKEN || env.MERCADOPAGO_ACCESS_TOKEN || '';
  if (!token) {
    console.warn('Advertencia: MP_ACCESS_TOKEN pendiente de configuración en variables de entorno.');
  }
  return token;
}

export function isMpProduction(env: CloudflareEnv = {}): boolean {
  return getMpAccessToken(env).startsWith('APP_USR-');
}

export interface CreatePreferenceParams {
  payerEmail?: string;
  externalReference: string;
  title: string;
  amount: number;
  currencyId: string;
  backUrls: {
    success: string;
    pending: string;
    failure: string;
  };
  notificationUrl: string;
}

export interface PreferenceResponse {
  id: string;
  init_point: string;
  sandbox_init_point?: string;
  external_reference?: string;
}

export async function createPaymentPreference(
  params: CreatePreferenceParams,
  env: CloudflareEnv = {},
  fetchFn: typeof fetch = fetch
): Promise<{ success: boolean; pendingConfig?: boolean; data?: PreferenceResponse; error?: string }> {
  const accessToken = getMpAccessToken(env);
  if (!accessToken) {
    return {
      success: false,
      pendingConfig: true,
      error: 'MP_ACCESS_TOKEN pendiente de configuración en Cloudflare.'
    };
  }

  const payload: Record<string, any> = {
    items: [
      {
        id: 'vel-suscripcion-mensual',
        title: params.title,
        description: 'Renovación manual de acceso VEL por 30 días',
        quantity: 1,
        currency_id: params.currencyId.toUpperCase(),
        unit_price: Number(params.amount)
      }
    ],
    external_reference: params.externalReference,
    back_urls: params.backUrls,
    notification_url: params.notificationUrl,
    statement_descriptor: 'VEL SEGURIDAD',
    metadata: {
      circuito: 'checkout_pro',
      firebase_uid: params.externalReference,
      concepto: params.title,
      monto_vigente: Number(params.amount),
      moneda_vigente: params.currencyId.toUpperCase()
    }
  };

  if (params.payerEmail && params.payerEmail.trim()) {
    payload.payer = {
      email: params.payerEmail.trim()
    };
  }

  if (params.backUrls.success.startsWith('https://') || params.backUrls.success.startsWith('http://')) {
    payload.auto_return = 'approved';
  }

  try {
    const response = await fetchFn(`${MP_BASE_URL}/checkout/preferences`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify(payload)
    });

    const resJson = (await response.json()) as Record<string, any>;

    if (!response.ok) {
      const errMsg = resJson.message || resJson.error || JSON.stringify(resJson);
      return {
        success: false,
        error: `Error de Mercado Pago (${response.status}): ${errMsg}`
      };
    }

    if (!resJson?.id || typeof resJson?.init_point !== 'string' || !resJson.init_point.startsWith('https://')) {
      return {
        success: false,
        error: 'Mercado Pago no devolvió una preferencia válida con init_point seguro.'
      };
    }

    return {
      success: true,
      data: resJson as PreferenceResponse
    };
  } catch (err: any) {
    return {
      success: false,
      error: `Error de red al conectar con Mercado Pago: ${err?.message || err}`
    };
  }
}

export interface CreatePreapprovalParams {
  payerEmail: string;
  externalReference: string;
  reason: string;
  amount: number;
  currencyId: string;
  backUrl: string;
}

export interface PreapprovalResponse {
  id: string;
  init_point: string;
  status: string;
  external_reference?: string;
  payer_email?: string;
  reason?: string;
  auto_recurring?: {
    frequency: number;
    frequency_type: string;
    transaction_amount: number;
    currency_id: string;
  };
}

export async function getPreapproval(
  preapprovalId: string,
  env: CloudflareEnv = {},
  fetchFn: typeof fetch = fetch
): Promise<{ success: boolean; data?: any; error?: string }> {
  const accessToken = getMpAccessToken(env);
  if (!accessToken) {
    return { success: false, error: 'MP_ACCESS_TOKEN no configurado.' };
  }

  try {
    const response = await fetchFn(`${MP_BASE_URL}/preapproval/${encodeURIComponent(preapprovalId)}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const resJson = (await response.json()) as Record<string, any>;
    if (!response.ok) {
      return {
        success: false,
        error: `Mercado Pago respondió error ${response.status}: ${resJson.message || ''}`
      };
    }

    return { success: true, data: resJson };
  } catch (err: any) {
    return { success: false, error: err?.message || 'Error de conexión con Mercado Pago.' };
  }
}

export async function cancelPreapproval(
  preapprovalId: string,
  env: CloudflareEnv = {},
  fetchFn: typeof fetch = fetch
): Promise<{ success: boolean; error?: string }> {
  const accessToken = getMpAccessToken(env);
  if (!accessToken) {
    return { success: false, error: 'MP_ACCESS_TOKEN no configurado.' };
  }

  try {
    const response = await fetchFn(`${MP_BASE_URL}/preapproval/${encodeURIComponent(preapprovalId)}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`
      },
      body: JSON.stringify({ status: 'cancelled' })
    });

    if (!response.ok) {
      const resJson = (await response.json().catch(() => ({}))) as Record<string, any>;
      return {
        success: false,
        error: `Error cancelando suscripción en Mercado Pago: ${resJson.message || response.status}`
      };
    }

    return { success: true };
  } catch (err: any) {
    return { success: false, error: err?.message || 'Error de conexión.' };
  }
}

export async function getPayment(
  paymentId: string,
  env: CloudflareEnv = {},
  fetchFn: typeof fetch = fetch
): Promise<{ success: boolean; pendingConfig?: boolean; data?: any; error?: string }> {
  const accessToken = getMpAccessToken(env);
  if (!accessToken) {
    return {
      success: false,
      pendingConfig: true,
      error: 'MP_ACCESS_TOKEN pendiente de configuración en Cloudflare.'
    };
  }

  try {
    const response = await fetchFn(`${MP_BASE_URL}/v1/payments/${encodeURIComponent(paymentId)}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    const resJson = (await response.json()) as Record<string, any>;
    if (!response.ok) {
      return {
        success: false,
        error: `Error al consultar pago ${paymentId}: ${resJson.message || response.status}`
      };
    }

    return { success: true, data: resJson };
  } catch (err: any) {
    return { success: false, error: err?.message || 'Error de red.' };
  }
}

export const DEFAULT_WEBHOOK_MAX_AGE_MS = 48 * 60 * 60 * 1000;
export const DEFAULT_WEBHOOK_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

export interface VerifyWebhookSignatureOptions {
  nowMs?: number;
  maxAgeMs?: number;
  maxFutureSkewMs?: number;
}

/**
 * Valida la firma criptográfica x-signature enviada por Mercado Pago usando Web Crypto HMAC-SHA256
 * y comparación en tiempo constante.
 */
export async function verifyMpWebhookSignature(
  xSignatureHeader: string | undefined,
  xRequestIdHeader: string | undefined,
  dataId: string | undefined,
  env: CloudflareEnv = {},
  options: VerifyWebhookSignatureOptions = {}
): Promise<{ isValid: boolean; pendingConfig?: boolean; reason?: string }> {
  const webhookSecret = env.MP_WEBHOOK_SECRET;

  if (!webhookSecret || !webhookSecret.trim()) {
    return {
      isValid: false,
      pendingConfig: true,
      reason: 'MP_WEBHOOK_SECRET pendiente de configuración en Cloudflare.'
    };
  }

  if (!xSignatureHeader) {
    return { isValid: false, reason: 'Falta cabecera x-signature en la solicitud.' };
  }

  const parts = xSignatureHeader.split(',').reduce((acc, part) => {
    const eqIdx = part.indexOf('=');
    if (eqIdx > 0) {
      const key = part.slice(0, eqIdx).trim();
      const val = part.slice(eqIdx + 1).trim();
      if (key && val) acc[key] = val;
    }
    return acc;
  }, {} as Record<string, string>);

  const ts = parts['ts'];
  const v1 = parts['v1'];

  if (!ts || !v1) {
    return { isValid: false, reason: 'Formato inválido de x-signature (falta ts o v1).' };
  }

  let manifest = '';
  if (dataId) {
    manifest += `id:${String(dataId).toLowerCase()};`;
  }
  if (xRequestIdHeader) {
    manifest += `request-id:${xRequestIdHeader};`;
  }
  manifest += `ts:${ts};`;

  const computedBytes = await hmacSha256Bytes(webhookSecret, manifest);

  let providedBytes: Uint8Array;
  try {
    if (!/^[0-9a-fA-F]+$/.test(v1)) {
      return { isValid: false, reason: 'Hash v1 con caracteres no hexadecimales.' };
    }
    providedBytes = hexToBytes(v1);
  } catch {
    return { isValid: false, reason: 'Formato de hash v1 inválido.' };
  }

  if (!timingSafeEqualBytes(computedBytes, providedBytes)) {
    return {
      isValid: false,
      reason: 'Firma criptográfica x-signature no coincide con el secret configurado.'
    };
  }

  if (!/^\d+$/.test(ts)) {
    return { isValid: false, reason: 'Timestamp ts inválido en x-signature.' };
  }

  const tsNum = Number(ts);
  if (!Number.isSafeInteger(tsNum) || tsNum <= 0) {
    return { isValid: false, reason: 'Timestamp ts fuera de rango numérico válido.' };
  }

  const tsMs = tsNum >= 1e12 ? tsNum : tsNum * 1000;
  const nowMs = options.nowMs ?? Date.now();
  const envMaxAgeSec = Number(env.MP_WEBHOOK_MAX_AGE_SECONDS);
  const maxAgeMs =
    options.maxAgeMs ??
    (Number.isFinite(envMaxAgeSec) && envMaxAgeSec > 0
      ? envMaxAgeSec * 1000
      : DEFAULT_WEBHOOK_MAX_AGE_MS);
  const maxFutureSkewMs = options.maxFutureSkewMs ?? DEFAULT_WEBHOOK_MAX_FUTURE_SKEW_MS;

  if (tsMs - nowMs > maxFutureSkewMs) {
    return {
      isValid: false,
      reason: 'Timestamp ts de x-signature supera el desfase futuro permitido.'
    };
  }

  if (nowMs - tsMs > maxAgeMs) {
    return {
      isValid: false,
      reason: 'Firma de webhook expirada: timestamp ts supera la ventana de tolerancia.'
    };
  }

  return { isValid: true };
}
