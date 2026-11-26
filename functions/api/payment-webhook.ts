import {
  createFirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials
} from '../../cloudflare/shared/firebaseRest';
import { getQueryParams, jsonResponse, parseJsonBody } from '../../cloudflare/shared/http';
import {
  getPayment,
  verifyMpWebhookSignature,
  VerifyWebhookSignatureOptions
} from '../../cloudflare/shared/mercadopago';
import {
  createFirestoreRestPaymentStore,
  PaymentTransactionStore,
  processVerifiedPaymentAtomic,
  VerifiedMercadoPagoPayment
} from '../../cloudflare/shared/paymentRenewalService';
import { getCurrentPricing, PricingUnavailableError } from '../../cloudflare/shared/pricingService';
import type { CloudflareEnv, CloudflarePagesContext, PricingConfig } from '../../cloudflare/shared/types';

export interface PaymentWebhookDeps {
  verifySignature?: (
    xSignatureHeader: string | undefined,
    xRequestIdHeader: string | undefined,
    dataId: string | undefined,
    options?: VerifyWebhookSignatureOptions,
    env?: CloudflareEnv
  ) => Promise<{ isValid: boolean; pendingConfig?: boolean; reason?: string }> | {
    isValid: boolean;
    pendingConfig?: boolean;
    reason?: string;
  };
  fetchPayment?: (
    paymentId: string,
    env?: CloudflareEnv
  ) => Promise<{ success: boolean; pendingConfig?: boolean; data?: any; error?: string }>;
  getPricing?: (env?: CloudflareEnv) => Promise<PricingConfig>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getPaymentStore?: (env: CloudflareEnv) => PaymentTransactionStore;
  nowProvider?: () => Date;
}

export async function handlePaymentWebhook(
  context: CloudflarePagesContext,
  deps: PaymentWebhookDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;

  if (request.method !== 'POST') {
    return jsonResponse(405, {
      error: 'Método no permitido. Utilizar POST para webhooks.'
    });
  }

  const parsed = await parseJsonBody(request);
  const body = parsed.ok ? parsed.data : {};
  const queryParams = getQueryParams(request);

  const dataId = String(
    queryParams['data.id'] || body?.data?.id || queryParams.id || body?.id || ''
  ).trim();
  const notificationType = String(
    body?.type || queryParams?.type || body?.topic || queryParams?.topic || ''
  )
    .toLowerCase()
    .trim();

  if (notificationType !== 'payment') {
    return jsonResponse(200, {
      received: true,
      ignored: true,
      grantedDays: 0,
      reason: `Notificación de tipo '${notificationType || 'desconocido'}' ignorada (solo se procesan notificaciones 'payment').`
    });
  }

  if (!dataId) {
    return jsonResponse(400, {
      error: 'Notificación payment sin identificador de pago (data.id).'
    });
  }

  const now = deps.nowProvider ? deps.nowProvider() : new Date();
  const xSignature = request.headers.get('x-signature') ?? undefined;
  const xRequestId = request.headers.get('x-request-id') ?? undefined;

  const verifySigFn =
    deps.verifySignature ||
    ((sig?: string, reqId?: string, id?: string, opts?: VerifyWebhookSignatureOptions) =>
      verifyMpWebhookSignature(sig, reqId, id, env, opts));

  const sigCheck = await verifySigFn(xSignature, xRequestId, dataId, { nowMs: now.getTime() }, env);

  if (!sigCheck.isValid) {
    if (sigCheck.pendingConfig) {
      return jsonResponse(503, {
        pendingConfig: true,
        missingVariables: ['MP_WEBHOOK_SECRET'],
        error: sigCheck.reason
      });
    }

    return jsonResponse(401, {
      error: sigCheck.reason || 'Firma de webhook inválida.'
    });
  }

  const checkDbCreds = deps.hasDbCredentials || hasFirebaseAdminCredentials;
  if (!checkDbCreds(env)) {
    const pending = getFirebaseAdminPendingConfigResponse(env);
    return jsonResponse(503, {
      pendingConfig: true,
      configReason: pending.configReason,
      missingVariables: pending.missingVariables,
      error: pending.error
    });
  }

  const fetchPaymentFn = deps.fetchPayment || ((pid: string) => getPayment(pid, env));
  const mpPayment = await fetchPaymentFn(dataId, env);

  if (!mpPayment.success || !mpPayment.data) {
    if (mpPayment.pendingConfig) {
      return jsonResponse(503, {
        pendingConfig: true,
        missingVariables: ['MP_ACCESS_TOKEN'],
        error: mpPayment.error || 'MP_ACCESS_TOKEN pendiente de configuración en Cloudflare.'
      });
    }

    return jsonResponse(502, {
      error: mpPayment.error || 'No se pudo verificar el pago en la API de Mercado Pago.'
    });
  }

  try {
    const getPricingFn = deps.getPricing || (() => getCurrentPricing(env));
    const expectedPricing = await getPricingFn(env);

    const store = deps.getPaymentStore
      ? deps.getPaymentStore(env)
      : createFirestoreRestPaymentStore(createFirestoreRestClient(env));

    const outcome = await processVerifiedPaymentAtomic(
      store,
      mpPayment.data as VerifiedMercadoPagoPayment,
      expectedPricing,
      now
    );

    if (!outcome.ok) {
      return jsonResponse(422, {
        received: true,
        processed: false,
        grantedDays: 0,
        reason: outcome.reason
      });
    }

    return jsonResponse(200, {
      received: true,
      processed: !outcome.ignored,
      ignored: Boolean(outcome.ignored),
      reverted: Boolean(outcome.reverted),
      duplicate: Boolean(outcome.duplicate),
      grantedDays: outcome.grantedDays,
      paymentId: outcome.paymentId,
      paymentStatus: outcome.paymentStatus,
      uid: outcome.uid,
      estado: outcome.newEstado,
      venceEl: outcome.newVenceEl,
      reason: outcome.reason
    });
  } catch (err: any) {
    console.error('Error en payment-webhook:', err);

    if (
      err instanceof PricingUnavailableError ||
      err?.name === 'PricingUnavailableError' ||
      err?.code === 'PRICING_UNAVAILABLE'
    ) {
      return jsonResponse(503, {
        received: true,
        processed: false,
        retryable: true,
        grantedDays: 0,
        error:
          err?.message ||
          'No se pudo determinar la tarifa vigente en Firestore. Notificación diferida para reintento.'
      });
    }

    return jsonResponse(500, {
      received: true,
      processed: false,
      retryable: true,
      grantedDays: 0,
      error: `Error interno procesando notificación de pago: ${err?.message || err}`
    });
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handlePaymentWebhook(context);
};
