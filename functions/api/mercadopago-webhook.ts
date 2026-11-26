import {
  createFirestoreRestClient,
  FirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials
} from '../../cloudflare/shared/firebaseRest';
import { getQueryParams, jsonResponse, parseJsonBody } from '../../cloudflare/shared/http';
import {
  getPayment,
  getPreapproval,
  verifyMpWebhookSignature,
  VerifyWebhookSignatureOptions
} from '../../cloudflare/shared/mercadopago';
import type {
  CloudflareEnv,
  CloudflarePagesContext,
  SubscriberStatus,
  SuscriptorAdminRecord,
  WebhookEventRecord
} from '../../cloudflare/shared/types';

const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000;

export interface LegacyWebhookDeps {
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
  getPreapprovalFn?: (
    preapprovalId: string,
    env?: CloudflareEnv
  ) => Promise<{ success: boolean; data?: any; error?: string }>;
  getPaymentFn?: (
    paymentId: string,
    env?: CloudflareEnv
  ) => Promise<{ success: boolean; pendingConfig?: boolean; data?: any; error?: string }>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getClient?: (env: CloudflareEnv) => FirestoreRestClient;
  nowProvider?: () => Date;
}

export async function handleLegacyPreapprovalWebhook(
  context: CloudflarePagesContext,
  deps: LegacyWebhookDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;

  if (request.method !== 'POST') {
    return jsonResponse(405, {
      error: 'Solo se acepta método POST para webhooks.'
    });
  }

  const parsed = await parseJsonBody(request);
  const body = parsed.ok ? parsed.data : {};
  const queryParams = getQueryParams(request);

  const dataId = String(
    queryParams['data.id'] || body?.data?.id || queryParams.id || body.id || ''
  ).trim();
  const eventType = String(
    body.type || queryParams.type || body.topic || queryParams.topic || 'unknown'
  ).toLowerCase();
  const action = String(body.action || 'event');

  if (!dataId) {
    return jsonResponse(200, { received: true, note: 'Evento sin data.id' });
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
      error: 'Firma de webhook inválida o no autenticada.'
    });
  }

  const checkDb = deps.hasDbCredentials || hasFirebaseAdminCredentials;
  if (!checkDb(env)) {
    const pending = getFirebaseAdminPendingConfigResponse(env);
    return jsonResponse(503, {
      pendingConfig: true,
      configReason: pending.configReason,
      missingVariables: pending.missingVariables,
      error: pending.error
    });
  }

  const client = deps.getClient ? deps.getClient(env) : createFirestoreRestClient(env);
  const eventId = `ev_${eventType}_${dataId}_${action}`;

  try {
    const existingEvent = await client.getDocument<WebhookEventRecord>(`webhook_events/${eventId}`);
    if (existingEvent && existingEvent.processed === true) {
      return jsonResponse(200, { received: true, duplicate: true });
    }

    let externalRefUid: string | null = null;
    let newStatus: SubscriberStatus | null = null;
    let paymentDateIso: string | null = null;
    let nextPaymentDateIso: string | null = null;
    let preapprovalId: string | null = null;

    if (eventType.includes('preapproval')) {
      const fetchPreapproval = deps.getPreapprovalFn || ((id: string) => getPreapproval(id, env));
      const mpPreapproval = await fetchPreapproval(dataId, env);
      if (mpPreapproval.success && mpPreapproval.data) {
        const pData = mpPreapproval.data;
        preapprovalId = pData.id;
        externalRefUid = pData.external_reference || null;

        const mpStatus = String(pData.status || '').toLowerCase();
        if (mpStatus === 'authorized') {
          newStatus = 'activo';
          paymentDateIso = now.toISOString();
          nextPaymentDateIso = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
        } else if (mpStatus === 'cancelled') {
          newStatus = 'cancelado';
        } else if (mpStatus === 'paused' || mpStatus === 'pending') {
          newStatus = 'en_gracia';
        }
      }
    } else if (eventType.includes('payment')) {
      const processedDoc = await client.getDocument(`pagos_procesados/${dataId}`);
      if (processedDoc) {
        return jsonResponse(200, {
          received: true,
          ignored: true,
          reason: 'Pago pertenece al circuito oficial Checkout Pro (pagos_procesados).'
        });
      }

      const fetchPayment = deps.getPaymentFn || ((id: string) => getPayment(id, env));
      const mpPayment = await fetchPayment(dataId, env);
      if (mpPayment.success && mpPayment.data) {
        const payData = mpPayment.data;
        if (payData.metadata?.circuito === 'checkout_pro' || !payData.preapproval_id) {
          return jsonResponse(200, {
            received: true,
            ignored: true,
            reason:
              'Pago sin preapproval_id o marcado como checkout_pro; delegado exclusivamente a payment-webhook.'
          });
        }

        externalRefUid = payData.external_reference || null;
        preapprovalId = String(payData.preapproval_id);
        const payStatus = String(payData.status || '').toLowerCase();

        if (payStatus === 'approved') {
          newStatus = 'activo';
          paymentDateIso = payData.date_approved || now.toISOString();
          nextPaymentDateIso = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
        } else if (payStatus === 'rejected' || payStatus === 'refunded' || payStatus === 'charged_back') {
          newStatus = 'en_gracia';
        }
      }
    }

    if (externalRefUid && newStatus) {
      const currentData = await client.getDocument<SuscriptorAdminRecord>(
        `suscriptores/${externalRefUid}`
      );

      if (currentData) {
        if (currentData.modalidadComercial === 'manual_30d' || !currentData.mpPreapprovalId) {
          return jsonResponse(200, {
            received: true,
            ignored: true,
            reason:
              'Cuenta configurada en modalidad manual Checkout Pro; webhook Preapproval no modifica su vigencia.'
          });
        }

        const updatePayload: Partial<SuscriptorAdminRecord> & Record<string, any> = {};

        if (preapprovalId) {
          updatePayload.mpPreapprovalId = preapprovalId;
        }

        if (newStatus === 'activo') {
          updatePayload.estado = 'activo';
          updatePayload.fechaUltimoPago = paymentDateIso || now.toISOString();
          updatePayload.venceEl = nextPaymentDateIso || currentData.venceEl;
          updatePayload.fechaProximoPago = nextPaymentDateIso || currentData.venceEl;
          updatePayload.fechaInicioGracia = null;
        } else if (newStatus === 'cancelado') {
          updatePayload.estado = 'cancelado';
          updatePayload.canceladoEl = now.toISOString();
        } else if (newStatus === 'en_gracia') {
          if (!currentData.fechaInicioGracia) {
            updatePayload.fechaInicioGracia = now.toISOString();
            updatePayload.estado = 'en_gracia';
          } else {
            const inicioGraciaTime = new Date(currentData.fechaInicioGracia).getTime();
            const elapsed = now.getTime() - inicioGraciaTime;
            updatePayload.estado = elapsed >= GRACE_PERIOD_MS ? 'suspendido' : 'en_gracia';
          }
        }

        updatePayload.ultimaActualizacion = now.toISOString();
        await client.updateDocument(`suscriptores/${externalRefUid}`, updatePayload);
      }
    }

    const eventRecord: WebhookEventRecord = {
      eventId,
      receivedAt: now.toISOString(),
      type: eventType,
      action,
      resourceId: dataId,
      externalReference: externalRefUid,
      statusResolved: newStatus || undefined,
      processed: true
    };
    await client.setDocument(`webhook_events/${eventId}`, eventRecord, false);

    return jsonResponse(200, { received: true, processed: true, status: newStatus });
  } catch (err: any) {
    console.error('Error procesando webhook histórico Preapproval:', err);
    return jsonResponse(500, {
      error: `Fallo interno al procesar webhook: ${err?.message || err}`
    });
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleLegacyPreapprovalWebhook(context);
};
