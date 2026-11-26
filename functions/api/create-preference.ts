import {
  buildBloggerCorsHeaders,
  isOriginAllowedForBlogger
} from '../../cloudflare/shared/corsBlogger';
import {
  createFirestoreRestClient,
  FirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials,
  isNonAnonymousFirebaseToken,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../../cloudflare/shared/firebaseRest';
import {
  emptyResponse,
  getRequestHost,
  jsonResponse
} from '../../cloudflare/shared/http';
import {
  createPaymentPreference,
  CreatePreferenceParams,
  PreferenceResponse
} from '../../cloudflare/shared/mercadopago';
import { resolveEffectiveSubscriberPricing } from '../../cloudflare/shared/paymentRenewalService';
import { getCurrentPricing, PricingUnavailableError } from '../../cloudflare/shared/pricingService';
import { createSubscriptionPass } from '../../cloudflare/shared/subscriptionAccess';
import type {
  CloudflareEnv,
  CloudflarePagesContext,
  PreferenciaPagoRecord,
  PricingConfig,
  SuscriptorAdminRecord
} from '../../cloudflare/shared/types';

export interface CreatePreferenceDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  getPricing?: (env?: CloudflareEnv) => Promise<PricingConfig>;
  getSubscriber?: (uid: string, env?: CloudflareEnv) => Promise<SuscriptorAdminRecord | null>;
  createPreference?: (
    params: CreatePreferenceParams,
    env?: CloudflareEnv
  ) => Promise<{ success: boolean; pendingConfig?: boolean; data?: PreferenceResponse; error?: string }>;
  recordPreferenceIntent?: (
    uid: string,
    email: string,
    preferenceId: string,
    effectivePricing: { monto: number; moneda: string; isHistorical: boolean },
    env?: CloudflareEnv
  ) => Promise<void>;
}

async function defaultGetSubscriber(
  uid: string,
  env: CloudflareEnv = {}
): Promise<SuscriptorAdminRecord | null> {
  const client = createFirestoreRestClient(env);
  return client.getDocument<SuscriptorAdminRecord>(`suscriptores/${uid}`);
}

export async function defaultRecordPreferenceIntent(
  uid: string,
  email: string,
  preferenceId: string,
  effectivePricing: { monto: number; moneda: string; isHistorical: boolean },
  env: CloudflareEnv = {},
  clientOverride?: FirestoreRestClient
): Promise<void> {
  const client = clientOverride || createFirestoreRestClient(env);
  const nowIso = new Date().toISOString();

  await client.runTransaction(async (tx) => {
    const existing = await tx.getDocument<SuscriptorAdminRecord>(`suscriptores/${uid}`);

    const prefRecord: PreferenciaPagoRecord = {
      preferenceId,
      uid,
      email,
      amount: effectivePricing.monto,
      currencyId: effectivePricing.moneda,
      isHistoricalPrice: effectivePricing.isHistorical,
      modalidadComercial: 'manual_30d',
      status: 'created',
      createdAt: nowIso
    };
    tx.setDocument(`preferencias_pago/${preferenceId}`, prefRecord, false);

    const basePatch: Record<string, any> = {
      uid,
      email,
      modalidadComercial: 'manual_30d',
      mpPreferenceId: preferenceId,
      mpExternalReference: uid,
      ultimaSolicitudPagoEl: nowIso,
      ultimaTarifaConsultada: effectivePricing.monto
    };

    if (!existing) {
      tx.setDocument(
        `suscriptores/${uid}`,
        {
          ...basePatch,
          moneda: effectivePricing.moneda,
          estado: 'pendiente_pago',
          plan: 'Suscripción mensual VEL',
          fechaAlta: nowIso,
          venceEl: null
        },
        false
      );
    } else {
      tx.setDocument(`suscriptores/${uid}`, basePatch, true);
    }
  });
}

export async function handleCreatePreference(
  context: CloudflarePagesContext,
  deps: CreatePreferenceDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;
  const origin = request.headers.get('origin') ?? undefined;
  const host = getRequestHost(request);
  const corsHeaders = buildBloggerCorsHeaders(origin, host, env);

  if (origin && !isOriginAllowedForBlogger(origin, host, env)) {
    return jsonResponse(
      403,
      {
        success: false,
        error: 'Origen no autorizado por la política CORS de VEL.'
      },
      {
        'Content-Type': 'application/json',
        Vary: 'Origin'
      }
    );
  }

  if (request.method === 'OPTIONS') {
    return emptyResponse(204, corsHeaders);
  }

  if (request.method !== 'POST') {
    return jsonResponse(
      405,
      {
        success: false,
        error: 'Método no permitido. Utilizar POST.'
      },
      corsHeaders
    );
  }

  const authHeader = request.headers.get('authorization') ?? undefined;
  const verifyTokenFn = deps.verifyToken || ((hdr?: string) => verifyUserTokenStrict(hdr, env));
  const tokenCheck = await verifyTokenFn(authHeader, env);

  if (!tokenCheck.authenticated) {
    if (tokenCheck.reason === 'pending_config') {
      return jsonResponse(
        503,
        {
          success: false,
          pendingConfig: true,
          configReason: tokenCheck.configReason,
          missingVariables: tokenCheck.missingVariables ?? [],
          error: tokenCheck.message
        },
        corsHeaders
      );
    }

    return jsonResponse(
      401,
      {
        success: false,
        error: tokenCheck.message
      },
      corsHeaders
    );
  }

  if (!isNonAnonymousFirebaseToken(tokenCheck.claims)) {
    return jsonResponse(
      403,
      {
        success: false,
        code: 'ANONYMOUS_NOT_ALLOWED',
        error: 'Para contratar una suscripción debes iniciar sesión con tu correo electrónico.'
      },
      corsHeaders
    );
  }

  const authenticUid = tokenCheck.uid;
  const authenticEmail = (tokenCheck.email || '').trim().toLowerCase();

  if (!deps.getPricing && !deps.getSubscriber && !hasFirebaseAdminCredentials(env)) {
    const pending = getFirebaseAdminPendingConfigResponse(env);
    return jsonResponse(
      503,
      {
        success: false,
        pendingConfig: true,
        configReason: pending.configReason,
        missingVariables: pending.missingVariables,
        error: pending.error
      },
      corsHeaders
    );
  }

  try {
    const getPricingFn = deps.getPricing || (() => getCurrentPricing(env));
    const getSubscriberFn = deps.getSubscriber || ((u: string) => defaultGetSubscriber(u, env));

    const [currentPricing, existingSubscriber] = await Promise.all([
      getPricingFn(env),
      getSubscriberFn(authenticUid, env)
    ]);

    if (existingSubscriber?.estado === 'cancelado' && existingSubscriber?.bajaSolicitadaEl) {
      return jsonResponse(
        403,
        {
          success: false,
          code: 'ACCOUNT_DEACTIVATED',
          error: 'Esta cuenta fue dada de baja previamente y no puede iniciar un nuevo cobro.'
        },
        corsHeaders
      );
    }

    const effectivePricing = resolveEffectiveSubscriberPricing(existingSubscriber, currentPricing);

    const protocol = host.includes('localhost') || host.startsWith('127.0.0.1') ? 'http' : 'https';
    const requestBaseOrigin = host ? `${protocol}://${host}` : '';
    const appBaseUrl = (env.APP_BASE_URL || requestBaseOrigin).replace(/\/+$/, '');
    const portalReturnBase = (env.VEL_PORTAL_RETURN_URL || appBaseUrl).replace(/\/+$/, '');
    const notificationUrl = `${appBaseUrl}/api/payment-webhook?source_news=webhooks`;

    const velPass = await createSubscriptionPass(authenticUid, new Date(), undefined, undefined, env);
    const successReturnUrl = velPass
      ? `${portalReturnBase}/?pago_retorno=aprobado&vel_pass=${encodeURIComponent(velPass)}`
      : `${portalReturnBase}/?pago_retorno=aprobado`;

    const createPreferenceFn =
      deps.createPreference || ((p: CreatePreferenceParams) => createPaymentPreference(p, env));

    const mpResult = await createPreferenceFn(
      {
        payerEmail: authenticEmail,
        externalReference: authenticUid,
        title: 'Suscripción mensual VEL',
        amount: effectivePricing.monto,
        currencyId: effectivePricing.moneda,
        backUrls: {
          success: successReturnUrl,
          pending: `${portalReturnBase}/?pago_retorno=pendiente`,
          failure: `${portalReturnBase}/?pago_retorno=cancelado`
        },
        notificationUrl
      },
      env
    );

    if (!mpResult.success || !mpResult.data) {
      if (mpResult.pendingConfig) {
        return jsonResponse(
          503,
          {
            success: false,
            pendingConfig: true,
            missingVariables: ['MP_ACCESS_TOKEN'],
            error: mpResult.error || 'MP_ACCESS_TOKEN pendiente de configuración en Cloudflare.'
          },
          corsHeaders
        );
      }

      return jsonResponse(
        502,
        {
          success: false,
          error: mpResult.error || 'No se pudo crear la preferencia de pago en Mercado Pago.'
        },
        corsHeaders
      );
    }

    const preference = mpResult.data;
    if (
      !preference.id ||
      typeof preference.init_point !== 'string' ||
      !preference.init_point.startsWith('https://')
    ) {
      return jsonResponse(
        502,
        {
          success: false,
          error: 'Mercado Pago no confirmó una URL de inicio de pago (init_point) válida.'
        },
        corsHeaders
      );
    }

    const recordFn =
      deps.recordPreferenceIntent ||
      ((u: string, e: string, pId: string, eff: { monto: number; moneda: string; isHistorical: boolean }) =>
        defaultRecordPreferenceIntent(u, e, pId, eff, env));

    await recordFn(authenticUid, authenticEmail, preference.id, effectivePricing, env);

    return jsonResponse(
      200,
      {
        success: true,
        preference_id: preference.id,
        init_point: preference.init_point,
        concepto: 'Suscripción mensual VEL',
        monto: effectivePricing.monto,
        moneda: effectivePricing.moneda,
        tarifaHistoricaConservada: effectivePricing.isHistorical
      },
      corsHeaders
    );
  } catch (err: any) {
    console.error('Error en create-preference:', err);
    if (
      err instanceof PricingUnavailableError ||
      err?.name === 'PricingUnavailableError' ||
      err?.code === 'PRICING_UNAVAILABLE'
    ) {
      return jsonResponse(
        503,
        {
          success: false,
          retryable: true,
          error: err?.message || 'Tarifa vigente temporalmente no disponible.'
        },
        corsHeaders
      );
    }

    return jsonResponse(
      500,
      {
        success: false,
        error: `No se pudo completar la creación y registro de la preferencia de pago: ${err?.message || err}`
      },
      corsHeaders
    );
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleCreatePreference(context);
};
