import {
  buildBloggerCorsHeaders,
  isOriginAllowedForBlogger
} from '../../cloudflare/shared/corsBlogger';
import {
  createFirestoreRestDeviceStore,
  deactivateAccountAndDevicesAtomic,
  DeviceTransactionStore,
  ensureSubscriberAccountAtomic,
  toAccountDeviceSummary
} from '../../cloudflare/shared/deviceAuthService';
import {
  createFirestoreRestClient,
  deleteFirebaseAuthUser,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials,
  isNonAnonymousFirebaseToken,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../../cloudflare/shared/firebaseRest';
import {
  emptyResponse,
  getQueryParams,
  getRequestHost,
  jsonResponse,
  parseJsonBody
} from '../../cloudflare/shared/http';
import { cancelPreapproval } from '../../cloudflare/shared/mercadopago';
import { evaluateSubscriberAccess } from '../../cloudflare/shared/subscriptionAccess';
import type { CloudflareEnv, CloudflarePagesContext } from '../../cloudflare/shared/types';

export const ACCOUNT_DELETION_CONFIRM_KEYWORD = 'ELIMINAR CUENTA';

export interface AccountEndpointDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getDeviceStore?: (env: CloudflareEnv) => DeviceTransactionStore;
  cancelMpPreapproval?: (
    preapprovalId: string,
    env?: CloudflareEnv
  ) => Promise<{ success: boolean; error?: string }>;
  deleteAuthUser?: (
    uid: string,
    env?: CloudflareEnv
  ) => Promise<{ deleted: boolean; pendingConfig?: boolean; error?: string }>;
  nowProvider?: () => Date;
}

export async function handleAccountRequest(
  context: CloudflarePagesContext,
  deps: AccountEndpointDeps = {}
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

  if (request.method !== 'GET' && request.method !== 'POST' && request.method !== 'DELETE') {
    return jsonResponse(
      405,
      {
        success: false,
        error: 'Método no permitido. Utilizar GET, POST o DELETE.'
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
        error:
          'Las operaciones de cuenta VEL requieren una sesión autenticada con correo electrónico (no anónima).'
      },
      corsHeaders
    );
  }

  const checkDbCreds = deps.hasDbCredentials || hasFirebaseAdminCredentials;
  if (!checkDbCreds(env)) {
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

  const store = deps.getDeviceStore
    ? deps.getDeviceStore(env)
    : createFirestoreRestDeviceStore(createFirestoreRestClient(env));
  const now = deps.nowProvider ? deps.nowProvider() : new Date();

  try {
    if (request.method === 'GET') {
      const [subscriber, linkedDevices, contractAccepted] = await Promise.all([
        store.getSubscriber ? store.getSubscriber(tokenCheck.uid) : Promise.resolve(null),
        store.listDevicesBySubscriptionUid
          ? store.listDevicesBySubscriptionUid(tokenCheck.uid)
          : Promise.resolve([]),
        store.hasAcceptedContract
          ? store.hasAcceptedContract(tokenCheck.uid, '1.2')
          : Promise.resolve(false)
      ]);

      const evaluation = evaluateSubscriberAccess(subscriber, now);
      if (
        subscriber &&
        !evaluation.active &&
        evaluation.shouldPersistEstado &&
        store.updateSubscriberStatus
      ) {
        try {
          await store.updateSubscriberStatus(tokenCheck.uid, {
            estado: evaluation.shouldPersistEstado,
            ultimaActualizacion: now.toISOString()
          });
        } catch {}
      }

      return jsonResponse(
        200,
        {
          success: true,
          registered: Boolean(subscriber),
          account: subscriber
            ? {
                uid: subscriber.uid,
                email: subscriber.email,
                estado: evaluation.estado,
                plan: subscriber.plan,
                venceEl: subscriber.venceEl,
                modalidadComercial: subscriber.modalidadComercial ?? 'manual_30d',
                altaCompletadaEl: subscriber.altaCompletadaEl ?? null,
                bajaSolicitadaEl: subscriber.bajaSolicitadaEl ?? null,
                contratoV12Aceptado: contractAccepted
              }
            : {
                uid: tokenCheck.uid,
                email: tokenCheck.email || '',
                estado: 'no_registrado',
                plan: null,
                venceEl: null,
                modalidadComercial: 'manual_30d',
                altaCompletadaEl: null,
                bajaSolicitadaEl: null,
                contratoV12Aceptado: contractAccepted
              },
          subscriptionStatus: {
            linked: Boolean(subscriber),
            active: evaluation.active,
            estado: evaluation.estado,
            venceEl: evaluation.venceEl,
            reason: evaluation.reason
          },
          devices: linkedDevices.map(toAccountDeviceSummary)
        },
        {
          ...corsHeaders,
          'Cache-Control': 'no-store'
        }
      );
    }

    const parsed = await parseJsonBody(request);
    if (!parsed.ok) {
      return jsonResponse(
        400,
        {
          success: false,
          error: 'Cuerpo JSON inválido.'
        },
        corsHeaders
      );
    }

    const body = parsed.data || {};
    const action =
      request.method === 'DELETE' ? 'deactivate' : String(body.action || 'register').trim();

    if (action === 'register') {
      const outcome = await ensureSubscriberAccountAtomic(
        store,
        {
          uid: tokenCheck.uid,
          email: tokenCheck.email || String(body.email || '')
        },
        now
      );

      if (!outcome.ok || !outcome.subscriber) {
        return jsonResponse(
          outcome.statusCode,
          {
            success: false,
            code: outcome.code,
            error: outcome.reason
          },
          {
            ...corsHeaders,
            'Cache-Control': 'no-store'
          }
        );
      }

      const [linkedDevices, contractAccepted] = await Promise.all([
        store.listDevicesBySubscriptionUid
          ? store.listDevicesBySubscriptionUid(tokenCheck.uid)
          : Promise.resolve([]),
        store.hasAcceptedContract
          ? store.hasAcceptedContract(tokenCheck.uid, '1.2')
          : Promise.resolve(false)
      ]);
      const evaluation = evaluateSubscriberAccess(outcome.subscriber, now);

      return jsonResponse(
        outcome.statusCode,
        {
          success: true,
          created: Boolean(outcome.created),
          alreadyExisted: Boolean(outcome.alreadyExisted),
          account: {
            uid: outcome.subscriber.uid,
            email: outcome.subscriber.email,
            estado: evaluation.estado,
            plan: outcome.subscriber.plan,
            venceEl: outcome.subscriber.venceEl,
            modalidadComercial: outcome.subscriber.modalidadComercial ?? 'manual_30d',
            altaCompletadaEl: outcome.subscriber.altaCompletadaEl ?? null,
            bajaSolicitadaEl: outcome.subscriber.bajaSolicitadaEl ?? null,
            contratoV12Aceptado: contractAccepted
          },
          subscriptionStatus: {
            linked: true,
            active: evaluation.active,
            estado: evaluation.estado,
            venceEl: evaluation.venceEl,
            reason: evaluation.reason
          },
          devices: linkedDevices.map(toAccountDeviceSummary)
        },
        {
          ...corsHeaders,
          'Cache-Control': 'no-store'
        }
      );
    }

    if (action === 'deactivate' || action === 'baja') {
      const query = getQueryParams(request);
      const confirmText = String(body.confirmText || '').trim().toUpperCase();
      const confirmed =
        body.confirm === true ||
        confirmText === ACCOUNT_DELETION_CONFIRM_KEYWORD ||
        query.confirm === 'true';

      if (!confirmed) {
        return jsonResponse(
          400,
          {
            success: false,
            code: 'CONFIRMATION_REQUIRED',
            error: `Debes confirmar explícitamente la baja enviando confirmText="${ACCOUNT_DELETION_CONFIRM_KEYWORD}".`
          },
          corsHeaders
        );
      }

      const existingSub = store.getSubscriber
        ? await store.getSubscriber(tokenCheck.uid)
        : null;

      let mpSubscriptionCancelled = false;
      if (existingSub?.mpPreapprovalId) {
        const cancelMpFn =
          deps.cancelMpPreapproval || ((id: string) => cancelPreapproval(id, env));
        const mpRes = await cancelMpFn(existingSub.mpPreapprovalId, env);
        if (!mpRes.success) {
          return jsonResponse(
            502,
            {
              success: false,
              code: 'MP_CANCELLATION_FAILED',
              error:
                mpRes.error ||
                'No se pudo confirmar la cancelación de la suscripción recurrente en Mercado Pago. La baja quedó detenida para evitar cobros futuros.'
            },
            corsHeaders
          );
        }
        mpSubscriptionCancelled = true;
      }

      const reason = String(body.reason || 'Baja de cuenta solicitada por el titular').trim();
      const deactivation = await deactivateAccountAndDevicesAtomic(
        store,
        tokenCheck.uid,
        reason,
        now
      );

      if (!deactivation.ok) {
        return jsonResponse(
          deactivation.statusCode,
          {
            success: false,
            code: deactivation.code,
            error: deactivation.reason
          },
          corsHeaders
        );
      }

      const deleteAuthFn =
        deps.deleteAuthUser || ((uid: string) => deleteFirebaseAuthUser(env, uid));
      const authDel = await deleteAuthFn(tokenCheck.uid, env);

      return jsonResponse(
        200,
        {
          success: true,
          accountDeactivated: true,
          mpSubscriptionCancelled,
          revokedDeviceIds: deactivation.revokedDeviceIds,
          revokedLinkIds: deactivation.revokedLinkIds,
          authAccountDeleted: authDel.deleted,
          authPropagationError: authDel.deleted ? null : authDel.error || null,
          localVaultNotice:
            'Las copias guardadas localmente en tu teléfono VEL CORE permanecen intactas bajo tu control y no fueron borradas automáticamente.'
        },
        {
          ...corsHeaders,
          'Cache-Control': 'no-store'
        }
      );
    }

    return jsonResponse(
      400,
      {
        success: false,
        error: 'Acción no reconocida para /api/account.'
      },
      corsHeaders
    );
  } catch (err: any) {
    return jsonResponse(
      500,
      {
        success: false,
        error: `Error procesando cuenta VEL: ${err?.message || err}`
      },
      corsHeaders
    );
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleAccountRequest(context);
};
