import {
  createFirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../../cloudflare/shared/firebaseRest';
import { jsonResponse } from '../../cloudflare/shared/http';
import { cancelPreapproval } from '../../cloudflare/shared/mercadopago';
import type {
  CloudflareEnv,
  CloudflarePagesContext,
  SuscriptorAdminRecord
} from '../../cloudflare/shared/types';

export interface CancelSubscriptionDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getSubscriber?: (uid: string, env?: CloudflareEnv) => Promise<SuscriptorAdminRecord | null>;
  cancelMpPreapproval?: (
    preapprovalId: string,
    env?: CloudflareEnv
  ) => Promise<{ success: boolean; error?: string }>;
  updateSubscriber?: (
    uid: string,
    patch: Partial<SuscriptorAdminRecord>,
    env?: CloudflareEnv
  ) => Promise<void>;
  nowProvider?: () => Date;
}

export async function handleCancelSubscription(
  context: CloudflarePagesContext,
  deps: CancelSubscriptionDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;

  if (request.method !== 'POST') {
    return jsonResponse(405, {
      error: 'Método no permitido. Utilizar POST.'
    });
  }

  const authHeader = request.headers.get('authorization') ?? undefined;
  const verifyTokenFn = deps.verifyToken || ((hdr?: string) => verifyUserTokenStrict(hdr, env));
  const tokenCheck = await verifyTokenFn(authHeader, env);

  if (!tokenCheck.authenticated) {
    if (tokenCheck.reason === 'pending_config') {
      return jsonResponse(503, {
        success: false,
        pendingConfig: true,
        configReason: tokenCheck.configReason,
        missingVariables: tokenCheck.missingVariables ?? [],
        error: tokenCheck.message
      });
    }

    return jsonResponse(401, {
      error: 'No autorizado. Se requiere iniciar sesión.'
    });
  }

  const checkDbCreds = deps.hasDbCredentials || hasFirebaseAdminCredentials;
  if (!checkDbCreds(env)) {
    const pending = getFirebaseAdminPendingConfigResponse(env);
    return jsonResponse(503, {
      success: false,
      pendingConfig: true,
      configReason: pending.configReason,
      missingVariables: pending.missingVariables,
      error: pending.error
    });
  }

  const uid = tokenCheck.uid;

  try {
    const getSubscriberFn =
      deps.getSubscriber ||
      ((u: string) => createFirestoreRestClient(env).getDocument<SuscriptorAdminRecord>(`suscriptores/${u}`));

    const userData = await getSubscriberFn(uid, env);
    if (!userData) {
      return jsonResponse(404, {
        error: 'Ficha de suscriptor no encontrada.'
      });
    }

    const preapprovalId = userData.mpPreapprovalId;

    if (!preapprovalId || userData.modalidadComercial === 'manual_30d') {
      return jsonResponse(400, {
        success: false,
        error:
          'Tu cuenta opera con renovación manual por 30 días (Checkout Pro) y no posee una suscripción automática recurrente para cancelar.'
      });
    }

    const cancelPreapprovalFn =
      deps.cancelMpPreapproval || ((id: string) => cancelPreapproval(id, env));
    const cancelResult = await cancelPreapprovalFn(preapprovalId, env);
    if (!cancelResult.success) {
      console.warn('Advertencia cancelando en Mercado Pago:', cancelResult.error);
    }

    const now = deps.nowProvider ? deps.nowProvider() : new Date();
    const nowIso = now.toISOString();

    const updateSubscriberFn =
      deps.updateSubscriber ||
      ((u: string, patch: Partial<SuscriptorAdminRecord>) =>
        createFirestoreRestClient(env).updateDocument(`suscriptores/${u}`, patch));

    await updateSubscriberFn(
      uid,
      {
        estado: 'cancelado',
        canceladoEl: nowIso,
        ultimaActualizacion: nowIso
      },
      env
    );

    return jsonResponse(200, {
      success: true,
      mensaje: 'Suscripción comercial cancelada correctamente.',
      aclaracionSoberania:
        'La cancelación comercial no borra los datos guardados en tu teléfono VEL CORE ni desvincula las identidades de tus dispositivos.'
    });
  } catch (err: any) {
    return jsonResponse(500, {
      error: `Error cancelando suscripción: ${err?.message || err}`
    });
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleCancelSubscription(context);
};
