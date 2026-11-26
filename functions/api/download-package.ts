import {
  buildBloggerCorsHeaders,
  isOriginAllowedForBlogger
} from '../../cloudflare/shared/corsBlogger';
import {
  createFirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../../cloudflare/shared/firebaseRest';
import {
  emptyResponse,
  getQueryParams,
  getRequestHost,
  jsonResponse,
  redirectResponse
} from '../../cloudflare/shared/http';
import {
  createSubscriptionPass,
  evaluateSubscriberAccess,
  GRACE_PERIOD_MS
} from '../../cloudflare/shared/subscriptionAccess';
import type {
  CloudflareEnv,
  CloudflarePagesContext,
  SuscriptorAdminRecord
} from '../../cloudflare/shared/types';

export { GRACE_PERIOD_MS };

export interface DownloadPackageDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  getSubscriber?: (uid: string, env?: CloudflareEnv) => Promise<SuscriptorAdminRecord | null>;
  updateSubscriberStatus?: (
    uid: string,
    patch: Partial<SuscriptorAdminRecord>,
    env?: CloudflareEnv
  ) => Promise<void>;
  nowProvider?: () => Date;
}

async function defaultGetSubscriber(
  uid: string,
  env: CloudflareEnv = {}
): Promise<SuscriptorAdminRecord | null> {
  const client = createFirestoreRestClient(env);
  return client.getDocument<SuscriptorAdminRecord>(`suscriptores/${uid}`);
}

async function defaultUpdateSubscriberStatus(
  uid: string,
  patch: Partial<SuscriptorAdminRecord>,
  env: CloudflareEnv = {}
): Promise<void> {
  const client = createFirestoreRestClient(env);
  await client.updateDocument(`suscriptores/${uid}`, patch);
}

function resolvePwaAccessUrl(
  host: string,
  env: CloudflareEnv,
  velPass?: string | null
): string {
  const envBase = String(env.APP_BASE_URL || '').trim().replace(/\/+$/, '');
  const cleanHost = String(host || '').trim().replace(/\/+$/, '');
  let baseUrl = '/';
  if (envBase) {
    baseUrl = `${envBase}/`;
  } else if (cleanHost) {
    const protocol =
      cleanHost.includes('localhost') || cleanHost.startsWith('127.0.0.1') ? 'http' : 'https';
    baseUrl = `${protocol}://${cleanHost}/`;
  }
  if (velPass) {
    return `${baseUrl}?vel_pass=${encodeURIComponent(velPass)}`;
  }
  return baseUrl;
}

export async function handleDownloadPackage(
  context: CloudflarePagesContext,
  deps: DownloadPackageDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;
  const origin = request.headers.get('origin') ?? undefined;
  const host = getRequestHost(request);
  const corsHeaders = buildBloggerCorsHeaders(origin, host, env);

  if (origin && !isOriginAllowedForBlogger(origin, host, env)) {
    return jsonResponse(
      403,
      {
        authorized: false,
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

  const queryParams = getQueryParams(request);
  let authHeader = request.headers.get('authorization') ?? undefined;
  if (!authHeader && queryParams.token) {
    authHeader = `Bearer ${queryParams.token}`;
  }

  const verifyTokenFn = deps.verifyToken || ((hdr?: string) => verifyUserTokenStrict(hdr, env));
  const tokenCheck = await verifyTokenFn(authHeader, env);

  if (!tokenCheck.authenticated) {
    if (tokenCheck.reason === 'pending_config') {
      return jsonResponse(
        503,
        {
          authorized: false,
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
        authorized: false,
        error:
          'No autenticado. Debes iniciar sesión con tu cuenta para acceder a la descarga de la aplicación.'
      },
      corsHeaders
    );
  }

  const uid = tokenCheck.uid;
  if (!deps.getSubscriber && !hasFirebaseAdminCredentials(env)) {
    const pending = getFirebaseAdminPendingConfigResponse(env);
    return jsonResponse(
      503,
      {
        authorized: false,
        pendingConfig: true,
        configReason: pending.configReason,
        missingVariables: pending.missingVariables,
        error: pending.error
      },
      corsHeaders
    );
  }

  const now = deps.nowProvider ? deps.nowProvider() : new Date();
  const nowIso = now.toISOString();
  const wantsJson =
    queryParams.format === 'json' ||
    String(request.headers.get('accept') || '').includes('application/json');

  try {
    const getSubscriberFn =
      deps.getSubscriber || ((u: string) => defaultGetSubscriber(u, env));
    const updateStatusFn =
      deps.updateSubscriberStatus ||
      ((u: string, patch: Partial<SuscriptorAdminRecord>) =>
        defaultUpdateSubscriberStatus(u, patch, env));

    const subData = await getSubscriberFn(uid, env);
    const evalRes = evaluateSubscriberAccess(subData, now);

    if (!evalRes.active) {
      if (evalRes.shouldPersistEstado) {
        try {
          await updateStatusFn(
            uid,
            {
              estado: evalRes.shouldPersistEstado,
              ultimaActualizacion: nowIso
            },
            env
          );
        } catch (err) {
          console.warn('Advertencia actualizando estado vencido/suspendido en Firestore:', err);
        }
      }

      return jsonResponse(
        403,
        {
          authorized: false,
          estado: evalRes.estado,
          venceEl: evalRes.venceEl,
          error: evalRes.reason
        },
        corsHeaders
      );
    }

    const velPass = await createSubscriptionPass(uid, now, undefined, undefined, env);
    const pwaAccessUrl = resolvePwaAccessUrl(host, env, velPass);

    if (wantsJson) {
      return jsonResponse(
        200,
        {
          authorized: true,
          estado: evalRes.estado,
          venceEl: evalRes.venceEl,
          downloadUrl: pwaAccessUrl
        },
        {
          ...corsHeaders,
          'Cache-Control': 'no-store'
        }
      );
    }

    return redirectResponse(pwaAccessUrl, {
      ...corsHeaders,
      'Cache-Control': 'no-store'
    });
  } catch (err: any) {
    return jsonResponse(
      500,
      {
        authorized: false,
        error: `Error validando autorización de descarga: ${err?.message || err}`
      },
      corsHeaders
    );
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleDownloadPackage(context);
};
