import {
  bindDeviceSubscriptionAtomic,
  createFirestoreRestDeviceStore,
  deactivateDeviceForRoleChangeAtomic,
  DeviceTransactionStore,
  getAndRefreshDeviceSessionAtomic
} from '../../cloudflare/shared/deviceAuthService';
import {
  createFirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials,
  isNonAnonymousFirebaseToken,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../../cloudflare/shared/firebaseRest';
import { getQueryParams, jsonResponse, parseJsonBody } from '../../cloudflare/shared/http';
import {
  evaluateSubscriberAccess,
  verifySubscriptionPass
} from '../../cloudflare/shared/subscriptionAccess';
import type { CloudflareEnv, CloudflarePagesContext } from '../../cloudflare/shared/types';
import type { SubscriptionRuntimeStatus } from '../../src/contracts/velContracts';

export interface DeviceSessionDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  verifyCommercialToken?: (
    authHeader?: string,
    env?: CloudflareEnv
  ) => Promise<TokenVerificationResult>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getDeviceStore?: (env: CloudflareEnv) => DeviceTransactionStore;
  nowProvider?: () => Date;
}

async function resolveSubscriptionStatusForSession(
  store: DeviceTransactionStore,
  subscriptionUid: string | null | undefined,
  now: Date
): Promise<SubscriptionRuntimeStatus> {
  if (!subscriptionUid || !store.getSubscriber) {
    return { linked: false, active: true };
  }
  try {
    const sub = await store.getSubscriber(subscriptionUid);
    const evalRes = evaluateSubscriberAccess(sub, now);
    if (!evalRes.active && evalRes.shouldPersistEstado && store.updateSubscriberStatus) {
      try {
        await store.updateSubscriberStatus(subscriptionUid, {
          estado: evalRes.shouldPersistEstado,
          ultimaActualizacion: now.toISOString()
        });
      } catch {}
    }
    return {
      linked: true,
      active: evalRes.active,
      estado: evalRes.estado,
      venceEl: evalRes.venceEl,
      reason: evalRes.reason
    };
  } catch {
    return { linked: true, active: true };
  }
}

export async function handleDeviceSession(
  context: CloudflarePagesContext,
  deps: DeviceSessionDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;

  if (request.method !== 'GET' && request.method !== 'POST') {
    return jsonResponse(405, {
      success: false,
      error: 'Método no permitido. Utilizar GET o POST.'
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
      success: false,
      error: tokenCheck.message
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

  const store = deps.getDeviceStore
    ? deps.getDeviceStore(env)
    : createFirestoreRestDeviceStore(createFirestoreRestClient(env));
  const now = deps.nowProvider ? deps.nowProvider() : new Date();

  try {
    if (request.method === 'GET') {
      const query = getQueryParams(request);
      const deviceId = String(query.deviceId || '').trim();
      const outcome = await getAndRefreshDeviceSessionAtomic(store, tokenCheck.uid, deviceId, now);
      const subUid = outcome.device?.subscriptionUid || outcome.activeLink?.subscriptionUid || null;
      const subscriptionStatus = outcome.ok
        ? await resolveSubscriptionStatusForSession(store, subUid, now)
        : undefined;

      return jsonResponse(
        outcome.statusCode,
        outcome.ok
          ? {
              success: true,
              device: outcome.device,
              activeLink: outcome.activeLink || null,
              activeAuthorization: outcome.activeAuthorization || null,
              subscriptionStatus
            }
          : {
              success: false,
              code: outcome.code,
              error: outcome.reason
            },
        { 'Cache-Control': 'no-store' }
      );
    }

    const parsed = await parseJsonBody(request);
    if (!parsed.ok) {
      return jsonResponse(400, {
        success: false,
        error: 'Cuerpo JSON inválido.'
      });
    }

    const body = parsed.data;
    const action = String(body.action || 'status').trim();
    const deviceId = String(body.deviceId || '').trim();

    if (action === 'deactivate_for_role_change') {
      const outcome = await deactivateDeviceForRoleChangeAtomic(store, tokenCheck.uid, deviceId, now);
      return jsonResponse(
        outcome.statusCode,
        outcome.ok
          ? { success: true, device: outcome.device }
          : { success: false, code: outcome.code, error: outcome.reason },
        { 'Cache-Control': 'no-store' }
      );
    }

    if (action === 'bind_subscription') {
      let targetSubscriptionUid: string | null = null;
      const rawCommercialToken = String(body.commercialIdToken || '').trim();
      const rawSubscriptionPass = String(body.subscriptionPass || '').trim();

      if (rawCommercialToken) {
        const verifyCommercialFn =
          deps.verifyCommercialToken || ((hdr?: string) => verifyUserTokenStrict(hdr, env));
        const commercialCheck = await verifyCommercialFn(`Bearer ${rawCommercialToken}`, env);
        if (!commercialCheck.authenticated) {
          return jsonResponse(
            403,
            {
              success: false,
              code: 'INVALID_COMMERCIAL_TOKEN',
              error: commercialCheck.message || 'Sesión comercial de Firebase inválida.'
            },
            { 'Cache-Control': 'no-store' }
          );
        }
        if (!isNonAnonymousFirebaseToken(commercialCheck.claims)) {
          return jsonResponse(
            403,
            {
              success: false,
              code: 'ANONYMOUS_NOT_ALLOWED',
              error: 'Para vincular una cuenta VEL debes iniciar sesión con tu correo electrónico.'
            },
            { 'Cache-Control': 'no-store' }
          );
        }
        targetSubscriptionUid = commercialCheck.uid;
      } else {
        const passRes = await verifySubscriptionPass(
          rawSubscriptionPass,
          now,
          undefined,
          env
        );
        if (!passRes.valid || !passRes.uid) {
          return jsonResponse(
            403,
            {
              success: false,
              code: 'INVALID_SUBSCRIPTION_PASS',
              error: passRes.reason || 'Pase de suscripción inválido o expirado.'
            },
            { 'Cache-Control': 'no-store' }
          );
        }
        targetSubscriptionUid = passRes.uid;
      }

      const outcome = await bindDeviceSubscriptionAtomic(
        store,
        tokenCheck.uid,
        deviceId,
        targetSubscriptionUid,
        now
      );
      const subscriptionStatus = outcome.ok
        ? await resolveSubscriptionStatusForSession(store, targetSubscriptionUid, now)
        : undefined;

      return jsonResponse(
        outcome.statusCode,
        outcome.ok
          ? {
              success: true,
              device: outcome.device,
              activeLink: outcome.activeLink || null,
              activeAuthorization: outcome.activeAuthorization || null,
              subscriptionStatus
            }
          : { success: false, code: outcome.code, error: outcome.reason },
        { 'Cache-Control': 'no-store' }
      );
    }

    const outcome = await getAndRefreshDeviceSessionAtomic(store, tokenCheck.uid, deviceId, now);
    const subUid = outcome.device?.subscriptionUid || outcome.activeLink?.subscriptionUid || null;
    const subscriptionStatus = outcome.ok
      ? await resolveSubscriptionStatusForSession(store, subUid, now)
      : undefined;

    return jsonResponse(
      outcome.statusCode,
      outcome.ok
        ? {
            success: true,
            device: outcome.device,
            activeLink: outcome.activeLink || null,
            activeAuthorization: outcome.activeAuthorization || null,
            subscriptionStatus
          }
        : {
            success: false,
            code: outcome.code,
            error: outcome.reason
          },
      { 'Cache-Control': 'no-store' }
    );
  } catch (err: any) {
    return jsonResponse(500, {
      success: false,
      error: `Error en sesión técnica del dispositivo: ${err?.message || err}`
    });
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleDeviceSession(context);
};
