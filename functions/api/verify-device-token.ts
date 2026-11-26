import {
  createFirestoreRestDeviceStore,
  DeviceTransactionStore,
  getAndRefreshDeviceSessionAtomic
} from '../../cloudflare/shared/deviceAuthService';
import {
  createFirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../../cloudflare/shared/firebaseRest';
import { jsonResponse, parseJsonBody } from '../../cloudflare/shared/http';
import type { CloudflareEnv, CloudflarePagesContext } from '../../cloudflare/shared/types';

export interface VerifyDeviceTokenDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getDeviceStore?: (env: CloudflareEnv) => DeviceTransactionStore;
  nowProvider?: () => Date;
}

export async function handleVerifyDeviceToken(
  context: CloudflarePagesContext,
  deps: VerifyDeviceTokenDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;

  if (request.method !== 'POST') {
    return jsonResponse(405, {
      valid: false,
      error: 'Método no permitido. Utilizar POST.'
    });
  }

  const parsed = await parseJsonBody(request);
  if (!parsed.ok) {
    return jsonResponse(400, {
      valid: false,
      error: 'Cuerpo JSON inválido.'
    });
  }

  const body = parsed.data;
  const authHeader =
    request.headers.get('authorization') ||
    (body.firebaseIdToken ? `Bearer ${String(body.firebaseIdToken).trim()}` : undefined);

  const verifyTokenFn = deps.verifyToken || ((hdr?: string) => verifyUserTokenStrict(hdr, env));
  const tokenCheck = await verifyTokenFn(authHeader, env);

  if (!tokenCheck.authenticated) {
    const isPending = tokenCheck.reason === 'pending_config';
    return jsonResponse(isPending ? 503 : 401, {
      valid: false,
      pendingConfig: isPending,
      ...(isPending
        ? {
            configReason: tokenCheck.configReason,
            missingVariables: tokenCheck.missingVariables ?? []
          }
        : {}),
      reason: tokenCheck.message
    });
  }

  const checkDbCreds = deps.hasDbCredentials || hasFirebaseAdminCredentials;
  if (!checkDbCreds(env)) {
    const pending = getFirebaseAdminPendingConfigResponse(env);
    return jsonResponse(503, {
      valid: false,
      pendingConfig: true,
      configReason: pending.configReason,
      missingVariables: pending.missingVariables,
      reason: pending.error
    });
  }

  const deviceId = String(body.deviceId || '').trim();
  const peerDeviceId = body.peerDeviceId ? String(body.peerDeviceId).trim() : undefined;

  const store = deps.getDeviceStore
    ? deps.getDeviceStore(env)
    : createFirestoreRestDeviceStore(createFirestoreRestClient(env));
  const now = deps.nowProvider ? deps.nowProvider() : new Date();

  const outcome = await getAndRefreshDeviceSessionAtomic(store, tokenCheck.uid, deviceId, now);
  if (!outcome.ok || !outcome.device) {
    return jsonResponse(outcome.statusCode, {
      valid: false,
      code: outcome.code,
      reason: outcome.reason
    });
  }

  if (outcome.device.status === 'revoked') {
    return jsonResponse(403, {
      valid: false,
      code: 'DEVICE_REVOKED',
      authUid: tokenCheck.uid,
      device: outcome.device,
      reason: 'El dispositivo técnico se encuentra revocado.'
    });
  }

  if (peerDeviceId) {
    const auth = outcome.activeAuthorization;
    const isPeerAuthorized = Boolean(
      auth &&
        auth.status === 'active' &&
        ((auth.coreDeviceId === deviceId && auth.terminalDeviceId === peerDeviceId) ||
          (auth.terminalDeviceId === deviceId && auth.coreDeviceId === peerDeviceId))
    );
    if (!isPeerAuthorized) {
      return jsonResponse(403, {
        valid: false,
        code: 'PEER_NOT_AUTHORIZED',
        authUid: tokenCheck.uid,
        device: outcome.device,
        reason: 'No existe una autorización activa entre estos dos dispositivos.'
      });
    }
  }

  return jsonResponse(
    200,
    {
      valid: true,
      authUid: tokenCheck.uid,
      device: outcome.device,
      activeLink: outcome.activeLink || null,
      activeAuthorization: outcome.activeAuthorization || null
    },
    { 'Cache-Control': 'no-store' }
  );
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleVerifyDeviceToken(context);
};
