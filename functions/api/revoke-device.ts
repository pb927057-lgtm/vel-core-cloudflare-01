import {
  createFirestoreRestDeviceStore,
  DeviceTransactionStore,
  revokeDeviceAuthorizationAtomic
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

export interface RevokeDeviceDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getDeviceStore?: (env: CloudflareEnv) => DeviceTransactionStore;
  nowProvider?: () => Date;
}

export async function handleRevokeDevice(
  context: CloudflarePagesContext,
  deps: RevokeDeviceDeps = {}
): Promise<Response> {
  const { request, env = {} } = context;

  if (request.method !== 'POST') {
    return jsonResponse(405, {
      success: false,
      error: 'Método no permitido. Utilizar POST.'
    });
  }

  const authHeader = request.headers.get('authorization') ?? undefined;
  const verifyTokenFn = deps.verifyToken || ((hdr?: string) => verifyUserTokenStrict(hdr, env));
  const tokenCheck = await verifyTokenFn(authHeader, env);

  if (!tokenCheck.authenticated) {
    const isPending = tokenCheck.reason === 'pending_config';
    return jsonResponse(isPending ? 503 : 401, {
      success: false,
      pendingConfig: isPending,
      ...(isPending
        ? {
            configReason: tokenCheck.configReason,
            missingVariables: tokenCheck.missingVariables ?? []
          }
        : {}),
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

  const parsed = await parseJsonBody(request);
  if (!parsed.ok) {
    return jsonResponse(400, {
      success: false,
      error: 'Cuerpo JSON inválido.'
    });
  }

  const body = parsed.data;

  try {
    const store = deps.getDeviceStore
      ? deps.getDeviceStore(env)
      : createFirestoreRestDeviceStore(createFirestoreRestClient(env));
    const now = deps.nowProvider ? deps.nowProvider() : new Date();

    const outcome = await revokeDeviceAuthorizationAtomic(
      store,
      tokenCheck.uid,
      {
        coreDeviceId: String(body.coreDeviceId || '').trim(),
        targetTerminalId: body.targetTerminalId ? String(body.targetTerminalId).trim() : null,
        reason: body.reason ? String(body.reason) : undefined
      },
      now
    );

    if (!outcome.ok) {
      return jsonResponse(
        outcome.statusCode,
        {
          success: false,
          code: outcome.code,
          error: outcome.reason
        },
        { 'Cache-Control': 'no-store' }
      );
    }

    return jsonResponse(
      200,
      {
        success: true,
        revokedTerminalId: outcome.revokedTerminalId,
        revokedLinkId: outcome.revokedLinkId,
        coreDevice: outcome.coreDevice
      },
      { 'Cache-Control': 'no-store' }
    );
  } catch (err: any) {
    return jsonResponse(500, {
      success: false,
      error: `Error revocando autorización en Firestore: ${err?.message || err}`
    });
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleRevokeDevice(context);
};
