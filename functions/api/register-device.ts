import {
  createFirestoreRestDeviceStore,
  DeviceTransactionStore,
  registerDeviceAtomic,
  validateDeviceRegistrationPayload
} from '../../cloudflare/shared/deviceAuthService';
import {
  createFirestoreRestClient,
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../../cloudflare/shared/firebaseRest';
import { jsonResponse, parseJsonBody } from '../../cloudflare/shared/http';
import { verifySubscriptionPass } from '../../cloudflare/shared/subscriptionAccess';
import type { CloudflareEnv, CloudflarePagesContext } from '../../cloudflare/shared/types';

export interface RegisterDeviceDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getDeviceStore?: (env: CloudflareEnv) => DeviceTransactionStore;
  nowProvider?: () => Date;
}

export async function handleRegisterDevice(
  context: CloudflarePagesContext,
  deps: RegisterDeviceDeps = {}
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

  const parsed = await parseJsonBody(request);
  if (!parsed.ok) {
    return jsonResponse(400, {
      success: false,
      error: 'Cuerpo JSON inválido.'
    });
  }

  const validation = await validateDeviceRegistrationPayload(parsed.data);
  if (!validation.valid || !validation.sanitized) {
    return jsonResponse(400, {
      success: false,
      code: validation.code,
      error: validation.reason
    });
  }

  try {
    const store = deps.getDeviceStore
      ? deps.getDeviceStore(env)
      : createFirestoreRestDeviceStore(createFirestoreRestClient(env));
    const now = deps.nowProvider ? deps.nowProvider() : new Date();

    let verifiedSubscriptionUid: string | null = null;
    if (
      typeof parsed.data.subscriptionPass === 'string' &&
      parsed.data.subscriptionPass.trim()
    ) {
      const passRes = await verifySubscriptionPass(
        parsed.data.subscriptionPass,
        now,
        undefined,
        env
      );
      if (passRes.valid && passRes.uid) {
        verifiedSubscriptionUid = passRes.uid;
      }
    }

    const outcome = await registerDeviceAtomic(
      store,
      tokenCheck.uid,
      validation.sanitized,
      now,
      verifiedSubscriptionUid
    );

    if (!outcome.ok) {
      return jsonResponse(outcome.statusCode, {
        success: false,
        code: outcome.code,
        error: outcome.reason
      });
    }

    return jsonResponse(
      outcome.statusCode,
      {
        success: true,
        device: outcome.device
      },
      { 'Cache-Control': 'no-store' }
    );
  } catch (err: any) {
    return jsonResponse(500, {
      success: false,
      error: `Error registrando dispositivo en Firestore: ${err?.message || err}`
    });
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleRegisterDevice(context);
};
