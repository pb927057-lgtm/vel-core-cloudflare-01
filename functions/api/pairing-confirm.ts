import {
  confirmDevicePairingAtomic,
  createFirestoreRestDeviceStore,
  DeviceTransactionStore
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

export interface PairingConfirmDeps {
  verifyToken?: (authHeader?: string, env?: CloudflareEnv) => Promise<TokenVerificationResult>;
  hasDbCredentials?: (env?: CloudflareEnv) => boolean;
  getDeviceStore?: (env: CloudflareEnv) => DeviceTransactionStore;
  nowProvider?: () => Date;
}

export async function handlePairingConfirm(
  context: CloudflarePagesContext,
  deps: PairingConfirmDeps = {}
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

    const outcome = await confirmDevicePairingAtomic(
      store,
      tokenCheck.uid,
      {
        linkId: String(body.linkId || '').trim(),
        coreDeviceId: String(body.coreDeviceId || '').trim(),
        terminalDeviceId: String(body.terminalDeviceId || '').trim(),
        corePublicKeySpkiBase64: body.corePublicKeySpkiBase64
          ? String(body.corePublicKeySpkiBase64)
          : undefined,
        terminalPublicKeySpkiBase64: body.terminalPublicKeySpkiBase64
          ? String(body.terminalPublicKeySpkiBase64)
          : undefined,
        sasVerified: body.sasVerified === true
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
        coreDevice: outcome.coreDevice,
        terminalDevice: outcome.terminalDevice,
        link: outcome.link,
        authorization: outcome.authorization
      },
      { 'Cache-Control': 'no-store' }
    );
  } catch (err: any) {
    return jsonResponse(500, {
      success: false,
      error: `Error confirmando vinculación en Firestore: ${err?.message || err}`
    });
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handlePairingConfirm(context);
};
