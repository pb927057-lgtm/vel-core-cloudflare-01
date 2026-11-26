import { onRequest as accountOnRequest } from '../functions/api/account';
import { onRequest as adminPricingOnRequest } from '../functions/api/admin-pricing';
import { onRequest as cancelSubscriptionOnRequest } from '../functions/api/cancel-subscription';
import { onRequest as createPreferenceOnRequest } from '../functions/api/create-preference';
import { onRequest as createSubscriptionOnRequest } from '../functions/api/create-subscription';
import { onRequest as deviceSessionOnRequest } from '../functions/api/device-session';
import { onRequest as downloadPackageOnRequest } from '../functions/api/download-package';
import { onRequest as getPricingOnRequest } from '../functions/api/get-pricing';
import { onRequest as mercadopagoWebhookOnRequest } from '../functions/api/mercadopago-webhook';
import { onRequest as pairingConfirmOnRequest } from '../functions/api/pairing-confirm';
import { onRequest as paymentWebhookOnRequest } from '../functions/api/payment-webhook';
import { onRequest as registerDeviceOnRequest } from '../functions/api/register-device';
import { onRequest as relayConfigOnRequest } from '../functions/api/relay-config';
import { onRequest as revokeDeviceOnRequest } from '../functions/api/revoke-device';
import { onRequest as verifyDeviceTokenOnRequest } from '../functions/api/verify-device-token';
import { jsonResponse } from './shared/http';
import type { CloudflareEnv, CloudflarePagesContext } from './shared/types';

export interface WorkerAssetsBinding {
  fetch(request: Request | string, init?: RequestInit): Promise<Response>;
}

export interface VelWorkerEnv {
  ASSETS?: WorkerAssetsBinding;
  [key: string]: unknown;
}

export type PagesApiHandler = (context: CloudflarePagesContext) => Promise<Response>;

export const WORKER_API_ROUTES = new Map<string, PagesApiHandler>([
  ['/api/account', accountOnRequest],
  ['/api/admin-pricing', adminPricingOnRequest],
  ['/api/cancel-subscription', cancelSubscriptionOnRequest],
  ['/api/create-preference', createPreferenceOnRequest],
  ['/api/create-subscription', createSubscriptionOnRequest],
  ['/api/device-session', deviceSessionOnRequest],
  ['/api/download-package', downloadPackageOnRequest],
  ['/api/get-pricing', getPricingOnRequest],
  ['/api/mercadopago-webhook', mercadopagoWebhookOnRequest],
  ['/api/pairing-confirm', pairingConfirmOnRequest],
  ['/api/payment-webhook', paymentWebhookOnRequest],
  ['/api/register-device', registerDeviceOnRequest],
  ['/api/relay-config', relayConfigOnRequest],
  ['/api/revoke-device', revokeDeviceOnRequest],
  ['/api/verify-device-token', verifyDeviceTokenOnRequest]
]);

function normalizeApiPath(pathname: string): string {
  if (pathname.length > 1) {
    return pathname.replace(/\/+$/, '');
  }
  return pathname;
}

function toCloudflareEnv(env: VelWorkerEnv): CloudflareEnv {
  const stringEnv: CloudflareEnv = {};
  if (!env || typeof env !== 'object') {
    return stringEnv;
  }

  for (const [key, value] of Object.entries(env)) {
    if (typeof value === 'string') {
      stringEnv[key] = value;
    }
  }
  return stringEnv;
}

export default {
  async fetch(request: Request, env: VelWorkerEnv = {}): Promise<Response> {
    const url = new URL(request.url);
    const normalizedPath = normalizeApiPath(url.pathname);

    if (normalizedPath === '/api' || normalizedPath.startsWith('/api/')) {
      const handler = WORKER_API_ROUTES.get(normalizedPath);
      if (!handler) {
        return jsonResponse(
          404,
          {
            success: false,
            error: `Ruta de API no encontrada: ${normalizedPath}`
          },
          { 'Cache-Control': 'no-store' }
        );
      }

      try {
        return await handler({
          request,
          env: toCloudflareEnv(env),
          params: {}
        });
      } catch (err: any) {
        return jsonResponse(
          500,
          {
            success: false,
            error: err?.message || 'Error interno ejecutando endpoint de VEL en Cloudflare Worker.'
          },
          { 'Cache-Control': 'no-store' }
        );
      }
    }

    if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
      return env.ASSETS.fetch(request);
    }

    return jsonResponse(
      500,
      {
        success: false,
        error: 'Binding ASSETS no configurado en el Worker.'
      },
      { 'Cache-Control': 'no-store' }
    );
  }
};
