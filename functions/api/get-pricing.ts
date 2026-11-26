import {
  buildBloggerCorsHeaders,
  isOriginAllowedForBlogger
} from '../../cloudflare/shared/corsBlogger';
import {
  getFirebaseAdminPendingConfigResponse,
  hasFirebaseAdminCredentials
} from '../../cloudflare/shared/firebaseRest';
import { emptyResponse, getRequestHost, jsonResponse } from '../../cloudflare/shared/http';
import { getCurrentPricing, PricingUnavailableError } from '../../cloudflare/shared/pricingService';
import type { CloudflareEnv, CloudflarePagesContext, PricingConfig } from '../../cloudflare/shared/types';

export interface GetPricingDeps {
  getPricing?: (env: CloudflareEnv) => Promise<PricingConfig>;
}

export async function handleGetPricing(
  context: CloudflarePagesContext,
  deps: GetPricingDeps = {}
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

  if (request.method !== 'GET') {
    return jsonResponse(
      405,
      {
        error: 'Método no permitido. Utilizar GET.'
      },
      corsHeaders
    );
  }

  if (!deps.getPricing && !hasFirebaseAdminCredentials(env)) {
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
    const getPricingFn = deps.getPricing || ((e: CloudflareEnv) => getCurrentPricing(e));
    const pricing = await getPricingFn(env);

    return jsonResponse(
      200,
      {
        success: true,
        pricing: {
          monto: pricing.monto,
          moneda: pricing.moneda,
          periodicidad: pricing.periodicidad,
          actualizadoEl: pricing.actualizadoEl
        }
      },
      {
        ...corsHeaders,
        'Cache-Control': 'public, max-age=60'
      }
    );
  } catch (err: any) {
    if (err instanceof PricingUnavailableError || err?.code === 'PRICING_UNAVAILABLE') {
      return jsonResponse(
        503,
        {
          success: false,
          retryable: err?.retryable ?? true,
          error: err?.message || 'Tarifa vigente no configurada o temporalmente no disponible.'
        },
        corsHeaders
      );
    }

    return jsonResponse(
      500,
      {
        error: 'Error obteniendo precio vigente.'
      },
      corsHeaders
    );
  }
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleGetPricing(context);
};
