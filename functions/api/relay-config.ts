import { jsonResponse } from '../../cloudflare/shared/http';
import type { CloudflarePagesContext } from '../../cloudflare/shared/types';

export async function handleRelayConfig(context: CloudflarePagesContext): Promise<Response> {
  const { request, env = {} } = context;

  if (request.method !== 'GET') {
    return jsonResponse(405, {
      configured: false,
      wssUrl: null,
      error: 'Método no permitido. Utilizar GET.'
    });
  }

  const cleanEnvValue = (val?: string) =>
    String(val || '')
      .trim()
      .replace(/^["']|["']$/g, '')
      .trim();

  const rawServerUrl = cleanEnvValue(env.VEL_RELAY_WSS_URL);
  const rawViteUrl = cleanEnvValue(env.VITE_VEL_RELAY_WSS_URL);

  const resolved = rawServerUrl || rawViteUrl;
  const isValidWsUrl = /^wss?:\/\/.+/i.test(resolved);

  if (!isValidWsUrl) {
    return jsonResponse(
      200,
      {
        configured: false,
        wssUrl: null,
        source: 'none',
        message:
          'Relay WebSocket pendiente de despliegue y configuración (definir VEL_RELAY_WSS_URL en Cloudflare Pages como variable de entorno de ejecución).'
      },
      { 'Cache-Control': 'no-store' }
    );
  }

  return jsonResponse(
    200,
    {
      configured: true,
      wssUrl: resolved.replace(/\/+$/, ''),
      source: rawServerUrl ? 'env' : 'vite_env'
    },
    { 'Cache-Control': 'no-store' }
  );
}

export const onRequest = async (context: CloudflarePagesContext): Promise<Response> => {
  return handleRelayConfig(context);
};
