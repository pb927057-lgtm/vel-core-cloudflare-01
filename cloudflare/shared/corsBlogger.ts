import type { CloudflareEnv } from './types';

export const OFFICIAL_BLOGGER_ORIGIN = 'https://proyecto-vel.blogspot.com';
export const OFFICIAL_CLOUDFLARE_ORIGIN = 'https://proyecto-vel.pages.dev';

/**
 * Obtiene la lista estricta de orígenes externos autorizados de Blogger
 * y el mismo origen del portal VEL en Cloudflare Pages.
 * Nunca utiliza wildcard '*'.
 */
export function getAllowedBloggerOrigins(
  requestHost?: string,
  env: CloudflareEnv = {}
): string[] {
  const extra = env.BLOGGER_ORIGIN
    ? env.BLOGGER_ORIGIN.split(',')
        .map((o) => o.trim().replace(/\/+$/, ''))
        .filter(Boolean)
    : [];

  const samePortalOrigins: string[] = [OFFICIAL_CLOUDFLARE_ORIGIN];
  if (env.APP_BASE_URL) {
    samePortalOrigins.push(env.APP_BASE_URL.trim().replace(/\/+$/, ''));
  }
  if (requestHost && requestHost.trim()) {
    const cleanHost = requestHost.trim().replace(/\/+$/, '');
    const protocol =
      cleanHost.includes('localhost') || cleanHost.startsWith('127.0.0.1') ? 'http' : 'https';
    samePortalOrigins.push(`${protocol}://${cleanHost}`);
  }

  return Array.from(new Set([OFFICIAL_BLOGGER_ORIGIN, ...extra, ...samePortalOrigins]));
}

export function isOriginAllowedForBlogger(
  origin: string | undefined,
  requestHost?: string,
  env: CloudflareEnv = {}
): boolean {
  if (!origin) return false;
  const normalized = origin.trim().replace(/\/+$/, '');
  return getAllowedBloggerOrigins(requestHost, env).includes(normalized);
}

/**
 * Construye encabezados CORS exclusivamente para el origen de Blogger autorizado
 * o para el mismo origen del portal VEL en Cloudflare.
 */
export function buildBloggerCorsHeaders(
  origin: string | undefined,
  requestHost?: string,
  env: CloudflareEnv = {}
): Record<string, string> {
  const baseHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    Vary: 'Origin'
  };

  if (origin && isOriginAllowedForBlogger(origin, requestHost, env)) {
    const normalized = origin.trim().replace(/\/+$/, '');
    return {
      ...baseHeaders,
      'Access-Control-Allow-Origin': normalized,
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Max-Age': '86400'
    };
  }

  return baseHeaders;
}
