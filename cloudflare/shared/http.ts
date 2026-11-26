export function jsonResponse(
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): Response {
  const headers = new Headers(extraHeaders);
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  return new Response(JSON.stringify(body), { status, headers });
}

export function emptyResponse(
  status: number,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(null, { status, headers: extraHeaders });
}

export function redirectResponse(
  location: string,
  extraHeaders: Record<string, string> = {}
): Response {
  const headers = new Headers(extraHeaders);
  headers.set('Location', location);
  return new Response(null, { status: 302, headers });
}

export function getRequestHost(request: Request): string {
  const headerHost =
    request.headers.get('x-forwarded-host') ||
    request.headers.get('host');
  if (headerHost && headerHost.trim()) {
    return headerHost.split(',')[0].trim();
  }
  try {
    return new URL(request.url).host;
  } catch {
    return '';
  }
}

export function getQueryParams(request: Request): Record<string, string> {
  const params: Record<string, string> = {};
  try {
    const url = new URL(request.url);
    url.searchParams.forEach((value, key) => {
      params[key] = value;
    });
  } catch {
    // URL inválida
  }
  return params;
}

export async function parseJsonBody(
  request: Request
): Promise<{ ok: true; data: Record<string, any> } | { ok: false }> {
  try {
    const text = await request.text();
    if (!text.trim()) {
      return { ok: true, data: {} };
    }
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false };
    }
    return { ok: true, data: parsed as Record<string, any> };
  } catch {
    return { ok: false };
  }
}
