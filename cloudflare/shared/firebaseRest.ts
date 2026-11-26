import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToUtf8,
  toExactArrayBuffer,
  utf8ToBytes
} from './webCrypto';
import type { CloudflareEnv } from './types';

export const AUTHORIZED_ADMIN_EMAILS = [
  'admin@vel.com',
  'soporte@vel.com',
  'pb927057@gmail.com'
];

const PKCS8_BEGIN_MARKER = '-----BEGIN PRIVATE KEY-----';
const PKCS8_END_MARKER = '-----END PRIVATE KEY-----';
const FIREBASE_JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const GOOGLE_OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_SERVICE_SCOPES =
  'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/identitytoolkit';

export type FirebaseAdminConfigIssueReason =
  | 'missing_env'
  | 'incomplete_env'
  | 'invalid_service_account'
  | 'invalid_private_key'
  | 'init_error';

export class FirebaseAdminConfigError extends Error {
  public readonly code = 'FIREBASE_ADMIN_CONFIG_ERROR';
  public readonly configReason: FirebaseAdminConfigIssueReason;
  public readonly missingVariables: string[];

  constructor(
    message: string,
    configReason: FirebaseAdminConfigIssueReason = 'init_error',
    missingVariables: string[] = []
  ) {
    super(message);
    this.name = 'FirebaseAdminConfigError';
    this.configReason = configReason;
    this.missingVariables = missingVariables;
  }
}

export interface ParsedServiceAccount {
  projectId: string;
  clientEmail: string;
  privateKey: string;
}

export interface FirebaseAdminConfigDiagnostics {
  ok: boolean;
  reason?: FirebaseAdminConfigIssueReason;
  missingVariables: string[];
  error?: string;
  credentials?: ParsedServiceAccount;
}

function stripMatchingOuterQuotes(value: string): string {
  let out = value.trim();
  while (
    out.length >= 2 &&
    ((out.startsWith('"') && out.endsWith('"')) || (out.startsWith("'") && out.endsWith("'")))
  ) {
    out = out.slice(1, -1).trim();
  }
  return out;
}

function tryDecodeServiceAccountJson(raw: string): Record<string, any> | null {
  const cleaned = stripMatchingOuterQuotes(String(raw || ''));
  if (!cleaned) return null;

  if (cleaned.startsWith('{')) {
    const parsed = JSON.parse(cleaned);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed;
    }
    return null;
  }

  const compact = cleaned.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact) || compact.length < 16) {
    return null;
  }

  const normalizedB64 = compact.replace(/-/g, '+').replace(/_/g, '/');
  const paddedB64 =
    normalizedB64.length % 4 === 0
      ? normalizedB64
      : normalizedB64 + '='.repeat(4 - (normalizedB64.length % 4));

  const decoded = bytesToUtf8(base64ToBytes(paddedB64)).trim();
  if (!decoded.startsWith('{')) {
    return null;
  }

  const parsed = JSON.parse(decoded);
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    return parsed;
  }
  return null;
}

function isPlausiblePkcs8Der(bytes: Uint8Array): boolean {
  // PKCS#8 PrivateKeyInfo siempre inicia con ASN.1 SEQUENCE (0x30) y contiene al menos versión + AlgorithmIdentifier + OctetString
  if (bytes.length < 64 || bytes[0] !== 0x30) return false;
  const lenByte = bytes[1];
  if (lenByte < 0x80) {
    return bytes.length === 2 + lenByte;
  }
  const numLenBytes = lenByte & 0x7f;
  if (numLenBytes === 0 || numLenBytes > 3 || 2 + numLenBytes > bytes.length) {
    return false;
  }
  let declaredLen = 0;
  for (let i = 0; i < numLenBytes; i++) {
    declaredLen = (declaredLen << 8) | bytes[2 + i];
  }
  return bytes.length === 2 + numLenBytes + declaredLen;
}

/**
 * Normaliza y valida estrictamente una clave privada PKCS#8 sin depender de módulos Node.
 */
export function normalizePemPrivateKey(rawKey: string, depth: number = 0): string {
  if (depth > 1) {
    throw new FirebaseAdminConfigError(
      'Formato inválido de clave privada PKCS#8.',
      'invalid_private_key',
      []
    );
  }

  let key = stripMatchingOuterQuotes(String(rawKey || ''));
  if (!key) {
    throw new FirebaseAdminConfigError(
      'La clave privada de Firebase está vacía.',
      'invalid_private_key',
      []
    );
  }

  if (key.startsWith('{') || !key.includes('-----BEGIN')) {
    try {
      const parsedJson = tryDecodeServiceAccountJson(key);
      if (parsedJson && typeof parsedJson.private_key === 'string') {
        return normalizePemPrivateKey(parsedJson.private_key, depth + 1);
      }
      if (key.startsWith('{')) {
        throw new FirebaseAdminConfigError(
          'El JSON de cuenta de servicio no contiene un campo private_key válido.',
          'invalid_service_account',
          []
        );
      }
    } catch (err: any) {
      if (err instanceof FirebaseAdminConfigError) throw err;
      throw new FirebaseAdminConfigError(
        'No se pudo interpretar el JSON/Base64 de la cuenta de servicio de Firebase.',
        'invalid_service_account',
        []
      );
    }
  }

  key = key
    .replace(/\\\\r\\\\n/g, '\n')
    .replace(/\\\\n/g, '\n')
    .replace(/\\r\\n/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .trim();

  const firstBegin = key.indexOf(PKCS8_BEGIN_MARKER);
  const lastBegin = key.lastIndexOf(PKCS8_BEGIN_MARKER);
  const firstEnd = key.indexOf(PKCS8_END_MARKER);
  const lastEnd = key.lastIndexOf(PKCS8_END_MARKER);

  if (firstBegin === -1 || firstEnd === -1) {
    throw new FirebaseAdminConfigError(
      'La clave privada no tiene formato PEM PKCS#8 válido (faltan cabeceras BEGIN/END PRIVATE KEY).',
      'invalid_private_key',
      []
    );
  }

  if (firstBegin !== lastBegin || firstEnd !== lastEnd || firstEnd <= firstBegin) {
    throw new FirebaseAdminConfigError(
      'La clave privada PEM contiene marcadores duplicados o desordenados.',
      'invalid_private_key',
      []
    );
  }

  const prefixOutside = key.slice(0, firstBegin).trim();
  const suffixOutside = key.slice(firstEnd + PKCS8_END_MARKER.length).trim();
  if (prefixOutside.length > 0 || suffixOutside.length > 0) {
    throw new FirebaseAdminConfigError(
      'La clave privada PEM contiene datos inesperados fuera de las cabeceras PKCS#8.',
      'invalid_private_key',
      []
    );
  }

  const rawBody = key.slice(firstBegin + PKCS8_BEGIN_MARKER.length, firstEnd);
  const cleanBody = rawBody.replace(/\s+/g, '');

  if (
    !cleanBody ||
    cleanBody.length < 64 ||
    cleanBody.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(cleanBody)
  ) {
    throw new FirebaseAdminConfigError(
      'El cuerpo Base64 de la clave privada PEM está incompleto, truncado o contiene caracteres inválidos.',
      'invalid_private_key',
      []
    );
  }

  let derBytes: Uint8Array;
  try {
    derBytes = base64ToBytes(cleanBody);
  } catch {
    throw new FirebaseAdminConfigError(
      'No se pudo decodificar el cuerpo Base64 de la clave privada PKCS#8.',
      'invalid_private_key',
      []
    );
  }

  if (!isPlausiblePkcs8Der(derBytes)) {
    throw new FirebaseAdminConfigError(
      'La clave privada PEM PKCS#8 está truncada, corrupta o no tiene estructura ASN.1 PKCS#8 válida.',
      'invalid_private_key',
      []
    );
  }

  const wrappedLines = cleanBody.match(/.{1,64}/g);
  if (!wrappedLines || wrappedLines.length === 0) {
    throw new FirebaseAdminConfigError(
      'No se pudo reconstruir el bloque Base64 de la clave privada PEM.',
      'invalid_private_key',
      []
    );
  }

  return `${PKCS8_BEGIN_MARKER}\n${wrappedLines.join('\n')}\n${PKCS8_END_MARKER}\n`;
}

function pemToPkcs8Bytes(canonicalPem: string): Uint8Array {
  const cleanBody = canonicalPem
    .replace(PKCS8_BEGIN_MARKER, '')
    .replace(PKCS8_END_MARKER, '')
    .replace(/\s+/g, '');
  return base64ToBytes(cleanBody);
}

export function inspectFirebaseAdminConfig(
  env: CloudflareEnv = {}
): FirebaseAdminConfigDiagnostics {
  const defaultProjectId = String(env.FIREBASE_PROJECT_ID || 'proyecto-vel').trim() || 'proyecto-vel';
  const serviceAccountEnv = String(env.FIREBASE_SERVICE_ACCOUNT || '').trim();

  if (serviceAccountEnv) {
    let parsed: Record<string, any> | null = null;
    try {
      parsed = tryDecodeServiceAccountJson(serviceAccountEnv);
    } catch {
      return {
        ok: false,
        reason: 'invalid_service_account',
        missingVariables: [],
        error: 'FIREBASE_SERVICE_ACCOUNT contiene JSON/Base64 inválido.'
      };
    }

    if (!parsed) {
      return {
        ok: false,
        reason: 'invalid_service_account',
        missingVariables: [],
        error: 'FIREBASE_SERVICE_ACCOUNT no contiene un objeto JSON o Base64 válido de cuenta de servicio.'
      };
    }

    const clientEmail = String(parsed.client_email || '').trim();
    const rawPrivateKey = String(parsed.private_key || '');
    const projectId = String(parsed.project_id || defaultProjectId).trim() || defaultProjectId;

    if (!clientEmail || !rawPrivateKey) {
      return {
        ok: false,
        reason: 'invalid_service_account',
        missingVariables: [],
        error: 'FIREBASE_SERVICE_ACCOUNT está incompleto: falta client_email o private_key dentro del JSON.'
      };
    }

    try {
      const privateKey = normalizePemPrivateKey(rawPrivateKey);
      return {
        ok: true,
        missingVariables: [],
        credentials: { projectId, clientEmail, privateKey }
      };
    } catch (err: any) {
      return {
        ok: false,
        reason: err?.configReason || 'invalid_private_key',
        missingVariables: [],
        error: `La clave private_key dentro de FIREBASE_SERVICE_ACCOUNT es inválida o está truncada: ${err?.message || 'formato PEM incorrecto.'}`
      };
    }
  }

  const clientEmail = String(env.FIREBASE_CLIENT_EMAIL || '').trim();
  const rawPrivateKey = String(env.FIREBASE_PRIVATE_KEY || '').trim();

  if (clientEmail || rawPrivateKey) {
    const missing: string[] = [];
    if (!clientEmail) missing.push('FIREBASE_CLIENT_EMAIL');
    if (!rawPrivateKey) missing.push('FIREBASE_PRIVATE_KEY');

    if (missing.length > 0) {
      return {
        ok: false,
        reason: 'incomplete_env',
        missingVariables: missing,
        error: `Configuración incompleta de Firebase en Cloudflare: falta definir ${missing.join(', ')}.`
      };
    }

    try {
      const privateKey = normalizePemPrivateKey(rawPrivateKey);
      return {
        ok: true,
        missingVariables: [],
        credentials: {
          projectId: defaultProjectId,
          clientEmail,
          privateKey
        }
      };
    } catch (err: any) {
      return {
        ok: false,
        reason: err?.configReason || 'invalid_private_key',
        missingVariables: [],
        error: `FIREBASE_PRIVATE_KEY tiene un formato inválido o está truncada: ${err?.message || 'clave PEM PKCS#8 no válida.'}`
      };
    }
  }

  return {
    ok: false,
    reason: 'missing_env',
    missingVariables: ['FIREBASE_SERVICE_ACCOUNT'],
    error:
      'Variables de entorno faltantes en Cloudflare: falta configurar FIREBASE_SERVICE_ACCOUNT (o FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY).'
  };
}

export function getFirebaseAdminPendingConfigResponse(env: CloudflareEnv = {}): {
  pendingConfig: boolean;
  configReason?: FirebaseAdminConfigIssueReason;
  missingVariables: string[];
  error: string;
} {
  const diag = inspectFirebaseAdminConfig(env);
  if (!diag.ok) {
    return {
      pendingConfig: true,
      configReason: diag.reason || 'missing_env',
      missingVariables: diag.missingVariables,
      error:
        diag.error ||
        'Configuración de credenciales de servidor Firebase pendiente o inválida en Cloudflare.'
    };
  }

  return {
    pendingConfig: false,
    missingVariables: [],
    error: ''
  };
}

export function hasFirebaseAdminCredentials(env: CloudflareEnv = {}): boolean {
  return inspectFirebaseAdminConfig(env).ok;
}

// =============================================================================
// 1. VERIFICACIÓN OFICIAL DE FIREBASE ID TOKENS (WEB CRYPTO + GOOGLE JWKS)
// =============================================================================

export type TokenVerificationResult =
  | {
      authenticated: true;
      uid: string;
      email: string;
      claims: Record<string, any>;
    }
  | {
      authenticated: false;
      reason: 'missing_token' | 'invalid_token' | 'pending_config' | 'internal_error';
      message: string;
      configReason?: FirebaseAdminConfigIssueReason;
      missingVariables?: string[];
    };

interface CachedJwks {
  keysByKid: Map<string, JsonWebKey>;
  expiresAtMs: number;
}

let jwksCache: CachedJwks | null = null;

function parseMaxAgeFromCacheControl(headerValue: string | null): number {
  if (!headerValue) return 3600;
  const match = headerValue.match(/max-age=(\d+)/i);
  if (!match) return 3600;
  const sec = Number(match[1]);
  return Number.isFinite(sec) && sec > 0 ? sec : 3600;
}

async function getFirebasePublicJwk(
  kid: string,
  fetchFn: typeof fetch = fetch,
  nowMs: number = Date.now()
): Promise<JsonWebKey | null> {
  if (jwksCache && nowMs < jwksCache.expiresAtMs) {
    const cachedKey = jwksCache.keysByKid.get(kid);
    if (cachedKey) return cachedKey;
  }

  const res = await fetchFn(FIREBASE_JWKS_URL, { method: 'GET' });
  if (!res.ok) {
    throw new Error(`No se pudieron obtener las claves públicas de Google JWKS (HTTP ${res.status}).`);
  }
  const body = (await res.json()) as { keys?: Array<JsonWebKey & { kid?: string }> };
  const keysList = Array.isArray(body?.keys) ? body.keys : [];
  const nextMap = new Map<string, JsonWebKey>();
  for (const k of keysList) {
    if (k && typeof k.kid === 'string') {
      nextMap.set(k.kid, k);
    }
  }
  const maxAgeSec = parseMaxAgeFromCacheControl(res.headers.get('cache-control'));
  jwksCache = {
    keysByKid: nextMap,
    expiresAtMs: nowMs + maxAgeSec * 1000
  };
  return nextMap.get(kid) || null;
}

export function clearFirebaseJwksCacheForTests(): void {
  jwksCache = null;
}

export interface VerifyFirebaseTokenOptions {
  projectId?: string;
  nowMs?: number;
  fetchFn?: typeof fetch;
}

/**
 * Verifica un Firebase ID Token según la especificación oficial de Firebase Authentication:
 * https://firebase.google.com/docs/auth/admin/verify-id-tokens
 * utilizando Web Crypto API (RSASSA-PKCS1-v1_5 SHA-256) y las claves públicas JWKS de Google.
 */
export async function verifyUserTokenStrict(
  authHeader?: string,
  env: CloudflareEnv = {},
  options: VerifyFirebaseTokenOptions = {}
): Promise<TokenVerificationResult> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      authenticated: false,
      reason: 'missing_token',
      message: 'No autorizado. Debes iniciar sesión para continuar.'
    };
  }

  const token = authHeader.substring(7).trim();
  if (!token) {
    return {
      authenticated: false,
      reason: 'missing_token',
      message: 'Token de sesión vacío.'
    };
  }

  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'Formato de token Firebase inválido.'
    };
  }

  let header: Record<string, any>;
  let payload: Record<string, any>;
  let signatureBytes: Uint8Array;

  try {
    header = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[0])));
    payload = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[1])));
    signatureBytes = base64UrlToBytes(parts[2]);
  } catch {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'Token de Firebase mal formado.'
    };
  }

  const projectId =
    String(options.projectId || env.FIREBASE_PROJECT_ID || 'proyecto-vel').trim() || 'proyecto-vel';
  const nowMs = options.nowMs ?? Date.now();
  const nowSec = Math.floor(nowMs / 1000);

  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid.trim()) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'Cabecera criptográfica de token Firebase inválida.'
    };
  }

  if (payload.aud !== projectId) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'La audiencia del token no corresponde al proyecto VEL.'
    };
  }

  if (payload.iss !== `https://securetoken.google.com/${projectId}`) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'El emisor (iss) del token de Firebase es inválido.'
    };
  }

  if (typeof payload.sub !== 'string' || !payload.sub.trim() || payload.sub.length > 128) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'El identificador de usuario (sub) del token es inválido.'
    };
  }

  if (typeof payload.exp !== 'number' || payload.exp <= nowSec) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'Token de Firebase expirado.'
    };
  }

  if (typeof payload.iat !== 'number' || payload.iat > nowSec + 300) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'Marca temporal iat del token de Firebase inválida.'
    };
  }

  if (typeof payload.auth_time === 'number' && payload.auth_time > nowSec + 300) {
    return {
      authenticated: false,
      reason: 'invalid_token',
      message: 'Marca temporal auth_time del token de Firebase inválida.'
    };
  }

  try {
    const fetchFn = options.fetchFn || fetch;
    const jwk = await getFirebasePublicJwk(header.kid, fetchFn, nowMs);
    if (!jwk) {
      return {
        authenticated: false,
        reason: 'invalid_token',
        message: 'La clave pública de firma del token no es reconocida por Firebase.'
      };
    }

    const publicKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signedData = utf8ToBytes(`${parts[0]}.${parts[1]}`);
    const verified = await globalThis.crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      publicKey,
      toExactArrayBuffer(signatureBytes),
      toExactArrayBuffer(signedData)
    );

    if (!verified) {
      return {
        authenticated: false,
        reason: 'invalid_token',
        message: 'La firma del token de Firebase no es válida.'
      };
    }

    return {
      authenticated: true,
      uid: payload.sub,
      email: typeof payload.email === 'string' ? payload.email : '',
      claims: payload
    };
  } catch (err: any) {
    return {
      authenticated: false,
      reason: 'internal_error',
      message: `Error de conexión validando el token de Firebase: ${err?.message || err}`
    };
  }
}

export async function verifyUserToken(
  authHeader?: string,
  env: CloudflareEnv = {}
): Promise<{ uid: string; email?: string; claims?: Record<string, any> } | null> {
  const result = await verifyUserTokenStrict(authHeader, env);
  if (!result.authenticated) return null;
  return {
    uid: result.uid,
    email: result.email,
    claims: result.claims
  };
}

export function isUserAdmin(email?: string, customClaims?: any): boolean {
  if (customClaims && customClaims.admin === true) {
    return true;
  }
  if (!email) return false;
  const cleanEmail = email.toLowerCase().trim();
  return AUTHORIZED_ADMIN_EMAILS.includes(cleanEmail);
}

// =============================================================================
// 2. AUTENTICACIÓN DE CUENTA DE SERVICIO GOOGLE OAUTH2 (WEB CRYPTO RS256)
// =============================================================================

interface CachedOAuthToken {
  accessToken: string;
  expiresAtMs: number;
}

const oauthTokenCache = new Map<string, CachedOAuthToken>();

export function clearOAuthTokenCacheForTests(): void {
  oauthTokenCache.clear();
}

export async function getGoogleAccessToken(
  credentials: ParsedServiceAccount,
  fetchFn: typeof fetch = fetch,
  nowMs: number = Date.now(),
  scope: string = GOOGLE_SERVICE_SCOPES
): Promise<string> {
  const cacheKey = `${credentials.projectId}|${credentials.clientEmail}|${scope}`;
  const cached = oauthTokenCache.get(cacheKey);
  if (cached && nowMs < cached.expiresAtMs) {
    return cached.accessToken;
  }

  let signingKey: CryptoKey;
  try {
    const pkcs8Bytes = pemToPkcs8Bytes(credentials.privateKey);
    signingKey = await globalThis.crypto.subtle.importKey(
      'pkcs8',
      toExactArrayBuffer(pkcs8Bytes),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
  } catch (err: any) {
    throw new FirebaseAdminConfigError(
      `No se pudo importar la clave privada PKCS#8 en Web Crypto: ${err?.message || err}`,
      'invalid_private_key',
      []
    );
  }

  const nowSec = Math.floor(nowMs / 1000);
  const headerB64 = bytesToBase64Url(utf8ToBytes(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claimB64 = bytesToBase64Url(
    utf8ToBytes(
      JSON.stringify({
        iss: credentials.clientEmail,
        scope,
        aud: GOOGLE_OAUTH_TOKEN_URL,
        iat: nowSec,
        exp: nowSec + 3600
      })
    )
  );
  const unsigned = `${headerB64}.${claimB64}`;
  const sigBuf = await globalThis.crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    signingKey,
    toExactArrayBuffer(utf8ToBytes(unsigned))
  );
  const assertion = `${unsigned}.${bytesToBase64Url(new Uint8Array(sigBuf))}`;

  const body = `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${encodeURIComponent(assertion)}`;
  const res = await fetchFn(GOOGLE_OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });

  const data = (await res.json().catch(() => ({}))) as Record<string, any>;
  if (!res.ok || !data.access_token) {
    throw new FirebaseAdminConfigError(
      `No se pudo obtener token OAuth2 para Firestore REST (${res.status}): ${data.error_description || data.error || 'error desconocido'}`,
      'init_error',
      []
    );
  }

  const expiresInSec = Number(data.expires_in || 3600);
  oauthTokenCache.set(cacheKey, {
    accessToken: String(data.access_token),
    expiresAtMs: nowMs + Math.max(60, expiresInSec - 120) * 1000
  });

  return String(data.access_token);
}

// =============================================================================
// 3. CLIENTE OFICIAL CLOUD FIRESTORE REST API (CON TRANSACCIONES ATÓMICAS)
// =============================================================================

export type FirestoreRestValue =
  | { nullValue: null }
  | { booleanValue: boolean }
  | { integerValue: string }
  | { doubleValue: number }
  | { timestampValue: string }
  | { stringValue: string }
  | { arrayValue: { values?: FirestoreRestValue[] } }
  | { mapValue: { fields?: Record<string, FirestoreRestValue> } };

export function encodeFirestoreValue(value: unknown): FirestoreRestValue {
  if (value === null || value === undefined) {
    return { nullValue: null };
  }
  if (typeof value === 'boolean') {
    return { booleanValue: value };
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return { nullValue: null };
    }
    if (Number.isInteger(value) && Number.isSafeInteger(value)) {
      return { integerValue: String(value) };
    }
    return { doubleValue: value };
  }
  if (typeof value === 'string') {
    return { stringValue: value };
  }
  if (value instanceof Date) {
    return { timestampValue: value.toISOString() };
  }
  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map((item) => encodeFirestoreValue(item))
      }
    };
  }
  if (typeof value === 'object') {
    return {
      mapValue: {
        fields: encodeFirestoreFields(value as Record<string, unknown>)
      }
    };
  }
  return { stringValue: String(value) };
}

export function encodeFirestoreFields(
  obj: Record<string, unknown>
): Record<string, FirestoreRestValue> {
  const fields: Record<string, FirestoreRestValue> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) {
      fields[k] = encodeFirestoreValue(v);
    }
  }
  return fields;
}

export function decodeFirestoreValue(val: FirestoreRestValue | undefined): any {
  if (!val || typeof val !== 'object') return undefined;
  if ('nullValue' in val) return null;
  if ('booleanValue' in val) return Boolean(val.booleanValue);
  if ('integerValue' in val) return Number(val.integerValue);
  if ('doubleValue' in val) return Number(val.doubleValue);
  if ('timestampValue' in val) return val.timestampValue;
  if ('stringValue' in val) return val.stringValue;
  if ('arrayValue' in val) {
    const arr = val.arrayValue?.values;
    return Array.isArray(arr) ? arr.map((item) => decodeFirestoreValue(item)) : [];
  }
  if ('mapValue' in val) {
    return decodeFirestoreFields(val.mapValue?.fields || {});
  }
  return undefined;
}

export function decodeFirestoreFields(
  fields: Record<string, FirestoreRestValue> | undefined
): Record<string, any> {
  const out: Record<string, any> = {};
  if (!fields) return out;
  for (const [k, v] of Object.entries(fields)) {
    out[k] = decodeFirestoreValue(v);
  }
  return out;
}

function escapeFieldPath(field: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(field)
    ? field
    : `\`${field.replace(/`/g, '\\`')}\``;
}

export interface FirestoreTransactionContext {
  getDocument: <T = Record<string, any>>(relativePath: string) => Promise<T | null>;
  runQuery: <T = Record<string, any>>(
    parentRelativePath: string,
    structuredQuery: Record<string, any>
  ) => Promise<Array<{ id: string; data: T }>>;
  createDocument: (relativePath: string, data: Record<string, any>) => void;
  setDocument: (relativePath: string, data: Record<string, any>, merge?: boolean) => void;
  updateDocument: (relativePath: string, patch: Record<string, any>) => void;
}

export class FirestoreRestClient {
  public readonly projectId: string;
  private readonly credentials: ParsedServiceAccount;
  private readonly fetchFn: typeof fetch;
  private readonly documentsBaseUrl: string;
  private readonly databaseDocPrefix: string;

  constructor(credentials: ParsedServiceAccount, fetchFn: typeof fetch = fetch) {
    this.credentials = credentials;
    this.projectId = credentials.projectId;
    this.fetchFn = fetchFn;
    this.databaseDocPrefix = `projects/${this.projectId}/databases/(default)/documents`;
    this.documentsBaseUrl = `https://firestore.googleapis.com/v1/${this.databaseDocPrefix}`;
  }

  private normalizeRelativePath(relativePath: string): string {
    return relativePath.replace(/^\/+|\/+$/g, '');
  }

  private fullDocumentName(relativePath: string): string {
    const clean = this.normalizeRelativePath(relativePath);
    return clean ? `${this.databaseDocPrefix}/${clean}` : this.databaseDocPrefix;
  }

  private async requestJson(
    url: string,
    init: RequestInit
  ): Promise<{ status: number; data: any }> {
    const token = await getGoogleAccessToken(this.credentials, this.fetchFn);
    const headers = new Headers(init.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    if (init.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const res = await this.fetchFn(url, { ...init, headers });
    const text = await res.text();
    let data: any = {};
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { raw: text };
      }
    }
    return { status: res.status, data };
  }

  async getDocument<T = Record<string, any>>(
    relativePath: string,
    transactionId?: string
  ): Promise<T | null> {
    const clean = this.normalizeRelativePath(relativePath);
    const url = transactionId
      ? `${this.documentsBaseUrl}/${clean}?transaction=${encodeURIComponent(transactionId)}`
      : `${this.documentsBaseUrl}/${clean}`;

    const { status, data } = await this.requestJson(url, { method: 'GET' });
    if (status === 404) {
      return null;
    }
    if (status < 200 || status >= 300) {
      const msg = data?.error?.message || `Error Firestore GET ${clean} (HTTP ${status})`;
      throw new Error(msg);
    }
    return decodeFirestoreFields(data.fields) as T;
  }

  async setDocument(
    relativePath: string,
    docData: Record<string, any>,
    merge: boolean = false
  ): Promise<void> {
    const clean = this.normalizeRelativePath(relativePath);
    const fields = encodeFirestoreFields(docData);
    let url = `${this.documentsBaseUrl}/${clean}`;
    if (merge) {
      const params = new URLSearchParams();
      for (const key of Object.keys(fields)) {
        params.append('updateMask.fieldPaths', escapeFieldPath(key));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    const { status, data } = await this.requestJson(url, {
      method: 'PATCH',
      body: JSON.stringify({ fields })
    });

    if (status < 200 || status >= 300) {
      throw new Error(data?.error?.message || `Error Firestore SET ${clean} (HTTP ${status})`);
    }
  }

  async updateDocument(relativePath: string, patch: Record<string, any>): Promise<void> {
    const clean = this.normalizeRelativePath(relativePath);
    const fields = encodeFirestoreFields(patch);
    const keys = Object.keys(fields);
    if (keys.length === 0) return;

    const params = new URLSearchParams();
    params.set('currentDocument.exists', 'true');
    for (const key of keys) {
      params.append('updateMask.fieldPaths', escapeFieldPath(key));
    }

    const url = `${this.documentsBaseUrl}/${clean}?${params.toString()}`;
    const { status, data } = await this.requestJson(url, {
      method: 'PATCH',
      body: JSON.stringify({ fields })
    });

    if (status < 200 || status >= 300) {
      throw new Error(data?.error?.message || `Error Firestore UPDATE ${clean} (HTTP ${status})`);
    }
  }

  async addDocument(collectionRelativePath: string, docData: Record<string, any>): Promise<string> {
    const clean = this.normalizeRelativePath(collectionRelativePath);
    const url = `${this.documentsBaseUrl}/${clean}`;
    const { status, data } = await this.requestJson(url, {
      method: 'POST',
      body: JSON.stringify({ fields: encodeFirestoreFields(docData) })
    });

    if (status < 200 || status >= 300) {
      throw new Error(data?.error?.message || `Error Firestore ADD ${clean} (HTTP ${status})`);
    }
    const name = String(data?.name || '');
    return name.split('/').pop() || '';
  }

  async runQuery<T = Record<string, any>>(
    parentRelativePath: string,
    structuredQuery: Record<string, any>,
    transactionId?: string
  ): Promise<Array<{ id: string; data: T }>> {
    const cleanParent = this.normalizeRelativePath(parentRelativePath);
    const url = cleanParent
      ? `${this.documentsBaseUrl}/${cleanParent}:runQuery`
      : `${this.documentsBaseUrl}:runQuery`;

    const payload: Record<string, any> = { structuredQuery };
    if (transactionId) {
      payload.transaction = transactionId;
    }

    const { status, data } = await this.requestJson(url, {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    if (status < 200 || status >= 300) {
      throw new Error(data?.error?.message || `Error Firestore runQuery (HTTP ${status})`);
    }

    const rows = Array.isArray(data) ? data : [];
    const results: Array<{ id: string; data: T }> = [];
    for (const row of rows) {
      if (row && row.document && row.document.fields) {
        const fullName = String(row.document.name || '');
        const id = fullName.split('/').pop() || '';
        results.push({
          id,
          data: decodeFirestoreFields(row.document.fields) as T
        });
      }
    }
    return results;
  }

  async runTransaction<T>(fn: (ctx: FirestoreTransactionContext) => Promise<T>): Promise<T> {
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const beginRes = await this.requestJson(`${this.documentsBaseUrl}:beginTransaction`, {
        method: 'POST',
        body: JSON.stringify({ options: { readWrite: {} } })
      });

      if (beginRes.status < 200 || beginRes.status >= 300 || !beginRes.data?.transaction) {
        throw new Error(
          beginRes.data?.error?.message ||
            `No se pudo iniciar transacción en Firestore (HTTP ${beginRes.status}).`
        );
      }

      const transactionId = String(beginRes.data.transaction);
      const writes: Array<Record<string, any>> = [];

      const ctx: FirestoreTransactionContext = {
        getDocument: async <D = Record<string, any>>(relativePath: string): Promise<D | null> => {
          return this.getDocument<D>(relativePath, transactionId);
        },
        runQuery: async <D = Record<string, any>>(
          parentRelativePath: string,
          structuredQuery: Record<string, any>
        ) => {
          return this.runQuery<D>(parentRelativePath, structuredQuery, transactionId);
        },
        createDocument: (relativePath: string, docData: Record<string, any>): void => {
          writes.push({
            update: {
              name: this.fullDocumentName(relativePath),
              fields: encodeFirestoreFields(docData)
            },
            currentDocument: { exists: false }
          });
        },
        setDocument: (
          relativePath: string,
          docData: Record<string, any>,
          merge: boolean = false
        ): void => {
          const fields = encodeFirestoreFields(docData);
          const write: Record<string, any> = {
            update: {
              name: this.fullDocumentName(relativePath),
              fields
            }
          };
          if (merge) {
            write.updateMask = {
              fieldPaths: Object.keys(fields).map(escapeFieldPath)
            };
          }
          writes.push(write);
        },
        updateDocument: (relativePath: string, patch: Record<string, any>): void => {
          const fields = encodeFirestoreFields(patch);
          const keys = Object.keys(fields);
          if (keys.length === 0) return;
          writes.push({
            update: {
              name: this.fullDocumentName(relativePath),
              fields
            },
            updateMask: {
              fieldPaths: keys.map(escapeFieldPath)
            },
            currentDocument: { exists: true }
          });
        }
      };

      let outcome: T;
      try {
        outcome = await fn(ctx);
      } catch (err) {
        await this.requestJson(`${this.documentsBaseUrl}:rollback`, {
          method: 'POST',
          body: JSON.stringify({ transaction: transactionId })
        }).catch(() => {});
        throw err;
      }

      const commitRes = await this.requestJson(`${this.documentsBaseUrl}:commit`, {
        method: 'POST',
        body: JSON.stringify({
          transaction: transactionId,
          writes
        })
      });

      if (commitRes.status === 409 && attempt < maxAttempts) {
        continue;
      }

      if (commitRes.status < 200 || commitRes.status >= 300) {
        throw new Error(
          commitRes.data?.error?.message ||
            `Error al confirmar transacción en Firestore (HTTP ${commitRes.status}).`
        );
      }

      return outcome;
    }

    throw new Error('La transacción de Firestore excedió los reintentos por contención.');
  }
}

export function createFirestoreRestClient(
  env: CloudflareEnv = {},
  fetchFn: typeof fetch = fetch
): FirestoreRestClient {
  const diag = inspectFirebaseAdminConfig(env);
  if (!diag.ok || !diag.credentials) {
    throw new FirebaseAdminConfigError(
      diag.error || 'Credenciales de Firebase no disponibles en Cloudflare.',
      diag.reason || 'missing_env',
      diag.missingVariables
    );
  }
  return new FirestoreRestClient(diag.credentials, fetchFn);
}

export function isNonAnonymousFirebaseToken(claims?: Record<string, any> | null): boolean {
  if (!claims || typeof claims !== 'object') return false;
  const provider = claims?.firebase?.sign_in_provider;
  if (provider === 'anonymous') return false;
  return true;
}

export async function deleteFirebaseAuthUser(
  env: CloudflareEnv = {},
  uid: string,
  fetchFn: typeof fetch = fetch
): Promise<{ deleted: boolean; pendingConfig?: boolean; error?: string }> {
  const cleanUid = String(uid || '').trim();
  if (!cleanUid) {
    return { deleted: false, error: 'UID de usuario vacío.' };
  }

  const diag = inspectFirebaseAdminConfig(env);
  if (!diag.ok || !diag.credentials) {
    return {
      deleted: false,
      pendingConfig: true,
      error: diag.error || 'Credenciales de servicio Firebase no disponibles para eliminar la cuenta en Auth.'
    };
  }

  try {
    const token = await getGoogleAccessToken(diag.credentials, fetchFn);
    const endpoint = `https://identitytoolkit.googleapis.com/v1/projects/${encodeURIComponent(
      diag.credentials.projectId
    )}/accounts:delete`;

    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ localId: cleanUid })
    });

    const data = (await res.json().catch(() => ({}))) as Record<string, any>;
    if (!res.ok) {
      const msg = String(data?.error?.message || `HTTP ${res.status}`);
      const errorEntries = Array.isArray(data?.error?.errors) ? data.error.errors : [];
      const isUserNotFound =
        msg.includes('USER_NOT_FOUND') ||
        errorEntries.some((entry: any) => String(entry?.message || '').includes('USER_NOT_FOUND'));
      if (isUserNotFound) {
        return { deleted: true };
      }
      return {
        deleted: false,
        error: `No se pudo confirmar la eliminación de la cuenta en Firebase Auth: ${msg}`
      };
    }

    return { deleted: true };
  } catch (err: any) {
    return {
      deleted: false,
      error: `Error contactando Firebase Authentication para baja de usuario: ${err?.message || err}`
    };
  }
}
