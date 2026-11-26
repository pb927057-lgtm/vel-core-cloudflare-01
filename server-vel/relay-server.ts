import http from 'http';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { WebSocketServer, WebSocket } from 'ws';
import 'dotenv/config';
import {
  getAdminDb,
  hasFirebaseAdminCredentials,
  TokenVerificationResult,
  verifyUserTokenStrict
} from '../netlify/functions/shared/firebaseAdmin';
import {
  confirmDevicePairingAtomic,
  createFirestoreAdminDeviceStore,
  DeviceTransactionStore,
  isValidDeviceIdForRole,
  revokeDeviceAuthorizationAtomic,
  verifyPeerCommunicationAuthorization
} from '../netlify/functions/shared/deviceAuthService';
import {
  evaluateSubscriberAccess
} from '../netlify/functions/shared/subscriptionAccess';
import type {
  AuthorizationRecord as FirestoreAuthorizationRecord,
  DeviceLinkRecord,
  DeviceRecord,
  DeviceRole
} from '../netlify/functions/shared/types';
import type { SubscriptionRuntimeStatus } from '../src/contracts/velContracts';

export interface AuthorizationRecord {
  terminalId: string;
  coreId: string;
  pairedAt: number;
  fingerprint: string;
}

export interface RevocationRecord {
  terminalId: string;
  revokedByCoreId: string;
  revokedAt: number;
  reason: string;
}

export interface ClientConnection {
  ws: WebSocket;
  deviceId: string;
  authUid: string;
  role: DeviceRole;
  fingerprint: string;
  signingPublicKeySpkiBase64: string;
  publicKeySpkiBase64: string;
  activeLinkId: string | null;
  pairedPeerDeviceId: string | null;
  subscriptionUid?: string | null;
  authenticated: boolean;
  isAlive: boolean;
  connectedAt: number;
}

interface PendingChallengeState {
  challenge: string;
  expiresAt: number;
  authDeadlineTimer: NodeJS.Timeout | null;
}

interface EphemeralPairingOffer {
  code: string;
  linkId: string;
  initiatorDeviceId: string;
  initiatorAuthUid: string;
  initiatorRole: DeviceRole;
  initiatorFingerprint: string;
  initiatorPublicKeyBase64: string;
  expiresAt: number;
  status: 'OFFERING' | 'SAS_PENDING';
  ws: WebSocket;
  claimerDeviceId?: string;
  claimerAuthUid?: string;
  claimerFingerprint?: string;
  claimerPublicKeyBase64?: string;
  claimerWs?: WebSocket;
  coreConfirmedSas?: boolean;
  terminalConfirmedSas?: boolean;
}

interface CachedPeerAuth {
  linkId: string;
  subscriptionUid?: string | null;
  authorized: boolean;
  expiresAt: number;
}

interface CachedSubscriptionStatus {
  status: SubscriptionRuntimeStatus;
  expiresAt: number;
}

export interface VelRelayServerOptions {
  port?: number;
  storageDir?: string;
  deviceStore?: DeviceTransactionStore;
  verifyToken?: (authHeader?: string) => Promise<TokenVerificationResult>;
  hasDbCredentials?: () => boolean;
  allowedOrigins?: string[];
  maxConnections?: number;
  maxPayloadBytes?: number;
  authTimeoutMs?: number;
  challengeTtlMs?: number;
  heartbeatIntervalMs?: number;
  operationDedupeTtlMs?: number;
  maxClockSkewMs?: number;
}

const DEFAULT_MAX_CONNECTIONS = 1000;
const DEFAULT_MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB (soporta chunks de 128 KB en base64)
const DEFAULT_AUTH_TIMEOUT_MS = 15_000;
const DEFAULT_CHALLENGE_TTL_MS = 60_000;
const DEFAULT_HEARTBEAT_MS = 30_000;
const DEFAULT_DEDUPE_TTL_MS = 10 * 60_000;
const DEFAULT_CLOCK_SKEW_MS = 120_000;
const MAX_PAIRING_TTL_MS = 5 * 60_000;
const AUTH_CACHE_TTL_MS = 30_000;
const SUBSCRIPTION_ACTIVE_CACHE_TTL_MS = 60_000;
const SUBSCRIPTION_EXPIRED_CACHE_TTL_MS = 10_000;

function normalizeOrigin(raw: string): string {
  return raw.trim().toLowerCase().replace(/\/+$/, '');
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const buf = Buffer.from(base64, 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

async function verifyEcdsaAuthProof(
  signingPublicKeySpkiBase64: string,
  signatureBase64: string,
  canonicalMessage: string
): Promise<boolean> {
  try {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) return false;
    const publicKey = await subtle.importKey(
      'spki',
      base64ToArrayBuffer(signingPublicKeySpkiBase64),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      base64ToArrayBuffer(signatureBase64),
      new TextEncoder().encode(canonicalMessage)
    );
  } catch {
    return false;
  }
}

export class VelRelayServer {
  private port: number;
  private dataDir: string;
  private authFile: string;
  private revFile: string;
  private options: Required<
    Pick<
      VelRelayServerOptions,
      | 'maxConnections'
      | 'maxPayloadBytes'
      | 'authTimeoutMs'
      | 'challengeTtlMs'
      | 'heartbeatIntervalMs'
      | 'operationDedupeTtlMs'
      | 'maxClockSkewMs'
    >
  >;
  private allowedOrigins: Set<string> | null = null;
  private customDeviceStore?: DeviceTransactionStore;
  private customVerifyToken?: (authHeader?: string) => Promise<TokenVerificationResult>;
  private customHasDbCredentials?: () => boolean;

  private server: http.Server | null = null;
  private wss: WebSocketServer | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private startedAt = Date.now();

  private clients = new Map<string, ClientConnection>();
  private socketToDeviceId = new WeakMap<WebSocket, string>();
  private pendingChallenges = new WeakMap<WebSocket, PendingChallengeState>();
  private seenOperationIds = new Map<string, number>();
  private peerAuthCache = new Map<string, CachedPeerAuth>();
  private subscriptionCache = new Map<string, CachedSubscriptionStatus>();

  private authorizations = new Map<string, AuthorizationRecord>();
  private revocations = new Map<string, RevocationRecord>();
  private pairingOffers = new Map<string, EphemeralPairingOffer>();

  constructor(portOrOptions: number | VelRelayServerOptions = 8080, storageDir?: string) {
    if (typeof portOrOptions === 'object' && portOrOptions !== null) {
      this.port = portOrOptions.port ?? parseInt(process.env.RELAY_PORT || '8080', 10);
      this.dataDir = portOrOptions.storageDir || path.join(process.cwd(), 'server-vel', 'data');
      this.customDeviceStore = portOrOptions.deviceStore;
      this.customVerifyToken = portOrOptions.verifyToken;
      this.customHasDbCredentials = portOrOptions.hasDbCredentials;
      if (portOrOptions.allowedOrigins && portOrOptions.allowedOrigins.length > 0) {
        this.allowedOrigins = new Set(
          portOrOptions.allowedOrigins.map((o) => normalizeOrigin(o)).filter(Boolean)
        );
      }
      this.options = {
        maxConnections: portOrOptions.maxConnections ?? DEFAULT_MAX_CONNECTIONS,
        maxPayloadBytes: portOrOptions.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES,
        authTimeoutMs: portOrOptions.authTimeoutMs ?? DEFAULT_AUTH_TIMEOUT_MS,
        challengeTtlMs: portOrOptions.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS,
        heartbeatIntervalMs: portOrOptions.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_MS,
        operationDedupeTtlMs: portOrOptions.operationDedupeTtlMs ?? DEFAULT_DEDUPE_TTL_MS,
        maxClockSkewMs: portOrOptions.maxClockSkewMs ?? DEFAULT_CLOCK_SKEW_MS
      };
    } else {
      this.port = portOrOptions;
      this.dataDir = storageDir || path.join(process.cwd(), 'server-vel', 'data');
      this.options = {
        maxConnections: DEFAULT_MAX_CONNECTIONS,
        maxPayloadBytes: DEFAULT_MAX_PAYLOAD_BYTES,
        authTimeoutMs: DEFAULT_AUTH_TIMEOUT_MS,
        challengeTtlMs: DEFAULT_CHALLENGE_TTL_MS,
        heartbeatIntervalMs: DEFAULT_HEARTBEAT_MS,
        operationDedupeTtlMs: DEFAULT_DEDUPE_TTL_MS,
        maxClockSkewMs: DEFAULT_CLOCK_SKEW_MS
      };
    }

    if (!this.allowedOrigins && process.env.RELAY_ALLOWED_ORIGINS) {
      const parsed = process.env.RELAY_ALLOWED_ORIGINS.split(',')
        .map((s) => normalizeOrigin(s))
        .filter((s) => Boolean(s) && s !== '*');
      if (parsed.length > 0) {
        this.allowedOrigins = new Set(parsed);
      }
    }

    if (!this.allowedOrigins && (process.env.RENDER === 'true' || Boolean(process.env.RENDER_SERVICE_ID))) {
      this.allowedOrigins = new Set([
        'https://proyecto-vel.pages.dev'
      ]);
    }

    this.authFile = path.join(this.dataDir, 'authorizations.json');
    this.revFile = path.join(this.dataDir, 'revocations.json');
  }

  private getDeviceStore(): DeviceTransactionStore | null {
    if (this.customDeviceStore) return this.customDeviceStore;
    const hasCreds = this.customHasDbCredentials ? this.customHasDbCredentials() : hasFirebaseAdminCredentials();
    if (!hasCreds) return null;
    return createFirestoreAdminDeviceStore(getAdminDb());
  }

  private async verifyFirebaseToken(firebaseIdToken: string): Promise<TokenVerificationResult> {
    const authHeader = `Bearer ${firebaseIdToken}`;
    if (this.customVerifyToken) return this.customVerifyToken(authHeader);
    return verifyUserTokenStrict(authHeader);
  }

  private logEvent(event: string, detail: Record<string, string | number | boolean | null | undefined> = {}) {
    const safePairs = Object.entries(detail)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => `${k}=${String(v)}`)
      .join(' ');
    console.log(`[VEL-Relay] ${event}${safePairs ? ` ${safePairs}` : ''}`);
  }

  private sendJson(ws: WebSocket, payload: Record<string, unknown>) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(payload));
    }
  }

  private invalidateAuthCacheForDevice(deviceId: string) {
    for (const key of this.peerAuthCache.keys()) {
      if (key.includes(deviceId)) {
        this.peerAuthCache.delete(key);
      }
    }
  }

  private async checkSubscriptionAccess(
    store: DeviceTransactionStore | null,
    subscriptionUid?: string | null,
    forceFresh = false
  ): Promise<SubscriptionRuntimeStatus> {
    const cleanSubUid = subscriptionUid ? String(subscriptionUid).trim() : '';
    if (!cleanSubUid || !store?.getSubscriber) {
      return { linked: false, active: true };
    }

    const nowMs = Date.now();
    if (!forceFresh) {
      const cached = this.subscriptionCache.get(cleanSubUid);
      if (cached && nowMs <= cached.expiresAt) {
        return cached.status;
      }
    }

    try {
      const subData = await store.getSubscriber(cleanSubUid);
      const evaluation = evaluateSubscriberAccess(subData, new Date(nowMs));

      if (!evaluation.active && evaluation.shouldPersistEstado && store.updateSubscriberStatus && subData) {
        store.updateSubscriberStatus(cleanSubUid, { estado: evaluation.shouldPersistEstado }).catch(() => {});
      }

      const status: SubscriptionRuntimeStatus = {
        linked: true,
        active: evaluation.active,
        estado: evaluation.estado,
        venceEl: evaluation.venceEl,
        reason: evaluation.reason
      };

      this.subscriptionCache.set(cleanSubUid, {
        status,
        expiresAt:
          nowMs + (status.active ? SUBSCRIPTION_ACTIVE_CACHE_TTL_MS : SUBSCRIPTION_EXPIRED_CACHE_TTL_MS)
      });
      return status;
    } catch (err: any) {
      this.logEvent('SUBSCRIPTION_CHECK_ERROR', { message: err?.message || 'unknown' });
      // Ante fallo transitorio de lectura, no revocamos ni bloqueamos erróneamente un vínculo legítimo.
      return { linked: true, active: true };
    }
  }

  private pruneExpiredState(now = Date.now()) {
    for (const [code, offer] of this.pairingOffers.entries()) {
      if (now > offer.expiresAt) {
        this.pairingOffers.delete(code);
      }
    }
    for (const [opKey, seenAt] of this.seenOperationIds.entries()) {
      if (now - seenAt > this.options.operationDedupeTtlMs) {
        this.seenOperationIds.delete(opKey);
      }
    }
    for (const [cacheKey, entry] of this.peerAuthCache.entries()) {
      if (now > entry.expiresAt) {
        this.peerAuthCache.delete(cacheKey);
      }
    }
    for (const [subKey, entry] of this.subscriptionCache.entries()) {
      if (now > entry.expiresAt) {
        this.subscriptionCache.delete(subKey);
      }
    }
    if (this.seenOperationIds.size > 10_000) {
      const entries = Array.from(this.seenOperationIds.entries()).sort((a, b) => a[1] - b[1]);
      for (let i = 0; i < entries.length - 5_000; i++) {
        this.seenOperationIds.delete(entries[i][0]);
      }
    }
  }

  public loadPersistence() {
    try {
      if (fs.existsSync(this.authFile)) {
        const list: AuthorizationRecord[] = JSON.parse(fs.readFileSync(this.authFile, 'utf8'));
        this.authorizations.clear();
        for (const item of list) this.authorizations.set(item.terminalId, item);
      }
    } catch {}
    try {
      if (fs.existsSync(this.revFile)) {
        const list: RevocationRecord[] = JSON.parse(fs.readFileSync(this.revFile, 'utf8'));
        this.revocations.clear();
        for (const item of list) this.revocations.set(item.terminalId, item);
      }
    } catch {}
  }

  public start(): Promise<number> {
    this.startedAt = Date.now();
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => {
        if (req.url === '/health' || req.url === '/') {
          const hasCreds = this.customHasDbCredentials
            ? this.customHasDbCredentials()
            : hasFirebaseAdminCredentials();
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store'
          });
          res.end(
            JSON.stringify({
              status: 'UP',
              service: 'VEL-Relay',
              protocol: 'VEL-RELAY-v3-DIRECT',
              activeConnections: this.clients.size,
              pendingPairingOffers: this.pairingOffers.size,
              firebaseAdminConfigured: hasCreds || Boolean(this.customDeviceStore),
              uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000)
            })
          );
          return;
        }
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not Found' }));
      });

      this.wss = new WebSocketServer({
        server: this.server,
        maxPayload: this.options.maxPayloadBytes,
        verifyClient: (info, callback) => {
          if (!this.allowedOrigins) {
            callback(true);
            return;
          }
          const rawOrigin = info.req.headers.origin;
          const reqOrigin = rawOrigin ? normalizeOrigin(String(rawOrigin)) : '';
          if (!reqOrigin || !this.allowedOrigins.has(reqOrigin)) {
            this.logEvent('CONNECTION_REJECTED_ORIGIN', { origin: reqOrigin || '(missing)' });
            callback(false, 403, 'Origin not allowed');
            return;
          }
          callback(true);
        }
      });

      this.wss.on('connection', (ws: WebSocket, req: http.IncomingMessage) => {
        if (this.allowedOrigins) {
          const reqOrigin = req.headers.origin ? normalizeOrigin(String(req.headers.origin)) : '';
          if (!reqOrigin || !this.allowedOrigins.has(reqOrigin)) {
            this.logEvent('CONNECTION_REJECTED_ORIGIN', { origin: reqOrigin || '(missing)' });
            this.sendJson(ws, {
              type: 'AUTH_ERROR',
              error: 'ORIGIN_NOT_ALLOWED',
              message: 'Origen WebSocket no autorizado.'
            });
            ws.close(4003, 'Origin not allowed');
            return;
          }
        }

        if (this.wss && this.wss.clients.size > this.options.maxConnections) {
          this.logEvent('CONNECTION_REJECTED_LIMIT', { active: this.wss.clients.size });
          this.sendJson(ws, {
            type: 'ERROR',
            error: 'SERVER_BUSY',
            message: 'Límite máximo de conexiones simultáneas alcanzado.'
          });
          ws.close(1013, 'Server busy');
          return;
        }

        if (req.url && /^\/ws\//.test(req.url)) {
          this.sendJson(ws, {
            type: 'AUTH_ERROR',
            error: 'AUTH_REQUIRED',
            message: 'Autenticación mediante token Firebase requerida.'
          });
          ws.close(4001, 'Auth required');
          return;
        }

        const challenge = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + this.options.challengeTtlMs;
        const authDeadlineTimer = setTimeout(() => {
          if (!this.socketToDeviceId.has(ws) && ws.readyState === WebSocket.OPEN) {
            this.logEvent('AUTH_TIMEOUT');
            this.sendJson(ws, {
              type: 'AUTH_ERROR',
              error: 'AUTH_TIMEOUT',
              message: 'Tiempo de espera agotado para autenticar.'
            });
            ws.close(4008, 'Auth timeout');
          }
        }, this.options.authTimeoutMs);

        this.pendingChallenges.set(ws, {
          challenge,
          expiresAt,
          authDeadlineTimer
        });

        this.sendJson(ws, {
          type: 'AUTH_CHALLENGE',
          challenge,
          expiresAt,
          timestamp: Date.now()
        });

        ws.on('pong', () => {
          const deviceId = this.socketToDeviceId.get(ws);
          if (deviceId) {
            const client = this.clients.get(deviceId);
            if (client && client.ws === ws) {
              client.isAlive = true;
            }
          }
        });

        ws.on('message', async (messageRaw: string | Buffer) => {
          let data: any;
          try {
            data = JSON.parse(messageRaw.toString());
          } catch {
            this.sendJson(ws, { type: 'ERROR', error: 'INVALID_JSON', message: 'Mensaje JSON mal formado.' });
            return;
          }

          if (!data || typeof data !== 'object' || Array.isArray(data)) {
            this.sendJson(ws, { type: 'ERROR', error: 'INVALID_PAYLOAD', message: 'El mensaje debe ser un objeto JSON.' });
            return;
          }

          try {
            await this.handleMessage(ws, data);
          } catch (err: any) {
            this.logEvent('HANDLER_ERROR', { message: err?.message || 'unknown' });
            this.sendJson(ws, {
              type: 'ERROR',
              error: 'INTERNAL_RELAY_ERROR',
              message: 'Error interno procesando la operación en el Relay.'
            });
          }
        });

        ws.on('close', () => this.cleanupSocket(ws));
        ws.on('error', () => this.cleanupSocket(ws));
      });

      this.heartbeatTimer = setInterval(() => {
        for (const [deviceId, client] of this.clients.entries()) {
          if (!client.isAlive) {
            this.logEvent('HEARTBEAT_TIMEOUT', { deviceId });
            try {
              client.ws.terminate();
            } catch {}
            this.cleanupSocket(client.ws);
            continue;
          }
          client.isAlive = false;
          if (client.ws.readyState === WebSocket.OPEN) {
            try {
              client.ws.ping();
            } catch {}
          }
        }
        this.pruneExpiredState();
      }, this.options.heartbeatIntervalMs);

      this.server.listen(this.port, () => {
        const address = this.server?.address();
        const actualPort = typeof address === 'object' && address ? address.port : this.port;
        this.port = actualPort;
        resolve(actualPort);
      });
    });
  }

  private cleanupSocket(ws: WebSocket) {
    const pending = this.pendingChallenges.get(ws);
    if (pending?.authDeadlineTimer) {
      clearTimeout(pending.authDeadlineTimer);
    }
    this.pendingChallenges.delete(ws);

    for (const [code, offer] of this.pairingOffers.entries()) {
      if (offer.ws === ws || offer.claimerWs === ws) {
        const otherWs = offer.ws === ws ? offer.claimerWs : offer.ws;
        this.pairingOffers.delete(code);
        if (otherWs && otherWs.readyState === WebSocket.OPEN) {
          this.sendJson(otherWs, {
            type: 'PAIRING_CANCELLED',
            code,
            reason: 'PEER_DISCONNECTED',
            timestamp: Date.now()
          });
        }
      }
    }

    const deviceId = this.socketToDeviceId.get(ws);
    if (deviceId) {
      const current = this.clients.get(deviceId);
      if (current && current.ws === ws) {
        this.clients.delete(deviceId);
        this.logEvent('CLIENT_DISCONNECTED', { deviceId });

        if (current.pairedPeerDeviceId) {
          const peer = this.clients.get(current.pairedPeerDeviceId);
          if (peer && peer.ws.readyState === WebSocket.OPEN) {
            this.sendJson(peer.ws, {
              type: 'PEER_STATUS',
              peerDeviceId: deviceId,
              online: false,
              timestamp: Date.now()
            });
          }
        }
      }
    }
  }

  public stop(): Promise<void> {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    for (const client of this.clients.values()) {
      try {
        client.ws.terminate();
      } catch {}
    }
    this.clients.clear();
    this.pairingOffers.clear();
    this.seenOperationIds.clear();
    this.peerAuthCache.clear();
    this.subscriptionCache.clear();

    return new Promise((resolve) => {
      if (this.wss) {
        this.wss.close(() => {
          if (this.server) this.server.close(() => resolve());
          else resolve();
        });
      } else if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private getAuthenticatedClient(ws: WebSocket): ClientConnection | null {
    const deviceId = this.socketToDeviceId.get(ws);
    if (!deviceId) return null;
    const client = this.clients.get(deviceId);
    if (!client || client.ws !== ws || !client.authenticated) return null;
    return client;
  }

  private async handleMessage(ws: WebSocket, msg: Record<string, any>) {
    this.pruneExpiredState();

    switch (msg.type) {
      case 'AUTH':
        await this.handleAuth(ws, msg);
        return;
      case 'PAIRING_OFFER':
        await this.handlePairingOffer(ws, msg);
        return;
      case 'PAIRING_CLAIM':
        await this.handlePairingClaim(ws, msg);
        return;
      case 'PAIRING_CONFIRM':
        await this.handlePairingConfirm(ws, msg);
        return;
      case 'PAIRING_CANCEL':
        this.handlePairingCancel(ws, msg);
        return;
      case 'RELAY_DATA':
        await this.handleRelayData(ws, msg);
        return;
      case 'REVOKE_DEVICE':
        await this.handleRevokeDevice(ws, msg);
        return;
      case 'PING':
        this.sendJson(ws, { type: 'PONG', timestamp: Date.now() });
        return;
      default:
        this.sendJson(ws, { type: 'ERROR', error: 'UNKNOWN_MESSAGE_TYPE' });
        return;
    }
  }

  private async handleAuth(ws: WebSocket, msg: Record<string, any>) {
    const pending = this.pendingChallenges.get(ws);
    if (pending) {
      if (Date.now() > pending.expiresAt) {
        this.pendingChallenges.delete(ws);
        this.sendJson(ws, {
          type: 'AUTH_ERROR',
          error: 'CHALLENGE_EXPIRED',
          message: 'La sesión de conexión expiró. Reconectando...'
        });
        ws.close(4008, 'Challenge expired');
        return;
      }
      if (pending.authDeadlineTimer) {
        clearTimeout(pending.authDeadlineTimer);
      }
      this.pendingChallenges.delete(ws);
    }

    const deviceId = String(msg.deviceId || '').trim();
    const role = msg.role as DeviceRole;
    const firebaseIdToken = String(msg.firebaseIdToken || '').trim();
    const challenge = msg.challenge ? String(msg.challenge).trim() : '';
    const signatureBase64 = msg.signatureBase64 ? String(msg.signatureBase64).trim() : '';
    const timestamp = Number(msg.timestamp || Date.now());
    const requestedPairedCoreId = msg.pairedCoreId ? String(msg.pairedCoreId).trim() : null;

    if (!deviceId || (role !== 'CORE' && role !== 'TERMINAL') || !isValidDeviceIdForRole(deviceId, role)) {
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'INVALID_DEVICE_ID',
        message: 'Identificador técnico o rol inválido.'
      });
      ws.close(4001, 'Invalid deviceId');
      return;
    }

    if (!firebaseIdToken) {
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'MISSING_CREDENTIALS',
        message: 'Se requiere token de sesión Firebase.'
      });
      ws.close(4001, 'Missing token');
      return;
    }

    if (challenge && pending && challenge !== pending.challenge) {
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'CHALLENGE_MISMATCH',
        message: 'El código de sesión no coincide.'
      });
      ws.close(4001, 'Challenge mismatch');
      return;
    }

    const tokenRes = await this.verifyFirebaseToken(firebaseIdToken);
    if (!tokenRes.authenticated) {
      this.logEvent('AUTH_REJECTED_TOKEN', { deviceId, reason: tokenRes.reason });
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: tokenRes.reason === 'pending_config' ? 'SERVER_CONFIG_PENDING' : 'INVALID_FIREBASE_TOKEN',
        message: tokenRes.message
      });
      ws.close(tokenRes.reason === 'pending_config' ? 4503 : 4001, 'Token verification failed');
      return;
    }

    const store = this.getDeviceStore();
    if (!store) {
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'SERVER_CONFIG_PENDING',
        message: 'Falta FIREBASE_SERVICE_ACCOUNT para consultar dispositivos en Firestore.'
      });
      ws.close(4503, 'Firestore config pending');
      return;
    }

    const authCheck = await verifyPeerCommunicationAuthorization(store, deviceId);
    if (!authCheck.device) {
      this.logEvent('AUTH_REJECTED_NOT_FOUND', { deviceId });
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'DEVICE_NOT_REGISTERED',
        message: 'El dispositivo aún no está registrado en Firestore.'
      });
      ws.close(4003, 'Device not registered');
      return;
    }

    const device: DeviceRecord = authCheck.device;
    if (device.authUid !== tokenRes.uid) {
      this.logEvent('AUTH_REJECTED_UID_MISMATCH', { deviceId });
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'AUTH_UID_MISMATCH',
        message: 'La sesión Firebase no corresponde al propietario de este dispositivo.'
      });
      ws.close(4003, 'Auth UID mismatch');
      return;
    }

    if (device.role !== role) {
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'ROLE_MISMATCH',
        message: 'El rol declarado no coincide con el registro.'
      });
      ws.close(4003, 'Role mismatch');
      return;
    }

    if (device.status === 'revoked' || this.revocations.has(deviceId)) {
      this.logEvent('AUTH_REJECTED_REVOKED', { deviceId });
      this.sendJson(ws, {
        type: 'AUTH_ERROR',
        error: 'DEVICE_REVOKED',
        message: device.revokedReason || 'Este dispositivo fue desvinculado desde VEL CORE.'
      });
      ws.close(4003, 'Device is revoked');
      return;
    }

    // Si el cliente envió firma ECDSA opcional, verificarla; si no la envió, el token Firebase + authUid ya autentica al dispositivo.
    if (signatureBase64 && challenge && device.signingPublicKeySpkiBase64) {
      const canonical = `VEL-RELAY-AUTH-v1|${challenge}|${deviceId}|${timestamp}`;
      const signatureOk = await verifyEcdsaAuthProof(
        device.signingPublicKeySpkiBase64,
        signatureBase64,
        canonical
      );
      if (!signatureOk) {
        this.logEvent('AUTH_REJECTED_BAD_SIGNATURE', { deviceId });
        this.sendJson(ws, {
          type: 'AUTH_ERROR',
          error: 'INVALID_SIGNATURE',
          message: 'La firma del dispositivo no es válida.'
        });
        ws.close(4001, 'Invalid signature');
        return;
      }
    }

    let activeLink: DeviceLinkRecord | null = authCheck.link || null;
    let activeAuth: FirestoreAuthorizationRecord | null = authCheck.authorization || null;
    let activeLinkId: string | null = null;
    let pairedPeerDeviceId: string | null = null;

    if (
      activeLink &&
      activeLink.status === 'active' &&
      activeAuth &&
      activeAuth.status === 'active'
    ) {
      activeLinkId = activeLink.linkId;
      pairedPeerDeviceId =
        role === 'CORE' ? activeLink.terminalDeviceId : activeLink.coreDeviceId;

      if (role === 'TERMINAL' && requestedPairedCoreId && requestedPairedCoreId !== activeLink.coreDeviceId) {
        this.sendJson(ws, {
          type: 'AUTH_ERROR',
          error: 'UNAUTHORIZED_CORE',
          message: 'El VEL CORE indicado no coincide con el vínculo activo.'
        });
        ws.close(4003, 'Unauthorized CORE');
        return;
      }
    }

    const previousClient = this.clients.get(deviceId);
    if (previousClient && previousClient.ws !== ws) {
      try {
        previousClient.ws.close(4009, 'Superseded by new connection');
      } catch {}
    }

    const resolvedSubUid = device.subscriptionUid || activeLink?.subscriptionUid || null;
    const subscriptionStatus = await this.checkSubscriptionAccess(store, resolvedSubUid, true);

    const connection: ClientConnection = {
      ws,
      deviceId,
      authUid: tokenRes.uid,
      role,
      fingerprint: device.fingerprint,
      signingPublicKeySpkiBase64: device.signingPublicKeySpkiBase64,
      publicKeySpkiBase64: device.publicKeySpkiBase64,
      activeLinkId,
      pairedPeerDeviceId,
      subscriptionUid: resolvedSubUid,
      authenticated: true,
      isAlive: true,
      connectedAt: Date.now()
    };

    this.clients.set(deviceId, connection);
    this.socketToDeviceId.set(ws, deviceId);

    const peerClient = pairedPeerDeviceId ? this.clients.get(pairedPeerDeviceId) : undefined;
    const peerOnline = Boolean(peerClient && peerClient.ws.readyState === WebSocket.OPEN);

    this.logEvent('AUTH_SUCCESS', {
      deviceId,
      role,
      linked: Boolean(activeLinkId),
      subActive: subscriptionStatus.active
    });

    let corePublicKeyForLink = activeLink?.corePublicKeySpkiBase64 || null;
    let terminalPublicKeyForLink = activeLink?.terminalPublicKeySpkiBase64 || null;
    if (activeLink && pairedPeerDeviceId && (!corePublicKeyForLink || !terminalPublicKeyForLink)) {
      try {
        const peerAuth = await verifyPeerCommunicationAuthorization(store, pairedPeerDeviceId);
        if (peerAuth.device?.publicKeySpkiBase64) {
          if (role === 'CORE') {
            corePublicKeyForLink = device.publicKeySpkiBase64;
            terminalPublicKeyForLink = peerAuth.device.publicKeySpkiBase64;
          } else {
            corePublicKeyForLink = peerAuth.device.publicKeySpkiBase64;
            terminalPublicKeyForLink = device.publicKeySpkiBase64;
          }
        }
      } catch {}
    }

    this.sendJson(ws, {
      type: 'AUTH_SUCCESS',
      deviceId,
      role,
      status: activeLinkId ? 'paired' : 'registered',
      activeLinkId,
      pairedPeerDeviceId,
      peerOnline,
      subscriptionStatus,
      link: activeLink
        ? {
            linkId: activeLink.linkId,
            coreDeviceId: activeLink.coreDeviceId,
            terminalDeviceId: activeLink.terminalDeviceId,
            corePublicKeySpkiBase64: corePublicKeyForLink,
            terminalPublicKeySpkiBase64: terminalPublicKeyForLink
          }
        : null,
      timestamp: Date.now()
    });

    if (peerOnline && peerClient) {
      this.sendJson(peerClient.ws, {
        type: 'PEER_STATUS',
        peerDeviceId: deviceId,
        online: true,
        timestamp: Date.now()
      });
    }
  }

  private async handlePairingOffer(ws: WebSocket, msg: Record<string, any>) {
    const sender = this.getAuthenticatedClient(ws);
    if (!sender) {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'UNAUTHENTICATED', message: 'Esperando conexión con el servidor...' });
      return;
    }

    if (sender.role !== 'CORE') {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'UNAUTHORIZED_ACTION', message: 'Solo VEL CORE puede generar código.' });
      return;
    }

    const store = this.getDeviceStore();
    if (store) {
      const coreAuth = await verifyPeerCommunicationAuthorization(store, sender.deviceId);
      const effectiveSubUid = coreAuth.device?.subscriptionUid || sender.subscriptionUid || null;
      sender.subscriptionUid = effectiveSubUid;
      const subStatus = await this.checkSubscriptionAccess(store, effectiveSubUid, true);
      if (subStatus.linked && !subStatus.active) {
        this.sendJson(ws, {
          type: 'PAIRING_ERROR',
          error: 'SUBSCRIPTION_EXPIRED',
          message: subStatus.reason || 'Tu suscripción mensual venció. Renueva en Blogger con Mercado Pago para vincular tus teléfonos.',
          subscriptionStatus: subStatus
        });
        return;
      }
    }

    const code = String(msg.code || '').trim().toUpperCase();
    if (!code || code.length < 4 || code.length > 32) {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'INVALID_CODE', message: 'Código de conexión inválido.' });
      return;
    }

    for (const [existingCode, existingOffer] of this.pairingOffers.entries()) {
      if (existingOffer.initiatorDeviceId === sender.deviceId) {
        this.pairingOffers.delete(existingCode);
      }
    }

    const requestedExpiresAt = Number(msg.expiresAt || 0);
    const maxAllowedExpiresAt = Date.now() + MAX_PAIRING_TTL_MS;
    const expiresAt =
      requestedExpiresAt > Date.now() && requestedExpiresAt <= maxAllowedExpiresAt
        ? requestedExpiresAt
        : maxAllowedExpiresAt;

    const linkId = `LNK-${crypto.randomUUID().toUpperCase()}`;

    this.pairingOffers.set(code, {
      code,
      linkId,
      initiatorDeviceId: sender.deviceId,
      initiatorAuthUid: sender.authUid,
      initiatorRole: sender.role,
      initiatorFingerprint: sender.fingerprint,
      initiatorPublicKeyBase64: sender.publicKeySpkiBase64,
      expiresAt,
      status: 'OFFERING',
      ws
    });

    this.logEvent('PAIRING_OFFER_CREATED', { coreDeviceId: sender.deviceId, linkId });

    this.sendJson(ws, {
      type: 'PAIRING_OFFER_REGISTERED',
      code,
      linkId,
      expiresAt,
      timestamp: Date.now()
    });
  }

  private async handlePairingClaim(ws: WebSocket, msg: Record<string, any>) {
    const sender = this.getAuthenticatedClient(ws);
    if (!sender) {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'UNAUTHENTICATED', message: 'Conéctate primero antes de ingresar el código.' });
      return;
    }

    if (sender.role !== 'TERMINAL') {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'UNAUTHORIZED_ACTION', message: 'Solo VEL MÓVIL puede ingresar el código de CORE.' });
      return;
    }

    const cleanCode = String(msg.code || '').trim().toUpperCase();
    const offer = this.pairingOffers.get(cleanCode);

    if (!offer) {
      this.sendJson(ws, {
        type: 'PAIRING_ERROR',
        error: 'OFFER_NOT_FOUND',
        message: 'El código no existe o ya expiró. Genera uno nuevo en tu VEL CORE.'
      });
      return;
    }

    if (Date.now() > offer.expiresAt) {
      this.pairingOffers.delete(cleanCode);
      this.sendJson(ws, {
        type: 'PAIRING_ERROR',
        error: 'OFFER_EXPIRED',
        message: 'Este código expiró (dura 5 minutos). Genera uno nuevo en VEL CORE.'
      });
      return;
    }

    if (offer.status !== 'OFFERING') {
      this.sendJson(ws, {
        type: 'PAIRING_ERROR',
        error: 'OFFER_ALREADY_CLAIMED',
        message: 'Este código ya está siendo utilizado.'
      });
      return;
    }

    if (offer.initiatorDeviceId === sender.deviceId || offer.ws.readyState !== WebSocket.OPEN) {
      this.pairingOffers.delete(cleanCode);
      this.sendJson(ws, {
        type: 'PAIRING_ERROR',
        error: 'CORE_UNAVAILABLE',
        message: 'Tu VEL CORE no está abierto en línea en este momento.'
      });
      return;
    }

    const store = this.getDeviceStore();
    if (!store) {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'SERVER_CONFIG_PENDING', message: 'Firestore no configurado en Relay.' });
      return;
    }

    const claimerCheck = await verifyPeerCommunicationAuthorization(store, sender.deviceId);
    const coreCheck = await verifyPeerCommunicationAuthorization(store, offer.initiatorDeviceId);
    if (!claimerCheck.authorized || !coreCheck.authorized) {
      this.sendJson(ws, {
        type: 'PAIRING_ERROR',
        error: 'DEVICE_NOT_ELIGIBLE',
        message: 'Alguno de los teléfonos fue desvinculado o no está habilitado.'
      });
      return;
    }

    const resolvedPairingSubUid =
      coreCheck.device?.subscriptionUid ||
      claimerCheck.device?.subscriptionUid ||
      sender.subscriptionUid ||
      null;
    const pairingSubStatus = await this.checkSubscriptionAccess(store, resolvedPairingSubUid, true);
    if (pairingSubStatus.linked && !pairingSubStatus.active) {
      this.sendJson(ws, {
        type: 'PAIRING_ERROR',
        error: 'SUBSCRIPTION_EXPIRED',
        message: pairingSubStatus.reason || 'Tu suscripción mensual venció. Renueva en Blogger con Mercado Pago para vincular tus teléfonos.',
        subscriptionStatus: pairingSubStatus
      });
      return;
    }

    // Modo simplificado en 1 solo paso (por defecto): confirmar vínculo inmediatamente al validar código.
    const singleStep = msg.requireSas !== true;
    if (singleStep) {
      const confirmOutcome = await confirmDevicePairingAtomic(store, offer.initiatorAuthUid, {
        linkId: offer.linkId,
        coreDeviceId: offer.initiatorDeviceId,
        terminalDeviceId: sender.deviceId,
        corePublicKeySpkiBase64: offer.initiatorPublicKeyBase64,
        terminalPublicKeySpkiBase64: sender.publicKeySpkiBase64,
        sasVerified: true
      });

      if (!confirmOutcome.ok || !confirmOutcome.link || !confirmOutcome.authorization) {
        this.sendJson(ws, {
          type: 'PAIRING_ERROR',
          error: confirmOutcome.code || 'PAIRING_PERSIST_FAILED',
          message: confirmOutcome.reason || 'No se pudo completar la conexión entre los teléfonos.'
        });
        return;
      }

      this.pairingOffers.delete(cleanCode);
      this.invalidateAuthCacheForDevice(offer.initiatorDeviceId);
      this.invalidateAuthCacheForDevice(sender.deviceId);

      const finalSubUid = confirmOutcome.link.subscriptionUid || resolvedPairingSubUid || null;
      const coreClient = this.clients.get(offer.initiatorDeviceId);
      if (coreClient) {
        coreClient.activeLinkId = confirmOutcome.link.linkId;
        coreClient.pairedPeerDeviceId = sender.deviceId;
        if (finalSubUid) coreClient.subscriptionUid = finalSubUid;
      }

      const termClient = this.clients.get(sender.deviceId);
      if (termClient) {
        termClient.activeLinkId = confirmOutcome.link.linkId;
        termClient.pairedPeerDeviceId = offer.initiatorDeviceId;
        if (finalSubUid) termClient.subscriptionUid = finalSubUid;
      }

      const confirmedPayload = {
        type: 'PAIRING_CONFIRMED',
        code: cleanCode,
        link: confirmOutcome.link,
        authorization: confirmOutcome.authorization,
        peerOnline: true,
        timestamp: Date.now()
      };

      this.logEvent('PAIRING_CONFIRMED_DIRECT', {
        linkId: confirmOutcome.link.linkId,
        coreDeviceId: offer.initiatorDeviceId,
        terminalDeviceId: sender.deviceId
      });

      if (offer.ws.readyState === WebSocket.OPEN) {
        this.sendJson(offer.ws, confirmedPayload);
      }
      if (ws.readyState === WebSocket.OPEN) {
        this.sendJson(ws, confirmedPayload);
      }
      return;
    }

    // Flujo heredado opcional si un cliente antiguo solicita SAS
    offer.status = 'SAS_PENDING';
    offer.claimerDeviceId = sender.deviceId;
    offer.claimerAuthUid = sender.authUid;
    offer.claimerFingerprint = sender.fingerprint;
    offer.claimerPublicKeyBase64 = sender.publicKeySpkiBase64;
    offer.claimerWs = ws;

    this.sendJson(ws, {
      type: 'PAIRING_OFFER_FOUND',
      code: cleanCode,
      linkId: offer.linkId,
      peerDeviceId: offer.initiatorDeviceId,
      peerRole: offer.initiatorRole,
      peerFingerprint: offer.initiatorFingerprint,
      peerPublicKeyBase64: offer.initiatorPublicKeyBase64,
      expiresAt: offer.expiresAt,
      timestamp: Date.now()
    });

    this.sendJson(offer.ws, {
      type: 'PAIRING_CLAIM_RECEIVED',
      code: cleanCode,
      linkId: offer.linkId,
      peerDeviceId: sender.deviceId,
      peerRole: sender.role,
      peerFingerprint: sender.fingerprint,
      peerPublicKeyBase64: sender.publicKeySpkiBase64,
      expiresAt: offer.expiresAt,
      timestamp: Date.now()
    });
  }

  private async handlePairingConfirm(ws: WebSocket, msg: Record<string, any>) {
    const sender = this.getAuthenticatedClient(ws);
    if (!sender) {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'UNAUTHENTICATED', message: 'Sesión no autenticada.' });
      return;
    }

    const cleanCode = String(msg.code || '').trim().toUpperCase();
    const offer = this.pairingOffers.get(cleanCode);
    const isCoreSender = offer && sender.role === 'CORE' && offer.initiatorDeviceId === sender.deviceId;
    const isTerminalSender = offer && sender.role === 'TERMINAL' && offer.claimerDeviceId === sender.deviceId;

    if (!offer || (!isCoreSender && !isTerminalSender) || offer.status !== 'SAS_PENDING' || !offer.claimerDeviceId) {
      this.sendJson(ws, {
        type: 'PAIRING_ERROR',
        error: 'PAIRING_SESSION_NOT_FOUND',
        message: 'No existe una sesión de emparejamiento pendiente.'
      });
      return;
    }

    if (Date.now() > offer.expiresAt) {
      this.pairingOffers.delete(cleanCode);
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'OFFER_EXPIRED', message: 'El código expiró.' });
      return;
    }

    if (isCoreSender) offer.coreConfirmedSas = true;
    else if (isTerminalSender) offer.terminalConfirmedSas = true;

    if (!offer.coreConfirmedSas || !offer.terminalConfirmedSas) {
      const awaitingMsg = {
        type: 'PAIRING_AWAITING_PEER',
        code: cleanCode,
        linkId: offer.linkId,
        confirmedBy: sender.role,
        coreConfirmed: Boolean(offer.coreConfirmedSas),
        terminalConfirmed: Boolean(offer.terminalConfirmedSas),
        timestamp: Date.now()
      };
      if (offer.ws.readyState === WebSocket.OPEN) this.sendJson(offer.ws, awaitingMsg);
      if (offer.claimerWs && offer.claimerWs.readyState === WebSocket.OPEN) this.sendJson(offer.claimerWs, awaitingMsg);
      return;
    }

    const store = this.getDeviceStore();
    if (!store) {
      this.sendJson(ws, { type: 'PAIRING_ERROR', error: 'SERVER_CONFIG_PENDING', message: 'Firestore no configurado en Relay.' });
      return;
    }

    const confirmOutcome = await confirmDevicePairingAtomic(store, offer.initiatorAuthUid, {
      linkId: offer.linkId,
      coreDeviceId: offer.initiatorDeviceId,
      terminalDeviceId: offer.claimerDeviceId,
      corePublicKeySpkiBase64: offer.initiatorPublicKeyBase64,
      terminalPublicKeySpkiBase64: offer.claimerPublicKeyBase64,
      sasVerified: true
    });

    if (!confirmOutcome.ok || !confirmOutcome.link || !confirmOutcome.authorization) {
      const errPayload = {
        type: 'PAIRING_ERROR',
        error: confirmOutcome.code || 'PAIRING_PERSIST_FAILED',
        message: confirmOutcome.reason || 'No se pudo persistir la vinculación.'
      };
      if (offer.ws.readyState === WebSocket.OPEN) this.sendJson(offer.ws, errPayload);
      if (offer.claimerWs && offer.claimerWs.readyState === WebSocket.OPEN) this.sendJson(offer.claimerWs, errPayload);
      return;
    }

    this.pairingOffers.delete(cleanCode);
    this.invalidateAuthCacheForDevice(offer.initiatorDeviceId);
    this.invalidateAuthCacheForDevice(offer.claimerDeviceId);

    const coreClient = this.clients.get(offer.initiatorDeviceId);
    if (coreClient) {
      coreClient.activeLinkId = confirmOutcome.link.linkId;
      coreClient.pairedPeerDeviceId = offer.claimerDeviceId;
    }

    const termClient = this.clients.get(offer.claimerDeviceId);
    if (termClient) {
      termClient.activeLinkId = confirmOutcome.link.linkId;
      termClient.pairedPeerDeviceId = offer.initiatorDeviceId;
    }

    const confirmedPayload = {
      type: 'PAIRING_CONFIRMED',
      code: cleanCode,
      link: confirmOutcome.link,
      authorization: confirmOutcome.authorization,
      peerOnline: true,
      timestamp: Date.now()
    };

    if (offer.ws.readyState === WebSocket.OPEN) this.sendJson(offer.ws, confirmedPayload);
    if (offer.claimerWs && offer.claimerWs.readyState === WebSocket.OPEN) this.sendJson(offer.claimerWs, confirmedPayload);
  }

  private handlePairingCancel(ws: WebSocket, msg: Record<string, any>) {
    const sender = this.getAuthenticatedClient(ws);
    if (!sender) return;

    const cleanCode = String(msg.code || '').trim().toUpperCase();
    const offer = this.pairingOffers.get(cleanCode);
    if (!offer) return;
    if (offer.initiatorDeviceId !== sender.deviceId && offer.claimerDeviceId !== sender.deviceId) return;

    this.pairingOffers.delete(cleanCode);
    const cancelMsg = {
      type: 'PAIRING_CANCELLED',
      code: cleanCode,
      cancelledBy: sender.deviceId,
      reason: String(msg.reason || 'CANCELLED_BY_PEER'),
      timestamp: Date.now()
    };

    this.sendJson(offer.ws, cancelMsg);
    if (offer.claimerWs && offer.claimerWs !== offer.ws) {
      this.sendJson(offer.claimerWs, cancelMsg);
    }
  }

  /**
   * Reenvía datos directamente teléfono-a-teléfono en memoria RAM (sin guardar nada en el servidor ni en Firestore).
   */
  private async handleRelayData(ws: WebSocket, msg: Record<string, any>) {
    const sender = this.getAuthenticatedClient(ws);
    if (!sender) {
      this.sendJson(ws, { type: 'ERROR', error: 'UNAUTHENTICATED', message: 'Conexión no autenticada.' });
      return;
    }

    const senderId = String(msg.senderId || '').trim();
    const recipientId = String(msg.recipientId || '').trim();
    const linkId = String(msg.linkId || '').trim();
    const operationId = String(msg.operationId || '').trim();
    const payload = msg.payload;
    const timestamp = Number(msg.timestamp || Date.now());

    if (senderId !== sender.deviceId) {
      this.sendJson(ws, { type: 'ERROR', error: 'SENDER_IMPERSONATION', operationId });
      return;
    }

    if (!recipientId || !linkId || !operationId || !payload || typeof payload !== 'object') {
      this.sendJson(ws, {
        type: 'ERROR',
        error: 'INVALID_RELAY_DATA',
        operationId,
        message: 'Faltan campos para enviar los datos.'
      });
      return;
    }

    const cacheKey = `${senderId}|${recipientId}|${linkId}`;
    const cached = this.peerAuthCache.get(cacheKey);
    const now = Date.now();
    const store = this.getDeviceStore();
    let effectiveSubscriptionUid: string | null = cached?.subscriptionUid || sender.subscriptionUid || null;

    if (!cached || now > cached.expiresAt) {
      if (!store) {
        this.sendJson(ws, { type: 'ERROR', error: 'SERVER_CONFIG_PENDING', operationId });
        return;
      }

      const authCheck = await verifyPeerCommunicationAuthorization(store, senderId, recipientId);
      if (!authCheck.authorized || !authCheck.link || authCheck.link.linkId !== linkId) {
        this.logEvent('RELAY_DATA_REJECTED_UNAUTH', {
          senderId,
          recipientId,
          reason: authCheck.reasonCode
        });

        if (authCheck.reasonCode === 'DEVICE_REVOKED') {
          this.sendJson(ws, {
            type: 'REVOCATION_NOTICE',
            message: 'Este dispositivo fue desvinculado en VEL CORE.',
            timestamp: Date.now()
          });
          ws.close(4003, 'Device revoked');
          return;
        }

        this.sendJson(ws, {
          type: 'DELIVERY_FAILED',
          operationId,
          recipientId,
          reason: authCheck.reasonCode || 'UNAUTHORIZED',
          message: 'No existe autorización activa entre ambos teléfonos.'
        });
        return;
      }

      effectiveSubscriptionUid =
        authCheck.link.subscriptionUid ||
        authCheck.device?.subscriptionUid ||
        authCheck.peerDevice?.subscriptionUid ||
        sender.subscriptionUid ||
        null;
      sender.subscriptionUid = effectiveSubscriptionUid;

      this.peerAuthCache.set(cacheKey, {
        linkId,
        subscriptionUid: effectiveSubscriptionUid,
        authorized: true,
        expiresAt: now + AUTH_CACHE_TTL_MS
      });
    }

    if (effectiveSubscriptionUid) {
      const subStatus = await this.checkSubscriptionAccess(store, effectiveSubscriptionUid, false);
      if (subStatus.linked && !subStatus.active) {
        if (subStatus.estado === 'cancelado') {
          this.invalidateAuthCacheForDevice(senderId);
          this.invalidateAuthCacheForDevice(recipientId);
          this.logEvent('RELAY_DATA_BLOCKED_ACCOUNT_DEACTIVATED', {
            senderId,
            recipientId
          });
          this.sendJson(ws, {
            type: 'REVOCATION_NOTICE',
            message: 'Tu cuenta VEL fue dada de baja. Los dispositivos quedaron desvinculados.',
            timestamp: Date.now()
          });
          ws.close(4003, 'Account deactivated');
          return;
        }
        this.logEvent('RELAY_DATA_BLOCKED_SUBSCRIPTION_EXPIRED', {
          senderId,
          recipientId,
          estado: subStatus.estado
        });
        this.sendJson(ws, {
          type: 'SUBSCRIPTION_STATUS',
          subscriptionStatus: subStatus,
          timestamp: Date.now()
        });
        const peerSocket = this.clients.get(recipientId)?.ws;
        if (peerSocket && peerSocket.readyState === WebSocket.OPEN) {
          this.sendJson(peerSocket, {
            type: 'SUBSCRIPTION_STATUS',
            subscriptionStatus: subStatus,
            timestamp: Date.now()
          });
        }
        this.sendJson(ws, {
          type: 'DELIVERY_FAILED',
          operationId,
          recipientId,
          reason: 'SUBSCRIPTION_EXPIRED',
          message:
            subStatus.reason ||
            'Tu período mensual venció. Tus copias siguen seguras; renueva en Blogger con Mercado Pago para reactivar el envío.'
        });
        return;
      }
    }

    const dedupeKey = `${senderId}|${recipientId}|${operationId}`;
    if (this.seenOperationIds.has(dedupeKey)) {
      this.sendJson(ws, { type: 'ERROR', error: 'DUPLICATE_OPERATION', operationId });
      return;
    }
    this.seenOperationIds.set(dedupeKey, now);

    const recipient = this.clients.get(recipientId);
    if (!recipient || recipient.ws.readyState !== WebSocket.OPEN) {
      this.sendJson(ws, {
        type: 'DELIVERY_FAILED',
        operationId,
        recipientId,
        reason: 'RECIPIENT_OFFLINE',
        message: 'El otro teléfono no está conectado ahora. Se enviará cuando vuelva a conectarse.'
      });
      return;
    }

    // Paso directo en memoria (nunca se persiste en disco, logs ni nube)
    this.sendJson(recipient.ws, {
      type: 'RELAY_DATA',
      senderId,
      recipientId,
      linkId,
      operationId,
      payload,
      timestamp
    });

    this.sendJson(ws, {
      type: 'MESSAGE_ROUTED',
      operationId,
      recipientId,
      timestamp: Date.now()
    });
  }

  private async handleRevokeDevice(ws: WebSocket, msg: Record<string, any>) {
    const sender = this.getAuthenticatedClient(ws);
    if (!sender || sender.role !== 'CORE') {
      this.sendJson(ws, {
        type: 'ERROR',
        error: 'UNAUTHORIZED_ACTION',
        message: 'Solo VEL CORE puede desvincular un móvil.'
      });
      return;
    }

    const coreId = String(msg.coreId || sender.deviceId).trim();
    const targetTerminalId = msg.targetTerminalId ? String(msg.targetTerminalId).trim() : null;
    const reason = String(msg.reason || 'Desvinculado por el usuario desde VEL CORE').trim();

    if (coreId !== sender.deviceId) {
      this.sendJson(ws, { type: 'ERROR', error: 'IDENTITY_MISMATCH' });
      return;
    }

    const store = this.getDeviceStore();
    if (!store) {
      this.sendJson(ws, { type: 'ERROR', error: 'SERVER_CONFIG_PENDING' });
      return;
    }

    const outcome = await revokeDeviceAuthorizationAtomic(store, sender.authUid, {
      coreDeviceId: sender.deviceId,
      targetTerminalId,
      reason
    });

    if (!outcome.ok) {
      this.sendJson(ws, {
        type: 'ERROR',
        error: outcome.code || 'REVOKE_FAILED',
        message: outcome.reason || 'No se pudo completar la desvinculación.'
      });
      return;
    }

    const revokedId = outcome.revokedTerminalId || targetTerminalId;
    this.invalidateAuthCacheForDevice(sender.deviceId);
    if (revokedId) this.invalidateAuthCacheForDevice(revokedId);

    let disconnectedLive = false;
    if (revokedId) {
      this.revocations.set(revokedId, {
        terminalId: revokedId,
        revokedByCoreId: sender.deviceId,
        revokedAt: Date.now(),
        reason
      });
      this.authorizations.delete(revokedId);

      const activeTerminal = this.clients.get(revokedId);
      if (activeTerminal && activeTerminal.ws.readyState === WebSocket.OPEN) {
        disconnectedLive = true;
        try {
          this.sendJson(activeTerminal.ws, {
            type: 'REVOCATION_NOTICE',
            message: 'Este móvil fue desvinculado desde VEL CORE.',
            timestamp: Date.now()
          });
          activeTerminal.ws.close(4003, 'Revoked by CORE');
        } catch {}
        this.clients.delete(revokedId);
      } else if (activeTerminal) {
        this.clients.delete(revokedId);
      }
    }

    sender.activeLinkId = null;
    sender.pairedPeerDeviceId = null;

    this.logEvent('DEVICE_REVOKED', {
      coreDeviceId: sender.deviceId,
      revokedTerminalId: revokedId || 'none',
      disconnectedLive
    });

    this.sendJson(ws, {
      type: 'REVOCATION_CONFIRMED',
      targetTerminalId: revokedId,
      revokedLinkId: outcome.revokedLinkId || null,
      persistedInFirestore: true,
      disconnectedLive,
      timestamp: Date.now()
    });
  }

  public getActiveClientCount(): number {
    return this.clients.size;
  }

  public isRevoked(deviceId: string): boolean {
    return this.revocations.has(deviceId);
  }
}

const isMainModule =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  import.meta.url === `file://${path.resolve(process.argv[1])}`;

if (isMainModule) {
  const port = parseInt(process.env.PORT || process.env.RELAY_PORT || '8080', 10);
  const server = new VelRelayServer({ port });

  const gracefulShutdown = async (signal: string) => {
    console.log(`[VEL-Relay] Señal ${signal} recibida. Cerrando conexiones limpiamente...`);
    await server.stop();
    process.exit(0);
  };

  process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => void gracefulShutdown('SIGINT'));

  server.start().then((actualPort) => {
    console.log(
      `[VEL-Relay] Servidor WebSocket directo activo en puerto ${actualPort} (/health disponible)`
    );
  });
}
