import {
  DeviceIdentitySummary,
  EncryptedRelayPayload,
  PairingSessionContract,
  RelayClientContract,
  RelayConnectionState,
  RelayDataPayload,
  RevocationStatus,
  SubscriptionRuntimeStatus
} from '../contracts/velContracts';
import {
  decryptAesGcmJson,
  deriveSharedAesGcmKey,
  encryptAesGcmJson
} from '../crypto/deviceCrypto';
import { velDb, VelStorageAdapter } from '../db/db';
import { getFreshDeviceAuthToken } from './firebase';

export interface RelayClientSnapshot {
  connectionState: RelayConnectionState;
  peerOnline: boolean;
  identity: DeviceIdentitySummary | null;
  pairingSession: PairingSessionContract | null;
  subscriptionStatus: SubscriptionRuntimeStatus | null;
  lastError: string | null;
  lastRevocationMessage: string | null;
  revocationStatus: RevocationStatus;
  revocationDetail: string | null;
}

export type VelUiConnectionStatus =
  | 'SIN_CONEXION'
  | 'CONECTANDO'
  | 'CONECTADO'
  | 'ESTADO_DESCONOCIDO'
  | 'REVOCADO';

export function getVelConnectionDisplayStatus(params: {
  isNetworkOnline: boolean;
  connectionState: RelayConnectionState;
  revocationStatus?: RevocationStatus;
  registrationStatus?: string | null;
}): { code: VelUiConnectionStatus; label: string } {
  if (params.registrationStatus === 'revoked' || params.connectionState === 'REVOKED') {
    return { code: 'REVOCADO', label: 'DESVINCULADO' };
  }
  if (!params.isNetworkOnline || params.connectionState === 'DISCONNECTED') {
    return { code: 'SIN_CONEXION', label: 'SIN CONEXIÓN' };
  }
  if (params.connectionState === 'ERROR' || params.revocationStatus === 'UNKNOWN') {
    return { code: 'ESTADO_DESCONOCIDO', label: 'ESTADO DESCONOCIDO' };
  }
  if (
    params.connectionState === 'CONNECTING' ||
    params.connectionState === 'RECONNECTING' ||
    params.connectionState === 'CONNECTED_UNAUTHENTICATED' ||
    params.connectionState === 'AUTHENTICATING'
  ) {
    return { code: 'CONECTANDO', label: 'CONECTANDO' };
  }
  return { code: 'CONECTADO', label: 'CONECTADO' };
}

export interface VelRelayClientOptions {
  storage?: VelStorageAdapter;
  getFirebaseIdToken?: () => Promise<string | null>;
  fetchFn?: typeof fetch;
  WebSocketImpl?: any;
  reconnectBaseDelayMs?: number;
  reconnectMaxDelayMs?: number;
  isNetworkOnline?: () => boolean;
  heartbeatIntervalMs?: number;
  heartbeatTimeoutMs?: number;
}

export interface SendRelayPayloadResult {
  routed: boolean;
  operationId: string;
  reason?: string;
  error?: string;
}

export interface RevokeOutcome {
  success: boolean;
  persistedInFirestore: boolean;
  disconnectedLive: boolean;
  revocationStatus?: RevocationStatus;
  revocationDetail?: string;
  error?: string;
}

export type IncomingRelayDataHandler = (msg: {
  senderId: string;
  recipientId: string;
  linkId: string;
  operationId: string;
  payload: RelayDataPayload;
  timestamp: number;
}) => void | Promise<void>;

const MAX_SEEN_OP_IDS = 4000;

export function generateNumericPairingCode(): string {
  const bytes = new Uint8Array(6);
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 6; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += String(bytes[i] % 10);
  }
  return code;
}

function createOperationId(): string {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return `op-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function resolveBoundFetch(customFetch?: typeof fetch): typeof fetch {
  if (!customFetch || (typeof globalThis !== 'undefined' && customFetch === globalThis.fetch)) {
    return (...args: Parameters<typeof fetch>) => globalThis.fetch(...args);
  }
  return (...args: Parameters<typeof fetch>) => customFetch(...args);
}

export class VelRelayClient implements RelayClientContract {
  private storage: VelStorageAdapter;
  private tokenProvider: () => Promise<string | null>;
  private fetchFn: typeof fetch;
  private WebSocketCtor: any;
  private reconnectBaseDelayMs: number;
  private reconnectMaxDelayMs: number;
  private isNetworkOnlineFn: () => boolean;
  private heartbeatIntervalMs: number;
  private heartbeatTimeoutMs: number;

  private ws: any = null;
  private wssUrl: string | null = null;
  private state: RelayConnectionState = 'DISCONNECTED';
  private peerOnline = false;
  private manualDisconnect = false;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private heartbeatTimeoutTimer: ReturnType<typeof setTimeout> | null = null;
  private authAttemptSeq = 0;
  private isConnectingGuard = false;

  private currentIdentity: DeviceIdentitySummary | null = null;
  private pairingSession: PairingSessionContract | null = null;
  private subscriptionStatus: SubscriptionRuntimeStatus | null = null;
  private seenIncomingOperationIds = new Set<string>();

  private lastError: string | null = null;
  private lastRevocationMessage: string | null = null;
  private revocationStatus: RevocationStatus = 'NONE';
  private revocationDetail: string | null = null;

  private dataHandler: IncomingRelayDataHandler | null = null;
  private cachedSharedKey: {
    linkId: string;
    peerDeviceId: string;
    peerPublicKeySpkiBase64: string;
    aesKey: CryptoKey;
  } | null = null;
  private pendingRouteWaiters = new Map<
    string,
    { resolve: (res: SendRelayPayloadResult) => void; timer: ReturnType<typeof setTimeout> }
  >();
  private pendingRevokeContext: {
    resolve: (res: RevokeOutcome) => void;
    fallbackToHttp: () => void;
  } | null = null;

  private stateListeners = new Set<(state: RelayConnectionState) => void>();
  private snapshotListeners = new Set<(snapshot: RelayClientSnapshot) => void>();
  private connectionLostListeners = new Set<(reason: string) => void>();
  private securityErrorListeners = new Set<(reason: string) => void>();

  constructor(options: VelRelayClientOptions = {}) {
    this.storage = options.storage || velDb;
    this.tokenProvider = options.getFirebaseIdToken || getFreshDeviceAuthToken;
    this.fetchFn = resolveBoundFetch(options.fetchFn);
    this.WebSocketCtor = options.WebSocketImpl || (typeof WebSocket !== 'undefined' ? WebSocket : null);
    this.reconnectBaseDelayMs = options.reconnectBaseDelayMs ?? 1_000;
    this.reconnectMaxDelayMs = options.reconnectMaxDelayMs ?? 30_000;
    this.isNetworkOnlineFn =
      options.isNetworkOnline ||
      (() => (typeof navigator === 'undefined' ? true : navigator.onLine !== false));
    this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? 25_000;
    this.heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? 10_000;
  }

  public getState(): RelayConnectionState {
    return this.state;
  }

  public getSnapshot(): RelayClientSnapshot {
    return {
      connectionState: this.state,
      peerOnline: this.peerOnline,
      identity: this.currentIdentity ? { ...this.currentIdentity } : null,
      pairingSession: this.pairingSession ? { ...this.pairingSession } : null,
      subscriptionStatus: this.subscriptionStatus ? { ...this.subscriptionStatus } : null,
      lastError: this.lastError,
      lastRevocationMessage: this.lastRevocationMessage,
      revocationStatus: this.revocationStatus,
      revocationDetail: this.revocationDetail
    };
  }

  public onStateChange(listener: (state: RelayConnectionState) => void): () => void {
    this.stateListeners.add(listener);
    return () => this.stateListeners.delete(listener);
  }

  public subscribe(listener: (snapshot: RelayClientSnapshot) => void): () => void {
    this.snapshotListeners.add(listener);
    listener(this.getSnapshot());
    return () => this.snapshotListeners.delete(listener);
  }

  public setDataHandler(handler: IncomingRelayDataHandler | null): void {
    this.dataHandler = handler;
  }

  public onConnectionLost(listener: (reason: string) => void): () => void {
    this.connectionLostListeners.add(listener);
    return () => this.connectionLostListeners.delete(listener);
  }

  public onSecurityError(listener: (reason: string) => void): () => void {
    this.securityErrorListeners.add(listener);
    return () => this.securityErrorListeners.delete(listener);
  }

  private emitSecurityError(reason: string) {
    this.lastError = reason;
    this.emit();
    for (const l of this.securityErrorListeners) {
      try {
        l(reason);
      } catch {}
    }
  }

  private invalidateSharedKeyCache() {
    this.cachedSharedKey = null;
  }

  private async getOrDeriveSharedKey(): Promise<{ aesKey: CryptoKey; linkId: string; peerDeviceId: string } | null> {
    const local = await this.storage.getIdentity();
    if (
      !local ||
      !local.activeLinkId ||
      !local.pairedPeerDeviceId ||
      !local.pairedPeerPublicKeySpkiBase64 ||
      !local.privateEcdhKey
    ) {
      return null;
    }

    const peerPub = local.pairedPeerPublicKeySpkiBase64.trim();
    if (
      this.cachedSharedKey &&
      this.cachedSharedKey.linkId === local.activeLinkId &&
      this.cachedSharedKey.peerDeviceId === local.pairedPeerDeviceId &&
      this.cachedSharedKey.peerPublicKeySpkiBase64 === peerPub
    ) {
      return {
        aesKey: this.cachedSharedKey.aesKey,
        linkId: local.activeLinkId,
        peerDeviceId: local.pairedPeerDeviceId
      };
    }

    const aesKey = await deriveSharedAesGcmKey(local.privateEcdhKey, peerPub);
    this.cachedSharedKey = {
      linkId: local.activeLinkId,
      peerDeviceId: local.pairedPeerDeviceId,
      peerPublicKeySpkiBase64: peerPub,
      aesKey
    };

    return {
      aesKey,
      linkId: local.activeLinkId,
      peerDeviceId: local.pairedPeerDeviceId
    };
  }

  private emit() {
    const snap = this.getSnapshot();
    for (const l of this.stateListeners) l(this.state);
    for (const l of this.snapshotListeners) l(snap);
  }

  private setState(next: RelayConnectionState) {
    this.state = next;
    this.emit();
  }

  private syncSummaryFromLocal(local: any) {
    this.currentIdentity = {
      deviceId: local.deviceId,
      role: local.role,
      fingerprint: local.fingerprint,
      publicKeySpkiBase64: local.publicKeySpkiBase64,
      signingPublicKeySpkiBase64: local.signingPublicKeySpkiBase64,
      firebaseAuthUid: local.firebaseAuthUid,
      registrationStatus: local.registrationStatus,
      activeLinkId: local.activeLinkId,
      pairedPeerDeviceId: local.pairedPeerDeviceId,
      pairedPeerPublicKeySpkiBase64: local.pairedPeerPublicKeySpkiBase64 ?? null,
      subscriptionUid: local.subscriptionUid ?? null,
      lastServerError: local.lastServerError,
      createdAt: local.createdAt,
      updatedAt: local.updatedAt
    };
  }

  private clearReconnectTimer() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = null;
    }
  }

  private clearHeartbeatWait() {
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = null;
    }
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    if (this.heartbeatIntervalMs <= 0) return;

    const timer = setInterval(() => {
      if (!this.ws || this.ws.readyState !== 1) return;
      if (!this.isNetworkOnlineFn()) {
        this.notifyNetworkOffline();
        return;
      }
      const sent = this.sendRaw({ type: 'PING', timestamp: Date.now() });
      if (!sent) return;

      this.clearHeartbeatWait();
      const waitTimer = setTimeout(() => {
        if (!this.ws) return;
        this.closeActiveSocketSilently();
        this.peerOnline = false;
        this.abortPendingWaiters('HEARTBEAT_TIMEOUT');
        if (!this.manualDisconnect && this.state !== 'REVOKED') {
          this.lastError = 'Se perdió respuesta del servidor Relay.';
          this.scheduleReconnect();
        }
      }, this.heartbeatTimeoutMs);
      (waitTimer as any)?.unref?.();
      this.heartbeatTimeoutTimer = waitTimer;
    }, this.heartbeatIntervalMs);
    (timer as any)?.unref?.();
    this.heartbeatTimer = timer;
  }

  private abortPendingWaiters(reason: string) {
    for (const [opId, waiter] of this.pendingRouteWaiters.entries()) {
      clearTimeout(waiter.timer);
      this.pendingRouteWaiters.delete(opId);
      waiter.resolve({
        routed: false,
        operationId: opId,
        reason,
        error: `Conexión interrumpida (${reason}).`
      });
    }
    if (this.pendingRevokeContext) {
      const ctx = this.pendingRevokeContext;
      this.pendingRevokeContext = null;
      this.revocationStatus = 'UNKNOWN';
      this.revocationDetail =
        'ESTADO DESCONOCIDO: se perdió la conexión antes de confirmar la revocación en el servidor.';
      ctx.resolve({
        success: false,
        persistedInFirestore: false,
        disconnectedLive: false,
        revocationStatus: this.revocationStatus,
        revocationDetail: this.revocationDetail,
        error: this.revocationDetail
      });
    }
    for (const l of this.connectionLostListeners) {
      try {
        l(reason);
      } catch {}
    }
  }

  private recordSeenOperationId(operationId: string) {
    this.seenIncomingOperationIds.add(operationId);
    if (this.seenIncomingOperationIds.size > MAX_SEEN_OP_IDS) {
      const excess = this.seenIncomingOperationIds.size - MAX_SEEN_OP_IDS;
      let removed = 0;
      for (const id of this.seenIncomingOperationIds) {
        this.seenIncomingOperationIds.delete(id);
        removed++;
        if (removed >= excess) break;
      }
    }
  }

  public notifyNetworkOffline(): void {
    this.clearReconnectTimer();
    this.stopHeartbeat();
    this.peerOnline = false;
    this.closeActiveSocketSilently();
    this.abortPendingWaiters('NETWORK_OFFLINE');
    if (this.state !== 'REVOKED' && this.currentIdentity?.registrationStatus !== 'revoked') {
      this.lastError = 'Sin conexión a internet.';
      this.setState('DISCONNECTED');
    } else {
      this.emit();
    }
  }

  public notifyNetworkOnline(): void {
    if (
      this.manualDisconnect ||
      !this.wssUrl ||
      this.state === 'REVOKED' ||
      this.currentIdentity?.registrationStatus === 'revoked'
    ) {
      return;
    }
    if (!this.isNetworkOnlineFn()) return;
    if (
      this.isConnectingGuard ||
      (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1))
    ) {
      return;
    }
    this.reconnectAttempts = 0;
    this.clearReconnectTimer();
    void this.openConnection();
  }

  public connect(wssUrl: string, firebaseIdTokenProvider?: () => Promise<string | null>): void {
    const cleanUrl = wssUrl.trim();
    if (firebaseIdTokenProvider) {
      this.tokenProvider = firebaseIdTokenProvider;
    }
    if (this.state === 'REVOKED' || this.currentIdentity?.registrationStatus === 'revoked') {
      return;
    }
    this.wssUrl = cleanUrl;
    this.manualDisconnect = false;

    if (!this.isNetworkOnlineFn()) {
      this.clearReconnectTimer();
      this.peerOnline = false;
      this.lastError = 'Sin conexión a internet.';
      this.setState('DISCONNECTED');
      return;
    }

    if (
      this.wssUrl === cleanUrl &&
      (this.isConnectingGuard || (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1)))
    ) {
      return;
    }
    this.clearReconnectTimer();
    void this.openConnection();
  }

  public forceReconnect(): void {
    if (
      !this.wssUrl ||
      this.state === 'REVOKED' ||
      this.currentIdentity?.registrationStatus === 'revoked'
    ) {
      return;
    }
    this.manualDisconnect = false;
    this.reconnectAttempts = 0;
    this.clearReconnectTimer();
    if (!this.isNetworkOnlineFn()) {
      this.notifyNetworkOffline();
      return;
    }
    this.closeActiveSocketSilently();
    void this.openConnection();
  }

  private async openConnection() {
    if (this.isConnectingGuard) return;
    if (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1)) return;
    this.isConnectingGuard = true;
    try {
      if (!this.wssUrl) {
        this.lastError = 'No hay dirección del servidor Relay configurada.';
        this.setState('ERROR');
        return;
      }
      if (!this.WebSocketCtor) {
        this.lastError = 'WebSocket no está disponible en este navegador.';
        this.setState('ERROR');
        return;
      }

      const local = await this.storage.getIdentity();
      if (!local) {
        this.setState('DISCONNECTED');
        return;
      }

      this.syncSummaryFromLocal(local);

      if (local.registrationStatus === 'revoked') {
        this.lastRevocationMessage = 'Este teléfono fue desvinculado desde VEL CORE.';
        this.setState('REVOKED');
        return;
      }

      if (local.registrationStatus === 'pending_local') {
        this.lastError = 'Esperando completar el registro en la nube.';
        this.setState('DISCONNECTED');
        return;
      }

      if (!this.isNetworkOnlineFn()) {
        this.peerOnline = false;
        this.lastError = 'Sin conexión a internet.';
        this.setState('DISCONNECTED');
        return;
      }

      this.closeActiveSocketSilently();
      this.lastError = null;
      this.setState(this.reconnectAttempts > 0 ? 'RECONNECTING' : 'CONNECTING');

      const socket = new this.WebSocketCtor(this.wssUrl);
      this.ws = socket;

      const attachHandler = (eventName: string, fn: (...args: any[]) => void) => {
        if (typeof socket.addEventListener === 'function') {
          socket.addEventListener(eventName, fn);
        } else if (typeof socket.on === 'function') {
          socket.on(eventName, fn);
        }
      };

      attachHandler('open', () => {
        if (this.ws !== socket) return;
        this.setState('CONNECTED_UNAUTHENTICATED');
        // Autenticar de inmediato con token Firebase (sin depender de firma ECDSA)
        void this.sendAuth();
      });

      attachHandler('message', (evtOrData: any) => {
        if (this.ws !== socket) return;
        const raw = evtOrData && typeof evtOrData === 'object' && 'data' in evtOrData ? evtOrData.data : evtOrData;
        const text = typeof raw === 'string' ? raw : raw?.toString?.('utf8') || '';
        if (!text) return;
        try {
          const msg = JSON.parse(text);
          void this.handleServerMessage(msg);
        } catch {
          this.lastError = 'Respuesta inválida recibida desde el servidor Relay.';
          this.emit();
        }
      });

      attachHandler('error', () => {
        if (this.ws !== socket) return;
        if (this.state !== 'REVOKED') {
          this.lastError = 'No se pudo conectar con el servidor de enlace.';
          this.emit();
        }
      });

      attachHandler('close', (evtOrCode: any) => {
        if (this.ws !== socket) return;
        const code =
          typeof evtOrCode === 'number'
            ? evtOrCode
            : typeof evtOrCode?.code === 'number'
            ? evtOrCode.code
            : 1000;

        this.stopHeartbeat();
        this.ws = null;
        this.peerOnline = false;
        this.abortPendingWaiters(code === 4003 ? 'DEVICE_REVOKED' : 'RELAY_DISCONNECTED');

        if (this.manualDisconnect) {
          this.setState('DISCONNECTED');
          return;
        }
        if (this.state === 'REVOKED' || code === 4003) {
          if (this.state !== 'ERROR') {
            this.setState('REVOKED');
          }
          return;
        }
        if (code === 4503 || code === 4001) {
          this.lastError = 'No se pudo validar la sesión con el servidor.';
          this.setState('ERROR');
          return;
        }
        if (code === 4009) {
          this.lastError = 'Este teléfono se abrió en otra pestaña.';
          this.setState('DISCONNECTED');
          return;
        }
        if (!this.isNetworkOnlineFn()) {
          this.lastError = 'Sin conexión a internet.';
          this.setState('DISCONNECTED');
          return;
        }
        this.scheduleReconnect();
      });
    } finally {
      this.isConnectingGuard = false;
    }
  }

  private scheduleReconnect() {
    this.clearReconnectTimer();
    if (
      this.manualDisconnect ||
      !this.wssUrl ||
      this.state === 'REVOKED' ||
      this.currentIdentity?.registrationStatus === 'revoked'
    ) {
      return;
    }
    if (!this.isNetworkOnlineFn()) {
      this.lastError = 'Sin conexión a internet.';
      this.setState('DISCONNECTED');
      return;
    }

    const delay = Math.min(
      this.reconnectMaxDelayMs,
      this.reconnectBaseDelayMs * Math.pow(2, Math.min(this.reconnectAttempts, 5))
    );
    this.reconnectAttempts += 1;
    this.setState('RECONNECTING');

    const timer = setTimeout(() => {
      void this.openConnection();
    }, delay);
    (timer as any)?.unref?.();
    this.reconnectTimer = timer;
  }

  private closeActiveSocketSilently() {
    this.stopHeartbeat();
    if (!this.ws) return;
    const oldWs = this.ws;
    this.ws = null;
    try {
      oldWs.close(1000, 'Reconnecting');
    } catch {}
  }

  public disconnect(): void {
    this.manualDisconnect = true;
    this.clearReconnectTimer();
    this.stopHeartbeat();
    this.abortPendingWaiters('MANUAL_DISCONNECT');
    this.peerOnline = false;
    if (this.ws) {
      const target = this.ws;
      this.ws = null;
      try {
        target.close(1000, 'Client disconnect');
      } catch {}
    }
    this.setState('DISCONNECTED');
  }

  private sendRaw(payload: Record<string, unknown>): boolean {
    if (!this.ws || this.ws.readyState !== 1) return false;
    try {
      this.ws.send(JSON.stringify(payload));
      return true;
    } catch {
      return false;
    }
  }

  private async sendAuth(challenge?: string) {
    if (this.state === 'AUTHENTICATING' || this.state === 'AUTHENTICATED' || this.state === 'LINKED') {
      return;
    }
    const targetSocket = this.ws;
    const attemptId = ++this.authAttemptSeq;
    try {
      const local = await this.storage.getIdentity();
      if (!local) {
        this.lastError = 'Identidad local no disponible.';
        this.setState('ERROR');
        return;
      }

      if (local.registrationStatus === 'revoked') {
        this.lastRevocationMessage = 'Este teléfono fue desvinculado desde VEL CORE.';
        this.closeActiveSocketSilently();
        this.setState('REVOKED');
        return;
      }

      this.setState('AUTHENTICATING');

      const firebaseIdToken = await this.tokenProvider();
      if (
        this.ws !== targetSocket ||
        !targetSocket ||
        targetSocket.readyState !== 1 ||
        attemptId !== this.authAttemptSeq
      ) {
        return;
      }
      if (!firebaseIdToken) {
        this.lastError = 'No se pudo obtener la sesión de Firebase.';
        this.setState('ERROR');
        return;
      }

      const sent = this.sendRaw({
        type: 'AUTH',
        deviceId: local.deviceId,
        role: local.role,
        pairedCoreId: local.role === 'TERMINAL' ? local.pairedPeerDeviceId : null,
        firebaseIdToken,
        challenge: challenge || undefined,
        timestamp: Date.now()
      });

      if (!sent) {
        this.lastError = 'Se cerró la conexión antes de autenticar.';
        this.setState('ERROR');
      }
    } catch (err: any) {
      this.lastError = err?.message || 'Error preparando conexión con el servidor Relay.';
      this.setState('ERROR');
    }
  }

  private async handleServerMessage(msg: Record<string, any>) {
    this.clearHeartbeatWait();
    switch (msg.type) {
      case 'PONG':
        return;

      case 'AUTH_CHALLENGE':
        if (this.state === 'CONNECTED_UNAUTHENTICATED') {
          await this.sendAuth(String(msg.challenge || ''));
        }
        return;

      case 'AUTH_SUCCESS':
        await this.onAuthSuccess(msg);
        return;

      case 'AUTH_ERROR':
        await this.onAuthError(msg);
        return;

      case 'PEER_STATUS':
        this.peerOnline = Boolean(msg.online);
        this.emit();
        return;

      case 'PAIRING_OFFER_REGISTERED':
        if (this.pairingSession && this.pairingSession.code === String(msg.code || '').toUpperCase()) {
          this.pairingSession = {
            ...this.pairingSession,
            linkId: msg.linkId ? String(msg.linkId) : this.pairingSession.linkId,
            expiresAt: Number(msg.expiresAt || this.pairingSession.expiresAt),
            stage: 'OFFERING'
          };
          this.emit();
        }
        return;

      case 'PAIRING_CONFIRMED':
        await this.onPairingConfirmed(msg);
        return;

      case 'PAIRING_CANCELLED':
        if (this.pairingSession) {
          this.pairingSession = {
            ...this.pairingSession,
            stage: 'CANCELLED'
          };
        }
        this.lastError =
          msg.reason === 'PEER_DISCONNECTED'
            ? 'El otro teléfono se desconectó antes de terminar.'
            : 'Conexión cancelada.';
        this.emit();
        return;

      case 'SUBSCRIPTION_STATUS':
        if (msg.subscriptionStatus && typeof msg.subscriptionStatus === 'object') {
          this.subscriptionStatus = msg.subscriptionStatus as SubscriptionRuntimeStatus;
          this.emit();
        }
        return;

      case 'PAIRING_ERROR':
        if (msg.error === 'SUBSCRIPTION_EXPIRED') {
          this.subscriptionStatus =
            (msg.subscriptionStatus as SubscriptionRuntimeStatus) || {
              linked: true,
              active: false,
              estado: 'vencido',
              reason: String(msg.message || 'Suscripción mensual vencida.')
            };
        }
        if (this.pairingSession) {
          this.pairingSession = {
            ...this.pairingSession,
            stage: msg.error === 'OFFER_EXPIRED' ? 'EXPIRED' : 'CANCELLED'
          };
        }
        this.lastError = String(msg.message || 'No se pudo completar la conexión.');
        this.emit();
        return;

      case 'MESSAGE_ROUTED': {
        const opId = String(msg.operationId || '');
        const waiter = this.pendingRouteWaiters.get(opId);
        if (waiter) {
          clearTimeout(waiter.timer);
          this.pendingRouteWaiters.delete(opId);
          waiter.resolve({ routed: true, operationId: opId });
        }
        return;
      }

      case 'DELIVERY_FAILED': {
        const opId = String(msg.operationId || '');
        const reason = String(msg.reason || 'DELIVERY_FAILED');
        if (reason === 'SUBSCRIPTION_EXPIRED') {
          this.subscriptionStatus = {
            linked: true,
            active: false,
            estado: 'vencido',
            reason: String(msg.message || 'Tu suscripción mensual venció. Renueva en Blogger para reactivar el envío.')
          };
          this.emit();
        }
        const waiter = this.pendingRouteWaiters.get(opId);
        if (waiter) {
          clearTimeout(waiter.timer);
          this.pendingRouteWaiters.delete(opId);
          waiter.resolve({
            routed: false,
            operationId: opId,
            reason,
            error: String(msg.message || 'No se pudo entregar al otro teléfono.')
          });
        }
        return;
      }

      case 'RELAY_DATA':
        await this.onIncomingRelayData(msg);
        return;

      case 'REVOCATION_NOTICE':
        await this.onRevokedNotice(msg);
        return;

      case 'REVOCATION_CONFIRMED':
        await this.onRevocationConfirmed(msg);
        return;

      case 'ERROR':
        if (msg.operationId) {
          const opId = String(msg.operationId);
          const waiter = this.pendingRouteWaiters.get(opId);
          if (waiter) {
            clearTimeout(waiter.timer);
            this.pendingRouteWaiters.delete(opId);
            waiter.resolve({
              routed: false,
              operationId: opId,
              reason: String(msg.error || 'RELAY_ERROR'),
              error: String(msg.message || 'Error en el servidor Relay.')
            });
            return;
          }
        }
        if (this.pendingRevokeContext) {
          const ctx = this.pendingRevokeContext;
          const errCode = String(msg.error || 'RELAY_ERROR');
          const errMsg = String(msg.message || errCode || 'Error en el servidor Relay.');
          if (errCode === 'SERVER_CONFIG_PENDING') {
            ctx.fallbackToHttp();
            return;
          }
          this.pendingRevokeContext = null;
          this.revocationStatus = 'UNKNOWN';
          this.revocationDetail = `ESTADO DESCONOCIDO: ${errMsg}`;
          this.lastError = errMsg;
          this.emit();
          ctx.resolve({
            success: false,
            persistedInFirestore: false,
            disconnectedLive: false,
            revocationStatus: this.revocationStatus,
            revocationDetail: this.revocationDetail,
            error: errMsg
          });
          return;
        }
        this.lastError = String(msg.message || msg.error || 'Error en el servidor Relay.');
        this.emit();
        return;

      default:
        return;
    }
  }

  private async onAuthSuccess(msg: Record<string, any>) {
    this.reconnectAttempts = 0;
    this.lastError = null;
    this.peerOnline = Boolean(msg.peerOnline);
    if (msg.subscriptionStatus && typeof msg.subscriptionStatus === 'object') {
      this.subscriptionStatus = msg.subscriptionStatus as SubscriptionRuntimeStatus;
    }

    const local = await this.storage.getIdentity();
    if (!local) return;

    const activeLinkId = msg.activeLinkId ? String(msg.activeLinkId) : null;
    const pairedPeerDeviceId = msg.pairedPeerDeviceId ? String(msg.pairedPeerDeviceId) : null;
    const linkInfo = msg.link as
      | {
          corePublicKeySpkiBase64?: string | null;
          terminalPublicKeySpkiBase64?: string | null;
        }
      | null
      | undefined;
    const rawPeerPub =
      local.role === 'CORE' ? linkInfo?.terminalPublicKeySpkiBase64 : linkInfo?.corePublicKeySpkiBase64;
    const pairedPeerPublicKeySpkiBase64 =
      activeLinkId && pairedPeerDeviceId
        ? typeof rawPeerPub === 'string' && rawPeerPub.trim()
          ? rawPeerPub.trim()
          : local.pairedPeerDeviceId === pairedPeerDeviceId
          ? local.pairedPeerPublicKeySpkiBase64 ?? null
          : null
        : null;

    if (!activeLinkId || !pairedPeerDeviceId) {
      this.invalidateSharedKeyCache();
    }

    const updated = {
      ...local,
      registrationStatus: activeLinkId ? ('paired' as const) : ('registered' as const),
      activeLinkId,
      pairedPeerDeviceId,
      pairedPeerPublicKeySpkiBase64,
      lastServerError: null,
      updatedAt: new Date().toISOString()
    };

    await this.storage.saveIdentity(updated);
    this.syncSummaryFromLocal(updated);

    if (activeLinkId && pairedPeerDeviceId) {
      this.setState('LINKED');
    } else {
      this.setState('AUTHENTICATED');
    }
    this.startHeartbeat();
  }

  private async onAuthError(msg: Record<string, any>) {
    const code = String(msg.error || '');
    const message = String(msg.message || 'Error de autenticación en el Relay.');
    this.lastError = message;

    if (code === 'DEVICE_REVOKED') {
      this.invalidateSharedKeyCache();
      const local = await this.storage.getIdentity();
      if (local) {
        const updated = {
          ...local,
          registrationStatus: 'revoked' as const,
          activeLinkId: null,
          pairedPeerDeviceId: null,
          pairedPeerPublicKeySpkiBase64: null,
          lastServerError: message,
          updatedAt: new Date().toISOString()
        };
        await this.storage.saveIdentity(updated);
        this.syncSummaryFromLocal(updated);
      }
      this.lastRevocationMessage = message;
      this.setState('REVOKED');
      return;
    }

    this.setState('ERROR');
  }

  private async onRevokedNotice(msg: Record<string, any>) {
    const message = String(msg.message || 'Este móvil fue desvinculado desde VEL CORE.');
    this.lastRevocationMessage = message;
    this.peerOnline = false;
    this.pairingSession = null;
    this.invalidateSharedKeyCache();

    const local = await this.storage.getIdentity();
    if (local) {
      const updated = {
        ...local,
        registrationStatus: 'revoked' as const,
        activeLinkId: null,
        pairedPeerDeviceId: null,
        pairedPeerPublicKeySpkiBase64: null,
        lastServerError: message,
        updatedAt: new Date().toISOString()
      };
      await this.storage.saveIdentity(updated);
      this.syncSummaryFromLocal(updated);
    }
    this.setState('REVOKED');
  }

  private async onRevocationConfirmed(msg: Record<string, any>) {
    const persistedInFirestore = Boolean(msg.persistedInFirestore);
    const disconnectedLive = Boolean(msg.disconnectedLive);

    if (!persistedInFirestore) {
      this.revocationStatus = 'UNKNOWN';
      this.revocationDetail =
        'ESTADO DESCONOCIDO: el servidor no confirmó el registro de la revocación.';
      this.emit();
      if (this.pendingRevokeContext) {
        const ctx = this.pendingRevokeContext;
        this.pendingRevokeContext = null;
        ctx.resolve({
          success: false,
          persistedInFirestore: false,
          disconnectedLive: false,
          revocationStatus: this.revocationStatus,
          revocationDetail: this.revocationDetail,
          error: this.revocationDetail
        });
      }
      return;
    }

    this.peerOnline = false;
    this.pairingSession = null;
    this.invalidateSharedKeyCache();
    const local = await this.storage.getIdentity();
    if (local) {
      const updated = {
        ...local,
        registrationStatus: 'registered' as const,
        activeLinkId: null,
        pairedPeerDeviceId: null,
        pairedPeerPublicKeySpkiBase64: null,
        updatedAt: new Date().toISOString()
      };
      await this.storage.saveIdentity(updated);
      this.syncSummaryFromLocal(updated);
    }

    this.revocationStatus = disconnectedLive ? 'CONFIRMED' : 'PERSISTED_PEER_OFFLINE';
    this.revocationDetail = disconnectedLive
      ? 'El móvil anterior fue revocado y desconectado en vivo.'
      : 'REVOCACIÓN PENDIENTE: el móvil anterior está desconectado. El servidor bloqueó su acceso para cuando intente conectarse.';

    this.setState('AUTHENTICATED');

    if (this.pendingRevokeContext) {
      const ctx = this.pendingRevokeContext;
      this.pendingRevokeContext = null;
      ctx.resolve({
        success: true,
        persistedInFirestore: true,
        disconnectedLive,
        revocationStatus: this.revocationStatus,
        revocationDetail: this.revocationDetail
      });
    }
  }

  public startCorePairingOffer(ttlMs = 5 * 60_000): PairingSessionContract | null {
    if (!this.currentIdentity || this.currentIdentity.role !== 'CORE') {
      this.lastError = 'Solo VEL CORE puede generar un código de conexión.';
      this.emit();
      return null;
    }
    if (!this.ws || this.ws.readyState !== 1 || (this.state !== 'AUTHENTICATED' && this.state !== 'LINKED')) {
      this.lastError = 'Esperando conexión con el servidor para generar el código.';
      this.emit();
      return null;
    }

    const code = generateNumericPairingCode();
    const expiresAt = Date.now() + ttlMs;

    const session: PairingSessionContract = {
      code,
      initiatorDeviceId: this.currentIdentity.deviceId,
      initiatorRole: 'CORE',
      stage: 'OFFERING',
      expiresAt
    };

    this.pairingSession = session;
    this.lastError = null;

    this.sendRaw({
      type: 'PAIRING_OFFER',
      code,
      initiatorDeviceId: this.currentIdentity.deviceId,
      expiresAt
    });

    this.emit();
    return session;
  }

  public claimPairingCode(rawCode: string): boolean {
    const code = rawCode.replace(/\s+/g, '').trim().toUpperCase();
    if (!this.currentIdentity || this.currentIdentity.role !== 'TERMINAL') {
      this.lastError = 'Solo VEL MÓVIL puede ingresar el código de VEL CORE.';
      this.emit();
      return false;
    }
    if (!/^\d{6}$/.test(code) && code.length < 4) {
      this.lastError = 'Ingresa el código numérico de 6 dígitos que aparece en tu VEL CORE.';
      this.emit();
      return false;
    }
    if (!this.ws || this.ws.readyState !== 1 || (this.state !== 'AUTHENTICATED' && this.state !== 'LINKED')) {
      this.lastError = 'Aún conectando con el servidor. Intenta en unos segundos.';
      this.emit();
      return false;
    }

    this.pairingSession = {
      code,
      initiatorDeviceId: '',
      initiatorRole: 'CORE',
      peerDeviceId: this.currentIdentity.deviceId,
      peerRole: 'TERMINAL',
      stage: 'CLAIMING',
      expiresAt: Date.now() + 5 * 60_000
    };
    this.lastError = null;

    this.sendRaw({
      type: 'PAIRING_CLAIM',
      code,
      claimerDeviceId: this.currentIdentity.deviceId
    });

    this.emit();
    return true;
  }

  public cancelPairing(): void {
    if (this.pairingSession) {
      this.sendRaw({
        type: 'PAIRING_CANCEL',
        code: this.pairingSession.code,
        reason: 'CANCELLED_BY_USER'
      });
    }
    this.pairingSession = null;
    this.emit();
  }

  public resetPairingSession(): void {
    this.pairingSession = null;
    this.lastError = null;
    this.emit();
  }

  private async onPairingConfirmed(msg: Record<string, any>) {
    const link = msg.link as
      | {
          linkId: string;
          coreDeviceId: string;
          terminalDeviceId: string;
          corePublicKeySpkiBase64?: string | null;
          terminalPublicKeySpkiBase64?: string | null;
        }
      | undefined;
    if (!link) return;

    const local = await this.storage.getIdentity();
    if (!local) return;

    const peerId = local.role === 'CORE' ? link.terminalDeviceId : link.coreDeviceId;
    const rawPeerPub =
      local.role === 'CORE' ? link.terminalPublicKeySpkiBase64 : link.corePublicKeySpkiBase64;
    const peerPublicKeySpkiBase64 =
      typeof rawPeerPub === 'string' && rawPeerPub.trim() ? rawPeerPub.trim() : null;

    this.invalidateSharedKeyCache();

    const updated = {
      ...local,
      registrationStatus: 'paired' as const,
      activeLinkId: link.linkId,
      pairedPeerDeviceId: peerId,
      pairedPeerPublicKeySpkiBase64: peerPublicKeySpkiBase64,
      lastServerError: null,
      updatedAt: new Date().toISOString()
    };

    await this.storage.saveIdentity(updated);
    this.syncSummaryFromLocal(updated);

    if (this.pairingSession) {
      this.pairingSession = {
        ...this.pairingSession,
        linkId: link.linkId,
        peerDeviceId: peerId,
        stage: 'CONFIRMED'
      };
    }

    this.peerOnline = true;
    this.lastError = null;
    this.revocationStatus = 'NONE';
    this.revocationDetail = null;
    this.setState('LINKED');
  }

  /**
   * Cifra el paquete con AES-256-GCM (clave compartida ECDH P-256) y lo envía
   * al otro teléfono conectado a través del Relay (sin guardar en la nube).
   * Si falla el cifrado, nunca envía información en texto claro.
   */
  public async sendRelayPayload(
    payload: RelayDataPayload,
    timeoutMs = 15_000
  ): Promise<SendRelayPayloadResult> {
    const operationId = createOperationId();

    if (this.state === 'REVOKED' || this.currentIdentity?.registrationStatus === 'revoked') {
      return {
        routed: false,
        operationId,
        reason: 'DEVICE_REVOKED',
        error: 'Este dispositivo fue revocado y no puede transferir información.'
      };
    }

    if (!this.isNetworkOnlineFn()) {
      return {
        routed: false,
        operationId,
        reason: 'NETWORK_OFFLINE',
        error: 'Sin conexión a internet.'
      };
    }

    if (this.state !== 'LINKED' || !this.ws || this.ws.readyState !== 1) {
      return {
        routed: false,
        operationId,
        reason: 'OFFLINE_OR_UNLINKED',
        error: 'El otro teléfono no está conectado todavía.'
      };
    }

    const identity = this.currentIdentity;
    if (!identity || !identity.activeLinkId || !identity.pairedPeerDeviceId) {
      return {
        routed: false,
        operationId,
        reason: 'NOT_PAIRED',
        error: 'Los teléfonos aún no están conectados.'
      };
    }

    const latestLocal = await this.storage.getIdentity();
    if (!latestLocal || latestLocal.registrationStatus === 'revoked') {
      return {
        routed: false,
        operationId,
        reason: 'DEVICE_REVOKED',
        error: 'Este dispositivo fue revocado y no puede transferir información.'
      };
    }

    let encryptedPayload: EncryptedRelayPayload;
    try {
      const keyCtx = await this.getOrDeriveSharedKey();
      if (!keyCtx || keyCtx.linkId !== identity.activeLinkId) {
        return {
          routed: false,
          operationId,
          reason: 'ENCRYPTION_FAILED',
          error: 'No se pudo derivar la clave compartida E2EE con el teléfono emparejado.'
        };
      }

      const aadText = `${identity.activeLinkId}|${payload.itemId}`;
      const encrypted = await encryptAesGcmJson(keyCtx.aesKey, payload, aadText);
      encryptedPayload = {
        kind: 'e2ee',
        v: 1,
        itemId: payload.itemId,
        ivBase64: encrypted.ivBase64,
        ciphertextBase64: encrypted.ciphertextBase64
      };
    } catch (err: any) {
      const msg = err?.message || 'Falló el cifrado AES-256-GCM; no se enviaron datos en texto claro.';
      this.emitSecurityError(msg);
      return {
        routed: false,
        operationId,
        reason: 'ENCRYPTION_FAILED',
        error: msg
      };
    }

    const ackPromise = new Promise<SendRelayPayloadResult>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingRouteWaiters.delete(operationId);
        resolve({
          routed: false,
          operationId,
          reason: 'ROUTE_TIMEOUT',
          error: 'ESTADO DESCONOCIDO: tiempo de espera agotado sin confirmación del servidor.'
        });
      }, timeoutMs);

      this.pendingRouteWaiters.set(operationId, { resolve, timer });
    });

    const sent = this.sendRaw({
      type: 'RELAY_DATA',
      senderId: identity.deviceId,
      recipientId: identity.pairedPeerDeviceId,
      linkId: identity.activeLinkId,
      operationId,
      payload: encryptedPayload,
      timestamp: Date.now()
    });

    if (!sent) {
      const waiter = this.pendingRouteWaiters.get(operationId);
      if (waiter) {
        clearTimeout(waiter.timer);
        this.pendingRouteWaiters.delete(operationId);
      }
      return {
        routed: false,
        operationId,
        reason: 'WS_SEND_FAILED',
        error: 'No se pudo enviar por WebSocket.'
      };
    }

    return ackPromise;
  }

  private async onIncomingRelayData(msg: Record<string, any>) {
    const operationId = String(msg.operationId || '').trim();
    const senderId = String(msg.senderId || '').trim();
    const recipientId = String(msg.recipientId || '').trim();
    const linkId = String(msg.linkId || '').trim();
    const rawPayload = msg.payload as Partial<EncryptedRelayPayload> | undefined;
    const timestamp = Number(msg.timestamp || Date.now());

    if (!operationId || !senderId || !rawPayload || typeof rawPayload !== 'object') return;

    const identity = this.currentIdentity;
    if (!identity || !identity.activeLinkId || !identity.pairedPeerDeviceId) {
      this.emitSecurityError('Paquete rechazado: dispositivo no emparejado.');
      return;
    }

    if (senderId !== identity.pairedPeerDeviceId || linkId !== identity.activeLinkId) {
      this.emitSecurityError('Paquete rechazado: remitente o vínculo no coincide con el emparejamiento activo.');
      return;
    }

    if (
      rawPayload.kind !== 'e2ee' ||
      rawPayload.v !== 1 ||
      typeof rawPayload.itemId !== 'string' ||
      !rawPayload.itemId ||
      typeof rawPayload.ivBase64 !== 'string' ||
      typeof rawPayload.ciphertextBase64 !== 'string'
    ) {
      this.emitSecurityError('Paquete rechazado: se recibió contenido sin cifrado E2EE válido.');
      return;
    }

    let decrypted: RelayDataPayload;
    try {
      const keyCtx = await this.getOrDeriveSharedKey();
      if (!keyCtx || keyCtx.linkId !== linkId) {
        this.emitSecurityError('No se pudo derivar la clave compartida para descifrar el paquete.');
        return;
      }

      const aadText = `${linkId}|${rawPayload.itemId}`;
      const plain = await decryptAesGcmJson<RelayDataPayload>(
        keyCtx.aesKey,
        rawPayload.ivBase64,
        rawPayload.ciphertextBase64,
        aadText
      );

      if (!plain || typeof plain !== 'object' || plain.itemId !== rawPayload.itemId || typeof plain.kind !== 'string') {
        this.emitSecurityError('Paquete rechazado: contenido descifrado inválido o inconsistente.');
        return;
      }
      decrypted = plain;
    } catch {
      this.emitSecurityError('Datos alterados o clave inválida rechazados al descifrar (AES-256-GCM).');
      return;
    }

    if (this.seenIncomingOperationIds.has(operationId)) return;
    this.recordSeenOperationId(operationId);

    if (this.dataHandler) {
      await this.dataHandler({
        senderId,
        recipientId,
        linkId,
        operationId,
        payload: decrypted,
        timestamp
      });
    }
  }

  public async replacePairedMobile(targetTerminalId?: string | null): Promise<RevokeOutcome> {
    const local = await this.storage.getIdentity();
    if (!local || local.role !== 'CORE') {
      return {
        success: false,
        persistedInFirestore: false,
        disconnectedLive: false,
        revocationStatus: 'UNKNOWN',
        error: 'Solo VEL CORE puede reemplazar el teléfono MÓVIL.'
      };
    }

    const cleanTargetId = String(targetTerminalId || local.pairedPeerDeviceId || '').trim();
    if (!cleanTargetId) {
      this.revocationStatus = 'UNKNOWN';
      this.revocationDetail =
        'ESTADO DESCONOCIDO: no hay un teléfono MÓVIL vinculado para revocar antes del reemplazo.';
      this.emit();
      return {
        success: false,
        persistedInFirestore: false,
        disconnectedLive: false,
        revocationStatus: 'UNKNOWN',
        revocationDetail: this.revocationDetail,
        error: this.revocationDetail
      };
    }

    return this.revokePairedTerminal(cleanTargetId, 'Reemplazo de teléfono MÓVIL desde VEL CORE');
  }

  public async revokePairedTerminal(
    targetTerminalId: string,
    reason = 'Desvinculado por el usuario desde VEL CORE'
  ): Promise<RevokeOutcome> {
    const local = await this.storage.getIdentity();
    if (!local || local.role !== 'CORE') {
      return {
        success: false,
        persistedInFirestore: false,
        disconnectedLive: false,
        revocationStatus: 'UNKNOWN',
        error: 'Solo VEL CORE puede desvincular un móvil.'
      };
    }

    const cleanTargetId = String(targetTerminalId || local.pairedPeerDeviceId || '').trim();
    if (!cleanTargetId) {
      this.revocationStatus = 'UNKNOWN';
      this.revocationDetail = 'ESTADO DESCONOCIDO: no se identificó el teléfono MÓVIL a revocar.';
      this.emit();
      return {
        success: false,
        persistedInFirestore: false,
        disconnectedLive: false,
        revocationStatus: 'UNKNOWN',
        revocationDetail: this.revocationDetail,
        error: this.revocationDetail
      };
    }

    this.revocationStatus = 'PENDING';
    this.revocationDetail = 'REVOCACIÓN PENDIENTE: esperando confirmación del servidor...';
    this.emit();

    if (this.ws && this.ws.readyState === 1 && (this.state === 'LINKED' || this.state === 'AUTHENTICATED')) {
      return new Promise<RevokeOutcome>((resolve) => {
        let settled = false;
        const finishWithHttpFallback = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          this.pendingRevokeContext = null;
          void this.revokeViaHttpFallback(local.deviceId, cleanTargetId, reason).then(resolve);
        };

        const timeout = setTimeout(finishWithHttpFallback, 5000);

        this.pendingRevokeContext = {
          resolve: (res) => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            this.pendingRevokeContext = null;
            resolve(res);
          },
          fallbackToHttp: finishWithHttpFallback
        };

        const sent = this.sendRaw({
          type: 'REVOKE_DEVICE',
          coreId: local.deviceId,
          targetTerminalId: cleanTargetId,
          reason
        });

        if (!sent) {
          finishWithHttpFallback();
        }
      });
    }

    return this.revokeViaHttpFallback(local.deviceId, cleanTargetId, reason);
  }

  private async revokeViaHttpFallback(
    coreDeviceId: string,
    targetTerminalId: string,
    reason: string
  ): Promise<RevokeOutcome> {
    try {
      const token = await this.tokenProvider();
      if (!token) {
        this.revocationStatus = 'UNKNOWN';
        this.revocationDetail =
          'ESTADO DESCONOCIDO: no hay sesión Firebase activa para confirmar la revocación con el servidor.';
        this.emit();
        return {
          success: false,
          persistedInFirestore: false,
          disconnectedLive: false,
          revocationStatus: this.revocationStatus,
          revocationDetail: this.revocationDetail,
          error: this.revocationDetail
        };
      }

      const res = await this.fetchFn('/api/revoke-device', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ coreDeviceId, targetTerminalId, reason })
      });

      const contentType = (res.headers?.get?.('content-type') || '').toLowerCase();
      if (contentType.includes('text/html')) {
        this.revocationStatus = 'UNKNOWN';
        this.revocationDetail =
          'ESTADO DESCONOCIDO: el servidor no confirmó la revocación en esta vista previa.';
        this.emit();
        return {
          success: false,
          persistedInFirestore: false,
          disconnectedLive: false,
          revocationStatus: this.revocationStatus,
          revocationDetail: this.revocationDetail,
          error: this.revocationDetail
        };
      }

      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.success) {
        this.revocationStatus = 'UNKNOWN';
        this.revocationDetail = `ESTADO DESCONOCIDO: ${
          data.error || `sin confirmación del servidor (HTTP ${res.status}).`
        }`;
        this.emit();
        return {
          success: false,
          persistedInFirestore: false,
          disconnectedLive: false,
          revocationStatus: this.revocationStatus,
          revocationDetail: this.revocationDetail,
          error: this.revocationDetail || undefined
        };
      }

      this.peerOnline = false;
      this.pairingSession = null;
      this.invalidateSharedKeyCache();
      const local = await this.storage.getIdentity();
      if (local) {
        const updated = {
          ...local,
          registrationStatus: 'registered' as const,
          activeLinkId: null,
          pairedPeerDeviceId: null,
          pairedPeerPublicKeySpkiBase64: null,
          updatedAt: new Date().toISOString()
        };
        await this.storage.saveIdentity(updated);
        this.syncSummaryFromLocal(updated);
      }

      this.revocationStatus = 'PERSISTED_PEER_OFFLINE';
      this.revocationDetail =
        'REVOCACIÓN PENDIENTE: el móvil anterior estaba desconectado. El servidor ya bloqueó su acceso para que no pueda volver a conectarse.';
      if (this.state === 'LINKED') {
        this.setState('AUTHENTICATED');
      } else {
        this.emit();
      }

      return {
        success: true,
        persistedInFirestore: true,
        disconnectedLive: false,
        revocationStatus: this.revocationStatus,
        revocationDetail: this.revocationDetail
      };
    } catch (err: any) {
      this.revocationStatus = 'UNKNOWN';
      this.revocationDetail = `ESTADO DESCONOCIDO: ${
        err?.message || 'sin conexión con el servidor para confirmar la revocación.'
      }`;
      this.emit();
      return {
        success: false,
        persistedInFirestore: false,
        disconnectedLive: false,
        revocationStatus: this.revocationStatus,
        revocationDetail: this.revocationDetail,
        error: this.revocationDetail || undefined
      };
    }
  }
}
