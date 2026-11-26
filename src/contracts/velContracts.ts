/**
 * Contratos técnicos oficiales de VEL 0.1
 * Base compartida para identidad, emparejamiento simple en 1 paso,
 * transmisión directa por Relay en memoria y custodia local en ambos teléfonos.
 */

export type DeviceRole = 'CORE' | 'TERMINAL';

export type DeviceRegistrationStatus =
  | 'pending_local'
  | 'registered'
  | 'paired'
  | 'revoked';

export type LinkStatus = 'pending' | 'active' | 'revoked';

export type AuthorizationStatus = 'active' | 'revoked';

export type DevicePermission =
  | 'RELAY_CONNECT'
  | 'E2EE_SESSION'
  | 'SYNC_STATUS'
  | 'REVOKE_PEER';

export type RelayConnectionState =
  | 'DISCONNECTED'
  | 'CONNECTING'
  | 'CONNECTED_UNAUTHENTICATED'
  | 'AUTHENTICATING'
  | 'AUTHENTICATED'
  | 'LINKED'
  | 'RECONNECTING'
  | 'REVOKED'
  | 'ERROR';

export type VelItemKind = 'note' | 'photo' | 'video' | 'file';

export type VelItemSyncStatus =
  | 'local_only'
  | 'pending'
  | 'sending'
  | 'synced'
  | 'error';

export interface VelVaultItemRecord {
  id: string;
  ownerRole: DeviceRole;
  kind: VelItemKind;
  title: string;
  textContent?: string;
  mimeType: string;
  sizeBytes: number;
  sha256Hex?: string;
  blob?: Blob;
  syncStatus: VelItemSyncStatus;
  progressPercent?: number;
  sourceDeviceId?: string;
  createdAt: number;
  updatedAt: number;
  syncedAt?: number;
  errorMessage?: string;
}

export interface VelVaultItemSummary {
  id: string;
  ownerRole: DeviceRole;
  kind: VelItemKind;
  title: string;
  textContent?: string;
  mimeType: string;
  sizeBytes: number;
  sha256Hex?: string;
  hasBlob: boolean;
  syncStatus: VelItemSyncStatus;
  progressPercent?: number;
  sourceDeviceId?: string;
  createdAt: number;
  updatedAt: number;
  syncedAt?: number;
  errorMessage?: string;
}

export interface VelIncomingChunkRecord {
  chunkKey: string; // `${itemId}:${chunkIndex}`
  itemId: string;
  chunkIndex: number;
  data: ArrayBuffer;
  updatedAt: number;
}

export interface RelayServerConfigResponse {
  configured: boolean;
  wssUrl: string | null;
  source?: 'env' | 'vite_env' | 'production_default' | 'none';
  message?: string;
}

/**
 * Conjunto público de claves y huella de un dispositivo (apto para backend y Firestore).
 * Nunca contiene claves privadas ni datos personales.
 */
export interface PublicDeviceKeyBundle {
  deviceId: string;
  role: DeviceRole;
  publicKeySpkiBase64: string;
  signingPublicKeySpkiBase64: string;
  fingerprint: string;
}

/**
 * Identidad técnica persistida localmente en IndexedDB de cada instalación PWA.
 */
export interface LocalDeviceIdentityRecord {
  id: 'current';
  deviceId: string;
  role: DeviceRole;
  fingerprint: string;
  publicKeySpkiBase64: string;
  signingPublicKeySpkiBase64: string;
  privateEcdhKey: CryptoKey;
  privateSigningKey: CryptoKey;
  firebaseAuthUid: string | null;
  registrationStatus: DeviceRegistrationStatus;
  activeLinkId: string | null;
  pairedPeerDeviceId: string | null;
  pairedPeerPublicKeySpkiBase64?: string | null;
  subscriptionUid?: string | null;
  lastServerError: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * Vista segura (sin CryptoKey) de la identidad técnica para UI y diagnósticos.
 */
export interface DeviceIdentitySummary {
  deviceId: string;
  role: DeviceRole;
  fingerprint: string;
  publicKeySpkiBase64: string;
  signingPublicKeySpkiBase64: string;
  firebaseAuthUid: string | null;
  registrationStatus: DeviceRegistrationStatus;
  activeLinkId: string | null;
  pairedPeerDeviceId: string | null;
  pairedPeerPublicKeySpkiBase64?: string | null;
  subscriptionUid?: string | null;
  lastServerError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SubscriptionRuntimeStatus {
  linked: boolean;
  active: boolean;
  estado?: string;
  venceEl?: string | null;
  reason?: string;
}

/**
 * Documento almacenado en Firestore: dispositivos/{deviceId}
 * No contiene claves privadas ni información personal.
 */
export interface DeviceRecord {
  deviceId: string;
  role: DeviceRole;
  authUid: string;
  publicKeySpkiBase64: string;
  signingPublicKeySpkiBase64: string;
  fingerprint: string;
  status: Exclude<DeviceRegistrationStatus, 'pending_local'>;
  activeLinkId: string | null;
  pairedPeerDeviceId: string | null;
  subscriptionUid?: string | null;
  createdAt: string;
  lastSeenAt: string;
  updatedAt: string;
  revokedAt: string | null;
  revokedReason: string | null;
}

/**
 * Documento almacenado en Firestore: vinculaciones/{linkId}
 * Representa la relación autorizada entre un VEL CORE y un VEL MÓVIL.
 */
export interface DeviceLinkRecord {
  linkId: string;
  coreDeviceId: string;
  terminalDeviceId: string;
  coreAuthUid: string;
  terminalAuthUid: string;
  coreFingerprint: string;
  terminalFingerprint: string;
  corePublicKeySpkiBase64?: string;
  terminalPublicKeySpkiBase64?: string;
  subscriptionUid?: string | null;
  status: LinkStatus;
  sasVerified: boolean;
  createdAt: string;
  activatedAt: string | null;
  revokedAt: string | null;
  revokedByDeviceId: string | null;
  revocationReason: string | null;
}

/**
 * Documento almacenado en Firestore: autorizaciones/{authorizationId}
 */
export interface AuthorizationRecord {
  authorizationId: string;
  linkId: string;
  coreDeviceId: string;
  terminalDeviceId: string;
  coreAuthUid: string;
  terminalAuthUid: string;
  subscriptionUid?: string | null;
  status: AuthorizationStatus;
  permissions: DevicePermission[];
  grantedAt: string;
  revokedAt: string | null;
  revokedByDeviceId: string | null;
  lastActivityAt: string;
}

export type RevocationStatus =
  | 'NONE'
  | 'PENDING'
  | 'PERSISTED_PEER_OFFLINE'
  | 'CONFIRMED'
  | 'UNKNOWN';

/**
 * Sesión de emparejamiento simple de 1 paso con código numérico de 6 dígitos.
 */
export interface PairingSessionContract {
  code: string;
  linkId?: string;
  initiatorDeviceId: string;
  initiatorRole: DeviceRole;
  peerDeviceId?: string;
  peerRole?: DeviceRole;
  stage: 'OFFERING' | 'CLAIMING' | 'CONFIRMED' | 'CANCELLED' | 'EXPIRED';
  expiresAt: number;
}

/**
 * Mensajes de datos directos teléfono-a-teléfono a través del Relay TLS (WSS) sin almacenamiento en la nube.
 */
export type RelayDataPayload =
  | {
      kind: 'note';
      itemId: string;
      title: string;
      textContent: string;
      createdAt: number;
    }
  | {
      kind: 'file_start';
      itemId: string;
      fileKind: Exclude<VelItemKind, 'note'>;
      title: string;
      mimeType: string;
      sizeBytes: number;
      totalChunks: number;
      sha256Hex: string;
      createdAt: number;
    }
  | {
      kind: 'file_chunk';
      itemId: string;
      chunkIndex: number;
      totalChunks: number;
      dataBase64: string;
    }
  | {
      kind: 'file_end';
      itemId: string;
      totalChunks: number;
      sizeBytes: number;
      sha256Hex: string;
    }
  | {
      kind: 'item_ack';
      itemId: string;
      ok: boolean;
      confirmedAt: number;
      error?: string;
    };

export interface EncryptedRelayPayload {
  kind: 'e2ee';
  v: 1;
  itemId: string;
  ivBase64: string;
  ciphertextBase64: string;
}

export interface RelayDataEnvelope {
  type: 'RELAY_DATA';
  senderId: string;
  recipientId: string;
  linkId: string;
  operationId: string;
  payload: EncryptedRelayPayload | RelayDataPayload;
  timestamp: number;
}

export interface RelayAuthPayload {
  type: 'AUTH';
  deviceId: string;
  role: DeviceRole;
  pairedCoreId?: string | null;
  firebaseIdToken: string;
  challenge?: string;
  signatureBase64?: string;
  timestamp: number;
}

export interface RelayClientContract {
  getState(): RelayConnectionState;
  connect(wssUrl: string, firebaseIdTokenProvider: () => Promise<string | null>): void;
  disconnect(): void;
  onStateChange(listener: (state: RelayConnectionState) => void): () => void;
}

export interface DeviceTokenVerificationRequest {
  firebaseIdToken: string;
  deviceId: string;
  peerDeviceId?: string;
}

export interface DeviceTokenVerificationResult {
  valid: boolean;
  authUid?: string;
  device?: DeviceRecord;
  activeLink?: DeviceLinkRecord | null;
  activeAuthorization?: AuthorizationRecord | null;
  reason?: string;
}
