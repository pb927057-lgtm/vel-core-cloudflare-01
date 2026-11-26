export type SubscriberStatus =
  | 'pendiente_pago'
  | 'activo'
  | 'en_gracia'
  | 'suspendido'
  | 'vencido'
  | 'cancelado';

export type CommercialModality = 'manual_30d' | 'preapproval';

export type DeviceRole = 'CORE' | 'TERMINAL';

export type DeviceRegistrationStatus = 'registered' | 'paired' | 'revoked';

export type LinkStatus = 'pending' | 'active' | 'revoked';

export type AuthorizationStatus = 'active' | 'revoked';

export type DevicePermission =
  | 'RELAY_CONNECT'
  | 'E2EE_SESSION'
  | 'SYNC_STATUS'
  | 'REVOKE_PEER';

export interface DeviceRecord {
  deviceId: string;
  role: DeviceRole;
  authUid: string;
  publicKeySpkiBase64: string;
  signingPublicKeySpkiBase64: string;
  fingerprint: string;
  status: DeviceRegistrationStatus;
  activeLinkId: string | null;
  pairedPeerDeviceId: string | null;
  subscriptionUid?: string | null;
  createdAt: string;
  lastSeenAt: string;
  updatedAt: string;
  revokedAt: string | null;
  revokedReason: string | null;
}

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

export interface SuscriptorAdminRecord {
  uid: string;
  email: string;
  estado: SubscriberStatus;
  plan: string | null;
  fechaAlta: any;
  venceEl: string | null;
  modalidadComercial?: CommercialModality | null;
  mpPreapprovalId?: string | null;
  mpPreferenceId?: string | null;
  mpExternalReference?: string | null;
  mpPayerId?: string | null;
  ultimoPagoId?: string | null;
  ultimaTarifaConsultada?: number | null;
  ultimaSolicitudPagoEl?: string | null;
  fechaUltimoPago?: string | null;
  fechaProximoPago?: string | null;
  fechaInicioGracia?: string | null;
  precioContratado?: number | null;
  moneda?: string | null;
  canceladoEl?: string | null;
  bajaSolicitadaEl?: string | null;
  altaCompletadaEl?: string | null;
  ultimoReembolsoEl?: string | null;
  ultimoMotivoReversion?: string | null;
  ultimaActualizacion?: string;
}

export interface AccountDeviceSummary {
  deviceId: string;
  role: DeviceRole;
  status: DeviceRegistrationStatus;
  activeLinkId: string | null;
  pairedPeerDeviceId: string | null;
  lastSeenAt: string;
}

export interface PagoProcesadoRecord {
  paymentId: string;
  uid: string;
  preferenceId?: string | null;
  status: 'approved' | 'reverted';
  reverted?: boolean;
  revertReason?: string | null;
  revertedAt?: string | null;
  transactionAmountRefunded?: number;
  netAmount?: number;
  grantedDays: number;
  paymentMethodId?: string | null;
  paymentTypeId?: string | null;
  transactionAmount: number;
  currencyId: string;
  dateApproved: string;
  appliedAt?: string;
  previousVenceEl: string | null;
  newVenceEl: string;
  processedAt: string;
}

export interface PreferenciaPagoRecord {
  preferenceId: string;
  uid: string;
  email: string;
  amount: number;
  currencyId: string;
  isHistoricalPrice: boolean;
  modalidadComercial: 'manual_30d';
  status: 'created' | 'paid' | 'reverted';
  createdAt: string;
  paymentId?: string | null;
  updatedAt?: string;
}

export interface PricingConfig {
  monto: number;
  moneda: string;
  periodicidad: 'mensual';
  actualizadoEl: string;
  actualizadoPor?: string;
  motivoCambio?: string;
}

export interface PricingHistoryEntry extends PricingConfig {
  id: string;
}

export interface WebhookEventRecord {
  eventId: string;
  receivedAt: string;
  type: string;
  action?: string;
  resourceId: string;
  processed: boolean;
  statusResolved?: string;
  externalReference?: string | null;
}

export type CloudflareEnv = Record<string, string | undefined>;

export interface CloudflarePagesContext {
  request: Request;
  env: CloudflareEnv;
  params?: Record<string, string | string[]>;
}
