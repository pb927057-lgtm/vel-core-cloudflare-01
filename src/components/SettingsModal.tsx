import React, { useState } from 'react';
import {
  CheckCircle,
  ChevronDown,
  ChevronUp,
  Database,
  Download,
  ExternalLink,
  Link2,
  Mail,
  RefreshCw,
  Shield,
  Smartphone,
  Unlink,
  UserCheck,
  X
} from 'lucide-react';
import {
  DeviceIdentitySummary,
  RevocationStatus,
  SubscriptionRuntimeStatus
} from '../contracts/velContracts';
import { LocalStorageStats, formatBytesHuman } from '../db/velLocalStore';
import { PWAInstallState } from '../hooks/usePWAInstall';
import {
  ACCOUNT_DELETION_CONFIRM_KEYWORD,
  AccountDeactivationResult,
  CommercialAccountSnapshot,
  ROLE_CHANGE_CONFIRMATION_KEYWORD
} from '../services/deviceIdentityService';
import { OFFICIAL_CONTRACT_URL } from '../services/firestore';

const OFFICIAL_BLOGGER_PORTAL_URL = 'https://proyecto-vel.blogspot.com';

interface SettingsModalProps {
  open: boolean;
  onClose: () => void;
  identity: DeviceIdentitySummary;
  stats: LocalStorageStats;
  pwa: PWAInstallState;
  peerOnline: boolean;
  isPairingPending: boolean;
  revocationStatus?: RevocationStatus;
  revocationDetail?: string | null;
  commercialUser?: { uid: string; email: string } | null;
  commercialAccount?: CommercialAccountSnapshot | null;
  subscriptionStatus?: SubscriptionRuntimeStatus | null;
  needsEmailLinkConfirmation?: boolean;
  onSendAccountEmailLink?: (email: string) => Promise<{ success: boolean; error?: string }>;
  onCompleteEmailLink?: (email: string) => Promise<{ success: boolean; error?: string }>;
  onRefreshAccountStatus?: () => Promise<{ success: boolean; error?: string }>;
  onSignOutAccount?: () => Promise<void>;
  onDeactivateAccount?: (confirmText: string) => Promise<AccountDeactivationResult>;
  onOpenInstallGuide: () => void;
  onStartPairing: () => void;
  onReplaceMobile?: () => Promise<{
    success: boolean;
    persistedInFirestore?: boolean;
    disconnectedLive?: boolean;
    revocationStatus?: RevocationStatus;
    revocationDetail?: string;
    error?: string;
  }>;
  onUnlinkPeer: () => Promise<{ success: boolean; error?: string }>;
  onConfirmRoleChange: (keyword: string) => Promise<{ success: boolean; error?: string }>;
  onRetryCloudSync: () => Promise<void>;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  open,
  onClose,
  identity,
  stats,
  pwa,
  peerOnline,
  isPairingPending,
  revocationStatus = 'NONE',
  revocationDetail = null,
  commercialUser = null,
  commercialAccount = null,
  subscriptionStatus = null,
  needsEmailLinkConfirmation = false,
  onSendAccountEmailLink,
  onCompleteEmailLink,
  onRefreshAccountStatus,
  onSignOutAccount,
  onDeactivateAccount,
  onOpenInstallGuide,
  onStartPairing,
  onReplaceMobile,
  onUnlinkPeer,
  onConfirmRoleChange,
  onRetryCloudSync
}) => {
  const [showRoleChangeForm, setShowRoleChangeForm] = useState(false);
  const [roleKeyword, setRoleKeyword] = useState('');
  const [roleError, setRoleError] = useState<string | null>(null);
  const [isChangingRole, setIsChangingRole] = useState(false);

  const [accountEmailInput, setAccountEmailInput] = useState('');
  const [isSendingAccountLink, setIsSendingAccountLink] = useState(false);
  const [accountEmailSent, setAccountEmailSent] = useState<string | null>(null);
  const [accountFeedback, setAccountFeedback] = useState<string | null>(null);
  const [isRefreshingAccount, setIsRefreshingAccount] = useState(false);
  const [showDeactivateForm, setShowDeactivateForm] = useState(false);
  const [deactivateKeyword, setDeactivateKeyword] = useState('');
  const [isDeactivatingAccount, setIsDeactivatingAccount] = useState(false);

  const [confirmReplace, setConfirmReplace] = useState(false);
  const [isReplacing, setIsReplacing] = useState(false);
  const [replaceFeedback, setReplaceFeedback] = useState<string | null>(null);

  const [confirmUnlink, setConfirmUnlink] = useState(false);
  const [isUnlinking, setIsUnlinking] = useState(false);
  const [unlinkFeedback, setUnlinkFeedback] = useState<string | null>(null);

  const [showTechInfo, setShowTechInfo] = useState(false);
  const [isSyncingCloud, setIsSyncingCloud] = useState(false);

  if (!open) return null;

  const isCore = identity.role === 'CORE';
  const isPaired = identity.registrationStatus === 'paired' && Boolean(identity.pairedPeerDeviceId);

  const handleReplaceMobile = async () => {
    if (!onReplaceMobile) return;
    setIsReplacing(true);
    setReplaceFeedback(null);
    setUnlinkFeedback(null);
    const res = await onReplaceMobile();
    setIsReplacing(false);
    setConfirmReplace(false);
    if (!res.success || !res.persistedInFirestore) {
      setReplaceFeedback(
        res.revocationDetail ||
          res.error ||
          'ESTADO DESCONOCIDO: no se pudo confirmar la revocación en el servidor.'
      );
      return;
    }
    onClose();
    onStartPairing();
  };

  const handleUnlink = async () => {
    setIsUnlinking(true);
    setUnlinkFeedback(null);
    setReplaceFeedback(null);
    const res = await onUnlinkPeer();
    setIsUnlinking(false);
    setConfirmUnlink(false);
    if (!res.success && res.error) {
      setUnlinkFeedback(res.error);
    } else {
      onClose();
    }
  };

  const handleRoleChangeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsChangingRole(true);
    setRoleError(null);
    const res = await onConfirmRoleChange(roleKeyword);
    setIsChangingRole(false);
    if (!res.success) {
      setRoleError(res.error || 'Confirmación incorrecta.');
    } else {
      setShowRoleChangeForm(false);
      setRoleKeyword('');
      onClose();
    }
  };

  const handleAccountEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAccountFeedback(null);
    setAccountEmailSent(null);
    const cleanEmail = accountEmailInput.trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes('@')) {
      setAccountFeedback('Ingresa un correo electrónico válido.');
      return;
    }
    setIsSendingAccountLink(true);
    if (needsEmailLinkConfirmation && onCompleteEmailLink) {
      const res = await onCompleteEmailLink(cleanEmail);
      setIsSendingAccountLink(false);
      if (!res.success && res.error) {
        setAccountFeedback(res.error);
      } else {
        setAccountEmailInput('');
      }
      return;
    }
    if (onSendAccountEmailLink) {
      const res = await onSendAccountEmailLink(cleanEmail);
      setIsSendingAccountLink(false);
      if (!res.success) {
        setAccountFeedback(res.error || 'No se pudo enviar el enlace de acceso.');
      } else {
        setAccountEmailSent(cleanEmail);
      }
      return;
    }
    setIsSendingAccountLink(false);
  };

  const handleRefreshAccount = async () => {
    if (!onRefreshAccountStatus) return;
    setIsRefreshingAccount(true);
    setAccountFeedback(null);
    const res = await onRefreshAccountStatus();
    setIsRefreshingAccount(false);
    if (!res.success && res.error) {
      setAccountFeedback(res.error);
    } else {
      setAccountFeedback('Estado de cuenta y dispositivo actualizado.');
    }
  };

  const handleDeactivateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onDeactivateAccount) return;
    setIsDeactivatingAccount(true);
    setAccountFeedback(null);
    const res = await onDeactivateAccount(deactivateKeyword);
    setIsDeactivatingAccount(false);
    if (!res.success) {
      setAccountFeedback(res.error || 'No se pudo procesar la baja.');
      return;
    }
    setShowDeactivateForm(false);
    setDeactivateKeyword('');
    setAccountFeedback(
      res.authAccountDeleted
        ? 'Cuenta dada de baja y dispositivos revocados. Tus copias locales en VEL CORE siguen intactas.'
        : `Cuenta y dispositivos revocados en Firestore. Aviso Auth: ${res.authPropagationError || 'requiere verificación en Firebase Auth'}.`
    );
  };

  return (
    <div
      className="fixed inset-0 z-[90] bg-black/80 backdrop-blur-sm flex items-end sm:items-center justify-center sm:p-4"
      onClick={onClose}
    >
      <div
        className="w-full sm:max-w-md bg-[#111C2E] border-t sm:border border-[#22324C] rounded-t-3xl sm:rounded-3xl max-h-[88dvh] flex flex-col overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="w-10 h-1.5 bg-[#22324C] rounded-full mx-auto mt-3 sm:hidden" />

        <div className="px-5 py-3.5 border-b border-[#22324C] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div
              className={`w-9 h-9 rounded-xl flex items-center justify-center border ${
                isCore
                  ? 'bg-[#00CFE8]/15 border-[#00CFE8]/40 text-[#00CFE8]'
                  : 'bg-[#10B981]/15 border-[#10B981]/40 text-[#10B981]'
              }`}
            >
              {isCore ? <Shield className="w-4 h-4" /> : <Smartphone className="w-4 h-4" />}
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">
                Opciones de {isCore ? 'VEL CORE' : 'VEL MÓVIL'}
              </h2>
              <p className="text-xs text-[#94A3B8]">
                {isCore ? 'Teléfono principal en casa' : 'Teléfono de uso diario'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="min-w-[44px] min-h-[44px] rounded-xl text-[#94A3B8] hover:text-white hover:bg-[#18263E] flex items-center justify-center cursor-pointer"
            aria-label="Cerrar opciones"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* Instalar app si está abierto en el navegador */}
          {!pwa.isInstalled && (
            <button
              type="button"
              onClick={async () => {
                if (pwa.isInstallable) {
                  await pwa.promptInstall();
                } else {
                  onClose();
                  onOpenInstallGuide();
                }
              }}
              className="w-full min-h-[48px] px-4 rounded-2xl bg-[#10B981] hover:bg-[#059669] text-[#0B1220] font-bold text-sm flex items-center justify-center gap-2 cursor-pointer"
            >
              <Download className="w-4 h-4" />
              <span>Instalar ícono de VEL en este teléfono</span>
            </button>
          )}

          {/* Estado de conexión entre los dos teléfonos */}
          <div className="p-4 rounded-2xl bg-[#0B1220] border border-[#22324C] space-y-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-bold text-white">Conexión con el otro teléfono</span>
              <span
                className={`text-xs font-semibold flex items-center gap-1 ${
                  isPaired ? (peerOnline ? 'text-[#10B981]' : 'text-[#F59E0B]') : 'text-[#94A3B8]'
                }`}
              >
                {isPaired ? (
                  <>
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>{peerOnline ? 'Conectado ahora' : 'Vinculado (en espera)'}</span>
                  </>
                ) : (
                  <span>Sin conectar</span>
                )}
              </span>
            </div>

            {isCore && (
              <div className="space-y-2">
                {(revocationStatus === 'PENDING' ||
                  revocationStatus === 'PERSISTED_PEER_OFFLINE' ||
                  revocationStatus === 'UNKNOWN') && (
                  <div
                    className={`p-3 rounded-xl border text-xs space-y-1 ${
                      revocationStatus === 'UNKNOWN'
                        ? 'bg-[#EF4444]/10 border-[#EF4444]/40 text-[#FCA5A5]'
                        : 'bg-[#F59E0B]/10 border-[#F59E0B]/40 text-[#FDE68A]'
                    }`}
                  >
                    <strong className="block text-white">
                      {revocationStatus === 'UNKNOWN'
                        ? 'ESTADO DESCONOCIDO'
                        : 'REVOCACIÓN PENDIENTE'}
                    </strong>
                    <span>
                      {revocationDetail ||
                        (revocationStatus === 'UNKNOWN'
                          ? 'No hubo confirmación del servidor para revocar el teléfono anterior.'
                          : 'El teléfono anterior está desconectado o pendiente de confirmación.')}
                    </span>
                  </div>
                )}

                {!isPaired ? (
                  <button
                    type="button"
                    onClick={() => {
                      onClose();
                      onStartPairing();
                    }}
                    className="w-full min-h-[44px] px-4 rounded-xl bg-[#00CFE8] hover:bg-[#00b8ce] text-[#0B1220] font-bold text-xs flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Link2 className="w-4 h-4" />
                    <span>Generar código para VEL MÓVIL</span>
                  </button>
                ) : !confirmReplace ? (
                  <button
                    type="button"
                    onClick={() => {
                      setConfirmReplace(true);
                      setConfirmUnlink(false);
                      setReplaceFeedback(null);
                      setUnlinkFeedback(null);
                    }}
                    className="w-full min-h-[44px] px-4 rounded-xl bg-[#00CFE8] hover:bg-[#00b8ce] text-[#0B1220] font-bold text-xs flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <RefreshCw className="w-4 h-4" />
                    <span>Reemplazar teléfono MÓVIL</span>
                  </button>
                ) : (
                  <div className="p-3 rounded-xl bg-[#00CFE8]/10 border border-[#00CFE8]/40 space-y-2.5">
                    <p className="text-xs font-bold text-white">
                      ¿Reemplazar el teléfono MÓVIL actual?
                    </p>
                    <p className="text-xs text-[#CBD5E1] leading-relaxed">
                      Se revocará la autorización del teléfono anterior para que no pueda volver a conectarse ni enviar archivos. Tu identidad y tus copias en VEL CORE permanecerán intactas y no se copiarán automáticamente al teléfono nuevo.
                    </p>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={isReplacing}
                        onClick={() => void handleReplaceMobile()}
                        className="flex-1 min-h-[44px] rounded-xl bg-[#00CFE8] hover:bg-[#00b8ce] disabled:opacity-60 text-[#0B1220] font-bold text-xs cursor-pointer"
                      >
                        {isReplacing ? 'Revocando móvil anterior...' : 'Confirmar reemplazo'}
                      </button>
                      <button
                        type="button"
                        disabled={isReplacing}
                        onClick={() => setConfirmReplace(false)}
                        className="flex-1 min-h-[44px] rounded-xl bg-[#18263E] text-white font-semibold text-xs cursor-pointer"
                      >
                        Cancelar
                      </button>
                    </div>
                  </div>
                )}

                {isPaired && !confirmUnlink && !confirmReplace && (
                  <button
                    type="button"
                    onClick={() => {
                      setConfirmUnlink(true);
                      setConfirmReplace(false);
                    }}
                    className="w-full min-h-[44px] px-4 rounded-xl bg-[#18263E] hover:bg-[#EF4444]/15 border border-[#22324C] hover:border-[#EF4444]/40 text-[#EF4444] font-semibold text-xs flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Unlink className="w-4 h-4" />
                    <span>Desvincular VEL MÓVIL actual</span>
                  </button>
                )}

                {isPaired && confirmUnlink && (
                  <div className="p-3 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/40 space-y-2">
                    <p className="text-xs text-[#FCA5A5]">
                      El móvil actual ya no podrá enviar archivos a este CORE hasta que vuelvas a ingresar un código.
                    </p>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={isUnlinking}
                        onClick={() => void handleUnlink()}
                        className="flex-1 min-h-[44px] rounded-xl bg-[#EF4444] text-white font-bold text-xs cursor-pointer"
                      >
                        {isUnlinking ? 'Desvinculando...' : 'Sí, desvincular'}
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmUnlink(false)}
                        className="flex-1 min-h-[44px] rounded-xl bg-[#18263E] text-white font-semibold text-xs cursor-pointer"
                      >
                        Cancelar
                      </button>
                    </div>
                  </div>
                )}

                {replaceFeedback && <p className="text-xs text-[#FCA5A5]">{replaceFeedback}</p>}
                {unlinkFeedback && <p className="text-xs text-[#FCA5A5]">{unlinkFeedback}</p>}
              </div>
            )}

            {!isCore && !isPaired && (
              <button
                type="button"
                disabled={isPairingPending}
                onClick={() => {
                  onClose();
                  onStartPairing();
                }}
                className="w-full min-h-[44px] px-4 rounded-xl bg-[#10B981] hover:bg-[#059669] text-[#0B1220] font-bold text-xs flex items-center justify-center gap-2 cursor-pointer"
              >
                <Link2 className="w-4 h-4" />
                <span>Ingresar código de mi VEL CORE</span>
              </button>
            )}
          </div>

          {/* Almacenamiento local */}
          <div className="p-4 rounded-2xl bg-[#0B1220] border border-[#22324C] flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <Database className="w-4 h-4 text-[#00CFE8]" />
              <div>
                <p className="text-xs font-bold text-white">Guardado en este teléfono</p>
                <p className="text-xs text-[#94A3B8]">
                  {stats.itemCount} elemento(s) · {formatBytesHuman(stats.totalBytes)}
                </p>
              </div>
            </div>
            {identity.registrationStatus === 'pending_local' && (
              <button
                type="button"
                disabled={isSyncingCloud}
                onClick={async () => {
                  setIsSyncingCloud(true);
                  await onRetryCloudSync();
                  setIsSyncingCloud(false);
                }}
                className="min-h-[40px] px-3 rounded-xl bg-[#F59E0B]/20 border border-[#F59E0B]/40 text-[#FCD34D] text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isSyncingCloud ? 'animate-spin' : ''}`} />
                <span>Activar enlace</span>
              </button>
            )}
          </div>

          {/* Cuenta VEL y suscripción (misma identidad Firebase que Blogger) */}
          <div className="p-4 rounded-2xl bg-[#0B1220] border border-[#22324C] space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-[#00CFE8]" />
                <span className="text-xs font-bold text-white">Cuenta VEL y suscripción</span>
              </div>
              <span
                className={`text-[11px] font-semibold px-2 py-0.5 rounded-md ${
                  subscriptionStatus?.active && subscriptionStatus?.linked
                    ? 'bg-[#10B981]/15 text-[#10B981]'
                    : commercialAccount?.estado === 'cancelado'
                    ? 'bg-[#EF4444]/15 text-[#FCA5A5]'
                    : 'bg-[#18263E] text-[#CBD5E1]'
                }`}
              >
                {commercialUser
                  ? subscriptionStatus?.active && subscriptionStatus?.linked
                    ? 'Activa'
                    : commercialAccount?.estado === 'cancelado'
                    ? 'Dada de baja'
                    : commercialAccount?.estado === 'pendiente_pago'
                    ? 'Pendiente de pago'
                    : 'En sesión'
                  : identity.subscriptionUid
                  ? 'Vinculada vía Blogger'
                  : 'Sin vincular'}
              </span>
            </div>

            {commercialUser ? (
              <div className="space-y-2.5 text-xs">
                <div className="p-2.5 rounded-xl bg-[#111C2E] border border-[#22324C] text-[#CBD5E1] space-y-1">
                  <div className="truncate">
                    <span className="text-[#94A3B8]">Correo: </span>
                    <strong className="text-white">{commercialUser.email || commercialUser.uid}</strong>
                  </div>
                  {subscriptionStatus?.venceEl && (
                    <div>
                      <span className="text-[#94A3B8]">Vigencia hasta: </span>
                      <span className="text-white">
                        {new Date(subscriptionStatus.venceEl).toLocaleDateString('es-AR')}
                      </span>
                    </div>
                  )}
                  <div className="text-[11px] text-[#94A3B8]">
                    {identity.subscriptionUid === commercialUser.uid
                      ? 'Este dispositivo está vinculado a esta misma cuenta VEL.'
                      : 'Sincronizando vínculo de este dispositivo con tu cuenta...'}
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  {onRefreshAccountStatus && (
                    <button
                      type="button"
                      disabled={isRefreshingAccount}
                      onClick={() => void handleRefreshAccount()}
                      className="flex-1 min-h-[40px] px-3 rounded-xl bg-[#18263E] hover:bg-[#22324C] border border-[#22324C] text-white font-semibold text-xs flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isRefreshingAccount ? 'animate-spin' : ''}`} />
                      <span>Actualizar estado</span>
                    </button>
                  )}
                  <a
                    href={OFFICIAL_BLOGGER_PORTAL_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="min-h-[40px] px-3 rounded-xl bg-[#00CFE8] text-[#0B1220] font-bold text-xs inline-flex items-center justify-center gap-1.5"
                  >
                    <span>Portal Blogger</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>

                <div className="flex items-center justify-between gap-2 pt-1">
                  {onSignOutAccount && (
                    <button
                      type="button"
                      onClick={() => void onSignOutAccount()}
                      className="min-h-[36px] px-3 rounded-xl bg-[#18263E] text-[#CBD5E1] hover:text-white text-xs font-semibold cursor-pointer"
                    >
                      Cerrar sesión de cuenta
                    </button>
                  )}
                  {onDeactivateAccount && (
                    <button
                      type="button"
                      onClick={() => {
                        setShowDeactivateForm((v) => !v);
                        setAccountFeedback(null);
                      }}
                      className="min-h-[36px] px-3 rounded-xl border border-[#EF4444]/40 text-[#FCA5A5] hover:bg-[#EF4444]/10 text-xs font-semibold cursor-pointer"
                    >
                      Dar de baja mi cuenta
                    </button>
                  )}
                </div>

                {showDeactivateForm && (
                  <form
                    onSubmit={(e) => void handleDeactivateSubmit(e)}
                    className="p-3 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/40 space-y-2"
                  >
                    <p className="text-xs text-[#FCA5A5] leading-relaxed">
                      Esto dará de baja tu cuenta VEL, cancelará renovaciones automáticas si hubiera y revocará tus teléfonos en el servidor. Tus copias locales en VEL CORE no se borrarán.
                    </p>
                    <p className="text-xs text-white font-semibold">
                      Escribe <strong>{ACCOUNT_DELETION_CONFIRM_KEYWORD}</strong> para confirmar:
                    </p>
                    <input
                      type="text"
                      value={deactivateKeyword}
                      onChange={(e) => setDeactivateKeyword(e.target.value)}
                      placeholder={ACCOUNT_DELETION_CONFIRM_KEYWORD}
                      className="w-full h-10 px-3 rounded-xl bg-[#111C2E] border border-[#EF4444]/50 text-xs text-white outline-none"
                    />
                    <div className="flex gap-2">
                      <button
                        type="submit"
                        disabled={isDeactivatingAccount}
                        className="flex-1 min-h-[40px] rounded-xl bg-[#EF4444] text-white font-bold text-xs cursor-pointer"
                      >
                        {isDeactivatingAccount ? 'Procesando baja...' : 'Confirmar baja'}
                      </button>
                      <button
                        type="button"
                        onClick={() => setShowDeactivateForm(false)}
                        className="min-h-[40px] px-3 rounded-xl bg-[#18263E] text-white font-semibold text-xs cursor-pointer"
                      >
                        Cancelar
                      </button>
                    </div>
                  </form>
                )}
              </div>
            ) : (
              <div className="space-y-2.5 text-xs">
                <p className="text-[#94A3B8] leading-relaxed">
                  {needsEmailLinkConfirmation
                    ? 'Confirma el correo electrónico donde recibiste tu enlace de acceso para completar la vinculación con esta misma cuenta:'
                    : 'Inicia sesión con el mismo correo que usas en el portal de Blogger (sin contraseña) para sincronizar tu cuenta VEL en este teléfono:'}
                </p>
                {onSendAccountEmailLink && (
                  <form onSubmit={(e) => void handleAccountEmailSubmit(e)} className="flex gap-2">
                    <input
                      type="email"
                      value={accountEmailInput}
                      onChange={(e) => setAccountEmailInput(e.target.value)}
                      placeholder="tu-correo@ejemplo.com"
                      className="flex-1 min-w-0 h-10 px-3 rounded-xl bg-[#111C2E] border border-[#22324C] focus:border-[#00CFE8] text-xs text-white outline-none"
                    />
                    <button
                      type="submit"
                      disabled={isSendingAccountLink}
                      className="min-h-[40px] px-3 rounded-xl bg-[#00CFE8] hover:bg-[#00b8ce] text-[#0B1220] font-bold text-xs inline-flex items-center gap-1.5 shrink-0 cursor-pointer"
                    >
                      <Mail className="w-3.5 h-3.5" />
                      <span>
                        {isSendingAccountLink
                          ? 'Enviando...'
                          : needsEmailLinkConfirmation
                          ? 'Confirmar'
                          : 'Enviar enlace'}
                      </span>
                    </button>
                  </form>
                )}
                {accountEmailSent && (
                  <p className="text-[#A7F3D0]">
                    Enlace enviado a <strong>{accountEmailSent}</strong>. Ábrelo en este dispositivo para ingresar con tu cuenta única VEL.
                  </p>
                )}
                <a
                  href={OFFICIAL_BLOGGER_PORTAL_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-[#00CFE8] hover:underline font-semibold"
                >
                  <span>Ir al portal en Blogger</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}

            {accountFeedback && (
              <p className="text-xs text-[#FDE68A] leading-relaxed">{accountFeedback}</p>
            )}
          </div>

          {/* Cambiar rol */}
          <div className="p-4 rounded-2xl bg-[#0B1220] border border-[#22324C] space-y-2.5">
            <button
              type="button"
              onClick={() => {
                setShowRoleChangeForm((v) => !v);
                setRoleError(null);
              }}
              className="w-full min-h-[44px] flex items-center justify-between text-left text-xs font-semibold text-[#CBD5E1] hover:text-white cursor-pointer"
            >
              <span>Cambiar función de este teléfono (CORE / MÓVIL)</span>
              {showRoleChangeForm ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>

            {showRoleChangeForm && (
              <form onSubmit={(e) => void handleRoleChangeSubmit(e)} className="space-y-2.5 pt-1">
                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  Para cambiar este teléfono a otro rol, escribe{' '}
                  <strong className="text-white">{ROLE_CHANGE_CONFIRMATION_KEYWORD}</strong>:
                </p>
                <input
                  type="text"
                  value={roleKeyword}
                  onChange={(e) => setRoleKeyword(e.target.value)}
                  placeholder={ROLE_CHANGE_CONFIRMATION_KEYWORD}
                  className="w-full h-11 px-3 rounded-xl bg-[#111C2E] border border-[#22324C] focus:border-[#00CFE8] text-sm text-white outline-none"
                />
                {roleError && <p className="text-xs text-[#FCA5A5]">{roleError}</p>}
                <button
                  type="submit"
                  disabled={isChangingRole}
                  className="w-full min-h-[44px] rounded-xl bg-[#F59E0B] hover:bg-[#d97706] text-[#0B1220] font-bold text-xs cursor-pointer"
                >
                  {isChangingRole ? 'Cambiando...' : 'Confirmar cambio de rol'}
                </button>
              </form>
            )}
          </div>

          {/* Términos e información técnica discreta */}
          <div className="pt-1 space-y-2">
            <a
              href={OFFICIAL_CONTRACT_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="w-full min-h-[44px] px-3 rounded-xl flex items-center justify-center gap-1.5 text-xs text-[#94A3B8] hover:text-[#00CFE8]"
            >
              <span>Términos y condiciones de VEL</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>

            <button
              type="button"
              onClick={() => setShowTechInfo((v) => !v)}
              className="w-full min-h-[36px] text-[11px] text-[#64748B] hover:text-[#94A3B8] cursor-pointer"
            >
              {showTechInfo ? 'Ocultar referencia técnica' : 'Ver referencia técnica'}
            </button>

            {showTechInfo && (
              <div className="p-3 rounded-xl bg-[#0B1220] border border-[#22324C] text-[11px] text-[#94A3B8] space-y-1 font-mono break-all">
                <div>ID: {identity.deviceId}</div>
                <div>Estado: {identity.registrationStatus}</div>
                {identity.pairedPeerDeviceId && <div>Par: {identity.pairedPeerDeviceId}</div>}
                {identity.lastServerError && (
                  <div className="text-[#F59E0B] font-sans">Aviso: {identity.lastServerError}</div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
