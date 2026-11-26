import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Camera,
  CheckCircle,
  Copy,
  Download,
  File,
  FileText,
  Film,
  Image as ImageIcon,
  Link2,
  Loader2,
  Plus,
  RefreshCw,
  Settings,
  Shield,
  Smartphone,
  Trash2,
  Upload,
  Wifi,
  WifiOff,
  X
} from 'lucide-react';
import {
  DeviceIdentitySummary,
  DeviceRole,
  RelayServerConfigResponse,
  SubscriptionRuntimeStatus,
  VelItemKind,
  VelVaultItemRecord,
  VelVaultItemSummary
} from './contracts/velContracts';
import { formatBytesHuman } from './db/velLocalStore';
import { useOnlineStatus, usePWAInstall } from './hooks/usePWAInstall';
import {
  bindCommercialAccountToDevice,
  bindSubscriptionPassToExistingDevice,
  CommercialAccountSnapshot,
  executeControlledRoleChange,
  fetchCommercialAccountStatus,
  loadPersistedDeviceIdentity,
  registerCommercialAccount,
  requestAccountDeactivation,
  retryPendingDeviceRegistration,
  savePendingSubscriptionPass,
  setupNewDeviceIdentity,
  syncPersistedDeviceSession
} from './services/deviceIdentityService';
import {
  auth,
  completePasswordlessSignInLink,
  getAuthErrorMessage,
  getFreshDeviceAuthToken,
  isIncomingPasswordlessSignInLink,
  logoutUser,
  sendPasswordlessSignInLink,
  subscribeToAuthChanges,
  User
} from './services/firebase';
import { OFFICIAL_CONTRACT_URL } from './services/firestore';
import { getVelConnectionDisplayStatus, RelayClientSnapshot, VelRelayClient } from './services/relayClient';
import { TransferManagerSnapshot, VelTransferManager } from './services/transferManager';
import { ItemPreviewModal } from './components/ItemPreviewModal';
import { OfflineIndicator, PWAInstallButton, SWUpdateBanner } from './components/PWAInstallBanner';
import { SettingsModal } from './components/SettingsModal';
import { VelLogo } from './components/VelLogo';

export type SimpleStep = 'INSTALL_STEP' | 'CHOOSE_ROLE' | 'PAIRING_STEP' | 'HOME';

const PRODUCTION_RELAY_WSS_URL = 'wss://server-vel.onrender.com';
const OFFICIAL_BLOGGER_URL = 'https://proyecto-vel.blogspot.com';

function getCompiledOrDefaultRelayConfig(): RelayServerConfigResponse {
  const viteConfigured = String((import.meta as any).env?.VITE_VEL_RELAY_WSS_URL || '').trim();
  if (/^wss?:\/\/.+/i.test(viteConfigured)) {
    return {
      configured: true,
      wssUrl: viteConfigured.replace(/\/+$/, ''),
      source: 'vite_env'
    };
  }
  return {
    configured: true,
    wssUrl: PRODUCTION_RELAY_WSS_URL,
    source: 'production_default'
  };
}

function renderItemIcon(kind: VelItemKind) {
  switch (kind) {
    case 'photo':
      return <ImageIcon className="w-5 h-5 text-[#00CFE8]" />;
    case 'video':
      return <Film className="w-5 h-5 text-[#00CFE8]" />;
    case 'note':
      return <FileText className="w-5 h-5 text-[#10B981]" />;
    default:
      return <File className="w-5 h-5 text-[#F59E0B]" />;
  }
}

export function App() {
  const pwa = usePWAInstall();
  const isOnline = useOnlineStatus();

  const [isLoading, setIsLoading] = useState(true);
  const [identity, setIdentity] = useState<DeviceIdentitySummary | null>(null);
  const [dismissedInstallStep, setDismissedInstallStep] = useState(false);
  const [manualPairingStep, setManualPairingStep] = useState(false);

  const [isSettingUpRole, setIsSettingUpRole] = useState<DeviceRole | null>(null);
  const [setupError, setSetupError] = useState<string | null>(null);

  const [pairingInput, setPairingInput] = useState('');
  const [pairingCountdown, setPairingCountdown] = useState(0);
  const [copiedCode, setCopiedCode] = useState(false);

  const [relayConfig, setRelayConfig] = useState<RelayServerConfigResponse>(() =>
    getCompiledOrDefaultRelayConfig()
  );

  const relayClientRef = useRef<VelRelayClient | null>(null);
  if (!relayClientRef.current) {
    relayClientRef.current = new VelRelayClient();
  }
  const [relaySnap, setRelaySnap] = useState<RelayClientSnapshot>(() =>
    relayClientRef.current!.getSnapshot()
  );

  const transferManagerRef = useRef<VelTransferManager | null>(null);
  const [transferSnap, setTransferSnap] = useState<TransferManagerSnapshot>({
    items: [],
    incomingProgress: [],
    stats: {
      itemCount: 0,
      totalBytes: 0,
      quotaSupported: false,
      usageBytes: null,
      quotaBytes: null
    },
    isSyncing: false
  });

  // Filtros y modales
  const [filterTab, setFilterTab] = useState<'all' | 'media' | 'file' | 'note' | 'pending' | 'synced'>('all');
  const [previewItem, setPreviewItem] = useState<VelVaultItemRecord | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showNoteComposer, setShowNoteComposer] = useState(false);
  const [noteTitle, setNoteTitle] = useState('');
  const [noteBody, setNoteBody] = useState('');
  const [noteError, setNoteError] = useState<string | null>(null);
  const [isSavingNote, setIsSavingNote] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [sessionSubStatus, setSessionSubStatus] = useState<SubscriptionRuntimeStatus | null>(null);
  const [commercialUser, setCommercialUser] = useState<User | null>(() => auth.currentUser);
  const [commercialAccount, setCommercialAccount] = useState<CommercialAccountSnapshot | null>(null);
  const [needsEmailLinkConfirmation, setNeedsEmailLinkConfirmation] = useState(false);
  const [isReactivating, setIsReactivating] = useState(false);
  const [reactivateNotice, setReactivateNotice] = useState<string | null>(null);
  const [paymentReturnStatus, setPaymentReturnStatus] = useState<'aprobado' | 'pendiente' | 'cancelado' | null>(() => {
    if (typeof window === 'undefined') return null;
    const param = new URLSearchParams(window.location.search).get('pago_retorno');
    if (param === 'aprobado' || param === 'pendiente' || param === 'cancelado') {
      return param;
    }
    return null;
  });

  const mediaInputRef = useRef<HTMLInputElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const loadRelayConfiguration = async () => {
    const fallback = getCompiledOrDefaultRelayConfig();
    try {
      const res = await fetch('/api/relay-config');
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      if (res.ok && ct.includes('application/json')) {
        const data = (await res.json()) as RelayServerConfigResponse;
        if (data.configured && data.wssUrl) {
          setRelayConfig({
            configured: true,
            wssUrl: data.wssUrl.replace(/\/+$/, ''),
            source: data.source || 'env'
          });
          return;
        }
      }
      setRelayConfig(fallback);
    } catch {
      setRelayConfig(fallback);
    }
  };

  // Inicializar cliente Relay, gestor de archivos y cargar identidad persistida
  useEffect(() => {
    let active = true;
    const client = relayClientRef.current!;
    const manager = new VelTransferManager({
      relayClient: client,
      role: 'CORE'
    });
    transferManagerRef.current = manager;

    const unsubRelay = client.subscribe((snap) => {
      if (!active) return;
      setRelaySnap(snap);
      if (snap.identity) {
        setIdentity(snap.identity);
        manager.setRole(snap.identity.role);
      }
    });

    const unsubTransfer = manager.subscribe((snap) => {
      if (!active) return;
      setTransferSnap(snap);
    });

    void loadRelayConfiguration();
    const rawVelPass =
      typeof window !== 'undefined'
        ? new URLSearchParams(window.location.search).get('vel_pass')
        : null;

    if (
      typeof window !== 'undefined' &&
      (window.location.search.includes('pago_retorno=') || window.location.search.includes('vel_pass='))
    ) {
      try {
        const url = new URL(window.location.href);
        url.searchParams.delete('pago_retorno');
        url.searchParams.delete('vel_pass');
        window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
      } catch {}
    }

    const bootstrap = async () => {
      try {
        if (rawVelPass) {
          await savePendingSubscriptionPass(rawVelPass);
        }

        const existing = await loadPersistedDeviceIdentity();
        if (!active) return;
        if (existing) {
          setIdentity(existing);
          manager.setRole(existing.role);
          setIsLoading(false);

          if (rawVelPass && existing.registrationStatus !== 'pending_local') {
            const bindRes = await bindSubscriptionPassToExistingDevice(rawVelPass).catch(() => null);
            if (!active) return;
            if (bindRes?.identity) setIdentity(bindRes.identity);
            if (bindRes?.subscriptionStatus) setSessionSubStatus(bindRes.subscriptionStatus);
          }

          syncPersistedDeviceSession()
            .then((syncRes) => {
              if (!active || !syncRes) return;
              setIdentity(syncRes.identity);
              manager.setRole(syncRes.identity.role);
              if (syncRes.subscriptionStatus) {
                setSessionSubStatus(syncRes.subscriptionStatus);
              }
              if (!syncRes.synced && syncRes.error) {
                setSetupError(syncRes.error);
              } else {
                setSetupError(null);
              }
            })
            .catch(() => {});
        } else {
          setIsLoading(false);
        }
      } catch (err: any) {
        if (!active) return;
        setSetupError(err?.message || 'Error leyendo la configuración local.');
        setIsLoading(false);
      }
    };

    void bootstrap();

    const syncCommercialUser = async (user: User | null) => {
      if (!active) return;
      setCommercialUser(user);
      if (!user) {
        setCommercialAccount(null);
        return;
      }
      try {
        const token = await user.getIdToken(true);
        if (!active || !token) return;
        const regRes = await registerCommercialAccount(token);
        if (!active) return;
        if (regRes.success) {
          if (regRes.account) setCommercialAccount(regRes.account);
          if (regRes.subscriptionStatus) setSessionSubStatus(regRes.subscriptionStatus);
        }
        const currentDevice = await loadPersistedDeviceIdentity();
        if (
          active &&
          currentDevice &&
          currentDevice.registrationStatus !== 'pending_local' &&
          currentDevice.registrationStatus !== 'revoked' &&
          currentDevice.subscriptionUid !== user.uid
        ) {
          const bindRes = await bindCommercialAccountToDevice(token);
          if (active && bindRes.success && bindRes.identity) {
            setIdentity(bindRes.identity);
            if (bindRes.subscriptionStatus) setSessionSubStatus(bindRes.subscriptionStatus);
          }
        }
      } catch {}
    };

    const unsubCommercialAuth = subscribeToAuthChanges((user) => {
      void syncCommercialUser(user);
    });

    if (typeof window !== 'undefined' && isIncomingPasswordlessSignInLink()) {
      void completePasswordlessSignInLink().then((res) => {
        if (!active) return;
        if (res.needsEmailConfirmation) {
          setNeedsEmailLinkConfirmation(true);
          setShowSettings(true);
          return;
        }
        if (res.completed) {
          setNeedsEmailLinkConfirmation(false);
          try {
            const url = new URL(window.location.href);
            url.searchParams.delete('apiKey');
            url.searchParams.delete('oobCode');
            url.searchParams.delete('mode');
            url.searchParams.delete('lang');
            window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
          } catch {}
        }
      });
    }

    return () => {
      active = false;
      unsubCommercialAuth();
      unsubTransfer();
      manager.dispose();
      transferManagerRef.current = null;
      unsubRelay();
      client.disconnect();
    };
  }, []);

  // Conectar automáticamente al servidor Relay cuando el dispositivo ya está registrado
  useEffect(() => {
    const client = relayClientRef.current!;
    if (
      !identity ||
      identity.registrationStatus === 'pending_local' ||
      identity.registrationStatus === 'revoked' ||
      !relayConfig.configured ||
      !relayConfig.wssUrl
    ) {
      return;
    }
    client.connect(relayConfig.wssUrl, getFreshDeviceAuthToken);
  }, [identity?.deviceId, identity?.registrationStatus, relayConfig.configured, relayConfig.wssUrl]);

  // Reconectar / detectar pérdida de red al instante o volver a la app (sin duplicar sesiones)
  useEffect(() => {
    const onOffline = () => {
      relayClientRef.current?.notifyNetworkOffline();
    };

    const onRecover = async () => {
      if (typeof navigator !== 'undefined' && navigator.onLine === false) {
        relayClientRef.current?.notifyNetworkOffline();
        return;
      }
      if (!identity) return;
      if (
        identity.registrationStatus !== 'pending_local' &&
        identity.registrationStatus !== 'revoked' &&
        relayConfig.wssUrl
      ) {
        relayClientRef.current?.notifyNetworkOnline();
        if (relayClientRef.current?.getState() === 'DISCONNECTED') {
          relayClientRef.current?.connect(relayConfig.wssUrl, getFreshDeviceAuthToken);
        }
      }
      try {
        const syncRes = await syncPersistedDeviceSession();
        if (syncRes) {
          setIdentity(syncRes.identity);
          transferManagerRef.current?.setRole(syncRes.identity.role);
          if (syncRes.subscriptionStatus) {
            setSessionSubStatus(syncRes.subscriptionStatus);
          }
          if (!syncRes.synced && syncRes.error) {
            setSetupError(syncRes.error);
          } else {
            setSetupError(null);
          }
        }
      } catch {}
    };

    const handleVisibility = () => {
      if (document.visibilityState === 'visible') void onRecover();
    };

    window.addEventListener('offline', onOffline);
    window.addEventListener('online', onRecover);
    document.addEventListener('visibilitychange', handleVisibility);
    return () => {
      window.removeEventListener('offline', onOffline);
      window.removeEventListener('online', onRecover);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [identity, relayConfig.wssUrl]);

  // Contador del código de conexión
  useEffect(() => {
    const session = relaySnap.pairingSession;
    if (!session || session.stage === 'CONFIRMED' || session.stage === 'CANCELLED') {
      setPairingCountdown(0);
      return;
    }
    const tick = () => {
      const rem = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
      setPairingCountdown(rem);
    };
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, [relaySnap.pairingSession]);

  // Si un código se confirma en Paso 3, pasar automáticamente al Panel Principal
  useEffect(() => {
    if (manualPairingStep && relaySnap.pairingSession?.stage === 'CONFIRMED') {
      setManualPairingStep(false);
      setPairingInput('');
    }
  }, [manualPairingStep, relaySnap.pairingSession?.stage]);

  // En VEL CORE dentro de Paso 3, generar el código automáticamente apenas esté autenticado en Relay
  useEffect(() => {
    if (
      manualPairingStep &&
      identity?.role === 'CORE' &&
      (relaySnap.connectionState === 'AUTHENTICATED' || relaySnap.connectionState === 'LINKED') &&
      (!relaySnap.pairingSession ||
        relaySnap.pairingSession.stage === 'CANCELLED' ||
        relaySnap.pairingSession.stage === 'EXPIRED' ||
        relaySnap.pairingSession.stage === 'CONFIRMED')
    ) {
      relayClientRef.current?.startCorePairingOffer();
    }
  }, [manualPairingStep, identity?.role, relaySnap.connectionState, relaySnap.pairingSession]);

  const openPairingStep = () => {
    relayClientRef.current?.resetPairingSession();
    setPairingInput('');
    setManualPairingStep(true);
  };

  // Determinar paso actual guiado (4 pasos claros)
  const currentStep: SimpleStep = useMemo(() => {
    if (!identity) {
      if (!pwa.isInstalled && !dismissedInstallStep) {
        return 'INSTALL_STEP';
      }
      return 'CHOOSE_ROLE';
    }
    if (manualPairingStep) {
      return 'PAIRING_STEP';
    }
    return 'HOME';
  }, [identity, pwa.isInstalled, dismissedInstallStep, manualPairingStep]);

  const handleChooseRole = async (role: DeviceRole) => {
    if (isSettingUpRole) return;
    setIsSettingUpRole(role);
    setSetupError(null);
    try {
      const res = await setupNewDeviceIdentity(role);
      if (res.identity) {
        let finalIdentity = res.identity;
        if (res.registeredInServer && auth.currentUser) {
          try {
            const commercialToken = await auth.currentUser.getIdToken(true);
            const bindRes = await bindCommercialAccountToDevice(commercialToken);
            if (bindRes.success && bindRes.identity) {
              finalIdentity = bindRes.identity;
            }
            if (bindRes.subscriptionStatus) {
              setSessionSubStatus(bindRes.subscriptionStatus);
            }
          } catch {}
        }
        setIdentity(finalIdentity);
        transferManagerRef.current?.setRole(finalIdentity.role);
        setFilterTab('all');
        if (res.registeredInServer) {
          setManualPairingStep(true);
        }
      }
      if (!res.success && res.error) {
        setSetupError(res.error);
      }
    } catch (err: any) {
      setSetupError(err?.message || 'No se pudo configurar este teléfono.');
    } finally {
      setIsSettingUpRole(null);
    }
  };

  const handleRetryCloudRegistration = async () => {
    setSetupError(null);
    const res = await retryPendingDeviceRegistration();
    if (res.identity) {
      setIdentity(res.identity);
    }
    if (!res.success && res.error) {
      setSetupError(res.error);
    }
  };

  const handleReactivateSubscription = async () => {
    if (isReactivating) return;
    setIsReactivating(true);
    setReactivateNotice(null);
    try {
      const syncRes = await syncPersistedDeviceSession();
      if (syncRes) {
        setIdentity(syncRes.identity);
        transferManagerRef.current?.setRole(syncRes.identity.role);
        if (syncRes.subscriptionStatus) {
          setSessionSubStatus(syncRes.subscriptionStatus);
        }
      }
      if (relayConfig.configured && relayConfig.wssUrl) {
        relayClientRef.current?.forceReconnect();
      }
      if (syncRes?.subscriptionStatus?.linked && !syncRes.subscriptionStatus.active) {
        setReactivateNotice(
          'Aún no vemos acreditada tu renovación en Mercado Pago. Si acabas de pagar, espera unos segundos y toca "Ya pagué — Reactivar".'
        );
      } else if (syncRes?.subscriptionStatus?.active) {
        setReactivateNotice('¡Suscripción reactivada por 30 días! Tus teléfonos continúan funcionando normalmente.');
        setTimeout(() => setReactivateNotice(null), 5000);
      }
    } catch {
      setReactivateNotice('No se pudo verificar el estado ahora. Comprueba tu conexión e inténtalo de nuevo.');
    } finally {
      setIsReactivating(false);
    }
  };

  const handleCopyPairingCode = async (code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    } catch {}
  };

  const handleFilesSelected = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0 || !transferManagerRef.current) return;
    const files = Array.from(fileList).map((f) => ({
      name: f.name,
      type: f.type,
      size: f.size,
      blob: f
    }));
    e.target.value = '';
    const res = await transferManagerRef.current.addFiles(files);
    if (res.errors.length > 0) {
      setActionNotice(res.errors[0]);
      setTimeout(() => setActionNotice(null), 4500);
    }
  };

  const handleSaveNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!transferManagerRef.current) return;
    setNoteError(null);
    setIsSavingNote(true);
    try {
      await transferManagerRef.current.addNote(noteTitle, noteBody);
      setNoteTitle('');
      setNoteBody('');
      setShowNoteComposer(false);
    } catch (err: any) {
      setNoteError(err?.message || 'Escribe algún texto para guardar la nota.');
    } finally {
      setIsSavingNote(false);
    }
  };

  const handleOpenItem = async (summary: VelVaultItemSummary) => {
    const full = await transferManagerRef.current?.getItemWithBlob(summary.id);
    if (full) {
      setPreviewItem(full);
    }
  };

  const handleDownloadDirect = async (summary: VelVaultItemSummary) => {
    const full = await transferManagerRef.current?.getItemWithBlob(summary.id);
    if (!full) return;
    if (full.kind === 'note') {
      const blob = new Blob([`${full.title}\n\n${full.textContent || ''}`], {
        type: 'text/plain;charset=utf-8'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${full.title.replace(/[^\w\s-]/g, '').trim() || 'nota-vel'}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return;
    }
    if (!full.blob) return;
    const url = URL.createObjectURL(full.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = full.title || 'archivo-vel';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const handleDeleteItem = async (id: string) => {
    await transferManagerRef.current?.deleteFromThisPhone(id);
    setConfirmDeleteId(null);
  };

  const filteredItems = useMemo(() => {
    return transferSnap.items.filter((item) => {
      if (filterTab === 'all') return true;
      if (filterTab === 'media') return item.kind === 'photo' || item.kind === 'video';
      if (filterTab === 'file') return item.kind === 'file';
      if (filterTab === 'note') return item.kind === 'note';
      if (filterTab === 'pending') return item.syncStatus === 'pending' || item.syncStatus === 'sending' || item.syncStatus === 'error';
      if (filterTab === 'synced') return item.syncStatus === 'synced';
      return true;
    });
  }, [transferSnap.items, filterTab]);

  const isCore = identity?.role === 'CORE';
  const isMovil = identity?.role === 'TERMINAL';
  const isPaired = identity?.registrationStatus === 'paired' && Boolean(identity?.pairedPeerDeviceId);
  const isRevoked = identity?.registrationStatus === 'revoked' || relaySnap.connectionState === 'REVOKED';
  const isPeerOnline = isOnline && relaySnap.connectionState === 'LINKED' && relaySnap.peerOnline;
  const effectiveSubStatus = relaySnap.subscriptionStatus ?? sessionSubStatus;
  const isSubscriptionPaused = Boolean(effectiveSubStatus?.linked && !effectiveSubStatus.active);
  const connectionDisplay = getVelConnectionDisplayStatus({
    isNetworkOnline: isOnline,
    connectionState: relaySnap.connectionState,
    revocationStatus: relaySnap.revocationStatus,
    registrationStatus: identity?.registrationStatus
  });

  return (
    <div className="min-h-[100dvh] bg-[#0B1220] text-[#F1F5F9] flex flex-col font-sans selection:bg-[#00CFE8]/20">
      {/* Barra superior limpia y compacta */}
      <header className="h-14 border-b border-[#22324C] bg-[#111C2E]/95 backdrop-blur px-4 sm:px-6 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-9 h-9 rounded-xl bg-[#18263E] border border-[#22324C] flex items-center justify-center shrink-0">
            <VelLogo className="w-6 h-6" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-sm tracking-wider text-white">VEL</span>
              {identity && (
                <span
                  className={`text-[11px] font-bold px-2 py-0.5 rounded-lg border ${
                    isCore
                      ? 'bg-[#00CFE8]/15 text-[#00CFE8] border-[#00CFE8]/35'
                      : 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/35'
                  }`}
                >
                  {isCore ? 'CORE' : 'MÓVIL'}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {identity && currentStep === 'HOME' && (
            <span
              className={`px-2.5 min-h-[36px] rounded-xl text-xs font-semibold flex items-center gap-1.5 border ${
                connectionDisplay.code === 'CONECTADO'
                  ? 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/30'
                  : connectionDisplay.code === 'CONECTANDO'
                  ? 'bg-[#00CFE8]/15 text-[#00CFE8] border-[#00CFE8]/30'
                  : connectionDisplay.code === 'ESTADO_DESCONOCIDO' || connectionDisplay.code === 'REVOCADO'
                  ? 'bg-[#EF4444]/15 text-[#FCA5A5] border-[#EF4444]/35'
                  : 'bg-[#18263E] text-[#F59E0B] border-[#F59E0B]/35'
              }`}
            >
              {connectionDisplay.code === 'CONECTADO' ? (
                <Wifi className="w-3.5 h-3.5" />
              ) : connectionDisplay.code === 'CONECTANDO' ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : connectionDisplay.code === 'ESTADO_DESCONOCIDO' || connectionDisplay.code === 'REVOCADO' ? (
                <AlertTriangle className="w-3.5 h-3.5" />
              ) : (
                <WifiOff className="w-3.5 h-3.5" />
              )}
              <span>{connectionDisplay.label}</span>
            </span>
          )}

          {!pwa.isInstalled && currentStep !== 'INSTALL_STEP' && (
            <PWAInstallButton pwa={pwa} compact />
          )}

          {identity && (
            <button
              type="button"
              onClick={() => setShowSettings(true)}
              className="min-w-[44px] min-h-[44px] rounded-xl bg-[#18263E] hover:bg-[#22324C] border border-[#22324C] text-[#CBD5E1] hover:text-white flex items-center justify-center cursor-pointer"
              aria-label="Opciones"
              title="Opciones"
            >
              <Settings className="w-5 h-5" />
            </button>
          )}
        </div>
      </header>

      <SWUpdateBanner visible={pwa.swUpdateAvailable} onUpdate={pwa.applySwUpdate} />
      <OfflineIndicator isOnline={isOnline} />

      <main className="flex-1 w-full max-w-2xl lg:max-w-4xl mx-auto px-4 py-5 flex flex-col">
        {paymentReturnStatus && (
          <div
            className={`mb-4 p-4 rounded-2xl border flex items-start justify-between gap-3 ${
              paymentReturnStatus === 'aprobado'
                ? 'bg-[#10B981]/15 border-[#10B981]/40 text-[#A7F3D0]'
                : 'bg-[#F59E0B]/15 border-[#F59E0B]/40 text-[#FDE68A]'
            }`}
          >
            <div className="text-xs leading-relaxed">
              <strong className="block text-sm text-white mb-0.5">
                {paymentReturnStatus === 'aprobado'
                  ? '¡Suscripción activada por 30 días!'
                  : paymentReturnStatus === 'pendiente'
                  ? 'Pago pendiente de acreditación'
                  : 'Pago cancelado'}
              </strong>
              <span>
                {paymentReturnStatus === 'aprobado'
                  ? 'Tu pago en Mercado Pago quedó registrado. Instala VEL en este teléfono para usarla cuando quieras.'
                  : paymentReturnStatus === 'pendiente'
                  ? 'En cuanto Mercado Pago confirme tu pago, el acceso en Blogger quedará habilitado automáticamente.'
                  : 'No se completó el cobro. Puedes reintentar desde el portal de VEL en Blogger.'}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setPaymentReturnStatus(null)}
              className="min-w-[36px] min-h-[36px] rounded-xl text-white/80 hover:text-white flex items-center justify-center cursor-pointer shrink-0"
              aria-label="Cerrar aviso"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* CARGA INICIAL */}
        {isLoading && (
          <div className="flex-1 flex flex-col items-center justify-center text-center space-y-3 py-12">
            <Loader2 className="w-8 h-8 text-[#00CFE8] animate-spin" />
            <p className="text-sm text-[#94A3B8]">Abriendo VEL...</p>
          </div>
        )}

        {/* PASO 1: INSTALAR VEL COMO APP (SOLO EN NAVEGADOR ANTES DE INSTALAR) */}
        {!isLoading && currentStep === 'INSTALL_STEP' && (
          <div className="flex-1 flex flex-col justify-center max-w-md mx-auto w-full space-y-5 py-4">
            <div className="p-6 rounded-3xl bg-[#111C2E] border border-[#22324C] shadow-2xl space-y-5 text-center">
              <div className="w-16 h-16 rounded-2xl bg-[#0B1220] border border-[#00CFE8]/40 flex items-center justify-center mx-auto shadow-lg">
                <VelLogo className="w-11 h-11" />
              </div>

              <div className="space-y-2">
                <span className="text-xs font-bold uppercase tracking-widest text-[#00CFE8] block">
                  Paso 1 de 3
                </span>
                <h1 className="text-xl font-extrabold text-white">Instala VEL en tu teléfono</h1>
                <p className="text-sm text-[#CBD5E1] leading-relaxed">
                  Así tendrás el ícono de VEL en tu pantalla principal como cualquier aplicación y se abrirá directo sin pasos extra.
                </p>
              </div>

              <PWAInstallButton pwa={pwa} />

              {pwa.isIOS && (
                <div className="p-3.5 rounded-2xl bg-[#0B1220] border border-[#22324C] text-left text-xs text-[#CBD5E1] space-y-1">
                  <p className="font-bold text-white">En iPhone / Safari:</p>
                  <p>1. Toca Compartir · 2. Elige "Agregar a inicio".</p>
                </div>
              )}

              <button
                type="button"
                onClick={() => setDismissedInstallStep(true)}
                className="w-full min-h-[44px] rounded-xl text-xs font-semibold text-[#94A3B8] hover:text-white cursor-pointer"
              >
                Continuar en el navegador por ahora
              </button>
            </div>
          </div>
        )}

        {/* PASO 2: ELEGIR QUÉ TELÉFONO ES ESTE */}
        {!isLoading && currentStep === 'CHOOSE_ROLE' && (
          <div className="flex-1 flex flex-col justify-center max-w-lg mx-auto w-full space-y-5 py-2">
            <div className="text-center space-y-2">
              <div className="w-14 h-14 rounded-2xl bg-[#111C2E] border border-[#22324C] flex items-center justify-center mx-auto">
                <VelLogo className="w-9 h-9" />
              </div>
              <h1 className="text-xl font-extrabold text-white">¿Qué teléfono es este?</h1>
              <p className="text-sm text-[#CBD5E1] leading-relaxed">
                VEL usa dos teléfonos: uno principal en casa que guarda tus copias y tu teléfono diario que envía fotos, archivos y notas.
              </p>
            </div>

            {setupError && (
              <div className="p-3.5 rounded-2xl bg-[#EF4444]/15 border border-[#EF4444]/40 text-xs text-[#FCA5A5] text-center">
                {setupError}
              </div>
            )}

            <div className="space-y-3.5">
              <button
                type="button"
                disabled={Boolean(isSettingUpRole)}
                onClick={() => void handleChooseRole('CORE')}
                className="w-full p-5 rounded-3xl bg-[#111C2E] hover:bg-[#18263E] border-2 border-[#00CFE8]/50 hover:border-[#00CFE8] text-left transition-all active:scale-[0.99] cursor-pointer shadow-lg flex items-center gap-4"
              >
                <div className="w-12 h-12 rounded-2xl bg-[#00CFE8]/15 border border-[#00CFE8]/40 flex items-center justify-center text-[#00CFE8] shrink-0">
                  {isSettingUpRole === 'CORE' ? (
                    <Loader2 className="w-6 h-6 animate-spin" />
                  ) : (
                    <Shield className="w-6 h-6" />
                  )}
                </div>
                <div className="space-y-1">
                  <span className="text-base font-extrabold text-white block">
                    VEL CORE — Teléfono principal (en casa)
                  </span>
                  <span className="text-xs text-[#CBD5E1] block leading-relaxed">
                    Guarda una copia segura de tus fotos, archivos y notas. Configura este teléfono primero.
                  </span>
                </div>
              </button>

              <button
                type="button"
                disabled={Boolean(isSettingUpRole)}
                onClick={() => void handleChooseRole('TERMINAL')}
                className="w-full p-5 rounded-3xl bg-[#111C2E] hover:bg-[#18263E] border-2 border-[#10B981]/50 hover:border-[#10B981] text-left transition-all active:scale-[0.99] cursor-pointer shadow-lg flex items-center gap-4"
              >
                <div className="w-12 h-12 rounded-2xl bg-[#10B981]/15 border border-[#10B981]/40 flex items-center justify-center text-[#10B981] shrink-0">
                  {isSettingUpRole === 'TERMINAL' ? (
                    <Loader2 className="w-6 h-6 animate-spin" />
                  ) : (
                    <Smartphone className="w-6 h-6" />
                  )}
                </div>
                <div className="space-y-1">
                  <span className="text-base font-extrabold text-white block">
                    VEL MÓVIL — Teléfono diario (contigo)
                  </span>
                  <span className="text-xs text-[#CBD5E1] block leading-relaxed">
                    Envía tus fotos, archivos y notas a tu VEL CORE. Tú decides si los borras de aquí o los conservas.
                  </span>
                </div>
              </button>

              <a
                href={OFFICIAL_CONTRACT_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="w-full p-5 rounded-3xl bg-[#111C2E] hover:bg-[#18263E] border-2 border-[#F59E0B]/50 hover:border-[#F59E0B] text-left transition-all active:scale-[0.99] cursor-pointer shadow-lg flex items-center gap-4"
              >
                <div className="w-12 h-12 rounded-2xl bg-[#F59E0B]/15 border border-[#F59E0B]/40 flex items-center justify-center text-[#F59E0B] shrink-0">
                  <FileText className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <span className="text-base font-extrabold text-white block">
                    CONTRATAR VEL
                  </span>
                  <span className="text-xs text-[#CBD5E1] block leading-relaxed">
                    Consulta los términos y condiciones y contrata tu suscripción oficial de VEL.
                  </span>
                </div>
              </a>
            </div>

            <div className="text-center pt-2">
              <a
                href={OFFICIAL_CONTRACT_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-[#94A3B8] hover:text-[#00CFE8] underline"
              >
                Términos y condiciones de uso
              </a>
            </div>
          </div>
        )}

        {/* PASO 3: CONECTAR AMBOS TELÉFONOS CON UN SOLO CÓDIGO */}
        {!isLoading && currentStep === 'PAIRING_STEP' && identity && (
          <div className="flex-1 flex flex-col justify-center max-w-md mx-auto w-full space-y-5 py-2">
            <div className="p-6 rounded-3xl bg-[#111C2E] border border-[#22324C] shadow-2xl space-y-5">
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setManualPairingStep(false)}
                  className="min-w-[44px] min-h-[44px] rounded-xl bg-[#0B1220] border border-[#22324C] text-[#94A3B8] hover:text-white flex items-center justify-center cursor-pointer"
                  aria-label="Volver"
                >
                  <ArrowLeft className="w-5 h-5" />
                </button>
                <div>
                  <h1 className="text-lg font-extrabold text-white">
                    {isCore ? 'Conecta tu VEL MÓVIL' : 'Conecta con tu VEL CORE'}
                  </h1>
                  <p className="text-xs text-[#94A3B8]">
                    {isCore
                      ? 'Escribe este código en tu otro teléfono'
                      : 'Ingresa el código de 6 dígitos que muestra tu VEL CORE'}
                  </p>
                </div>
              </div>

              {isSubscriptionPaused && (
                <div className="p-4 rounded-2xl bg-[#F59E0B]/15 border border-[#F59E0B]/40 space-y-2.5 text-xs text-[#FDE68A]">
                  <strong className="block text-sm text-white">Suscripción mensual vencida</strong>
                  <p className="leading-relaxed">
                    Tus archivos y copias locales siguen intactos, pero necesitas renovar tu mes en Blogger con Mercado Pago para conectar o enviar entre tus teléfonos.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <a
                      href={OFFICIAL_BLOGGER_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="min-h-[40px] px-3.5 rounded-xl bg-[#00CFE8] text-[#0B1220] font-extrabold text-xs inline-flex items-center justify-center"
                    >
                      Renovar en Blogger
                    </a>
                    <button
                      type="button"
                      disabled={isReactivating}
                      onClick={() => void handleReactivateSubscription()}
                      className="min-h-[40px] px-3.5 rounded-xl bg-[#18263E] hover:bg-[#22324C] border border-[#22324C] text-white font-bold text-xs inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      {isReactivating && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                      <span>Ya pagué — Reactivar</span>
                    </button>
                  </div>
                </div>
              )}

              {isCore &&
                (relaySnap.revocationStatus === 'PERSISTED_PEER_OFFLINE' ||
                  relaySnap.revocationStatus === 'PENDING' ||
                  relaySnap.revocationStatus === 'UNKNOWN' ||
                  relaySnap.revocationStatus === 'CONFIRMED') && (
                  <div
                    className={`p-3 rounded-2xl border text-xs space-y-1 ${
                      relaySnap.revocationStatus === 'UNKNOWN'
                        ? 'bg-[#EF4444]/15 border-[#EF4444]/40 text-[#FCA5A5]'
                        : relaySnap.revocationStatus === 'CONFIRMED'
                        ? 'bg-[#10B981]/15 border-[#10B981]/40 text-[#A7F3D0]'
                        : 'bg-[#F59E0B]/15 border-[#F59E0B]/40 text-[#FDE68A]'
                    }`}
                  >
                    <strong className="block text-white">
                      {relaySnap.revocationStatus === 'UNKNOWN'
                        ? 'ESTADO DESCONOCIDO'
                        : relaySnap.revocationStatus === 'CONFIRMED'
                        ? 'Móvil anterior revocado'
                        : 'REVOCACIÓN PENDIENTE'}
                    </strong>
                    <span>
                      {relaySnap.revocationDetail ||
                        (relaySnap.revocationStatus === 'UNKNOWN'
                          ? 'No se obtuvo confirmación del servidor.'
                          : 'El móvil anterior está desconectado; su acceso quedó bloqueado en el servidor.')}
                    </span>
                  </div>
                )}

              {relaySnap.lastError && !isSubscriptionPaused && (
                <div className="p-3 rounded-2xl bg-[#EF4444]/15 border border-[#EF4444]/40 text-xs text-[#FCA5A5]">
                  {relaySnap.lastError}
                </div>
              )}

              {isCore ? (
                <div className="space-y-4 text-center">
                  {relaySnap.pairingSession &&
                  relaySnap.pairingSession.stage === 'OFFERING' &&
                  pairingCountdown > 0 ? (
                    <div className="p-5 rounded-2xl bg-[#0B1220] border border-[#00CFE8]/40 space-y-3">
                      <span className="text-xs text-[#94A3B8] block">Código de conexión</span>
                      <div className="text-4xl font-black tracking-[0.22em] text-[#00CFE8] font-mono select-all">
                        {relaySnap.pairingSession.code}
                      </div>
                      <p className="text-xs text-[#94A3B8]">
                        Válido por {Math.floor(pairingCountdown / 60)}:
                        {String(pairingCountdown % 60).padStart(2, '0')} min
                      </p>
                      <div className="flex gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => void handleCopyPairingCode(relaySnap.pairingSession!.code)}
                          className="flex-1 min-h-[44px] rounded-xl bg-[#18263E] hover:bg-[#22324C] text-white text-xs font-semibold flex items-center justify-center gap-1.5 cursor-pointer"
                        >
                          <Copy className="w-4 h-4 text-[#00CFE8]" />
                          <span>{copiedCode ? 'Copiado' : 'Copiar'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => relayClientRef.current?.startCorePairingOffer()}
                          className="flex-1 min-h-[44px] rounded-xl bg-[#18263E] hover:bg-[#22324C] text-white text-xs font-semibold flex items-center justify-center gap-1.5 cursor-pointer"
                        >
                          <RefreshCw className="w-4 h-4 text-[#00CFE8]" />
                          <span>Nuevo código</span>
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="p-5 rounded-2xl bg-[#0B1220] border border-[#22324C] space-y-3">
                      <Loader2 className="w-7 h-7 text-[#00CFE8] animate-spin mx-auto" />
                      <p className="text-xs text-[#CBD5E1]">
                        {relaySnap.connectionState === 'AUTHENTICATED' ||
                        relaySnap.connectionState === 'LINKED'
                          ? 'Generando código...'
                          : 'Conectando con el servidor VEL...'}
                      </p>
                      <button
                        type="button"
                        onClick={() => relayClientRef.current?.startCorePairingOffer()}
                        className="w-full min-h-[44px] rounded-xl bg-[#00CFE8] text-[#0B1220] font-bold text-xs cursor-pointer"
                      >
                        Generar código ahora
                      </button>
                    </div>
                  )}

                  <button
                    type="button"
                    onClick={() => setManualPairingStep(false)}
                    className="w-full min-h-[44px] rounded-xl text-xs font-semibold text-[#94A3B8] hover:text-white cursor-pointer"
                  >
                    Ir a mis respaldos
                  </button>
                </div>
              ) : (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    relayClientRef.current?.claimPairingCode(pairingInput);
                  }}
                  className="space-y-4"
                >
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={pairingInput}
                    onChange={(e) => setPairingInput(e.target.value.replace(/[^\d]/g, '').slice(0, 6))}
                    placeholder="000000"
                    className="w-full h-14 px-4 rounded-2xl bg-[#0B1220] border-2 border-[#22324C] focus:border-[#10B981] text-center text-3xl font-black tracking-[0.25em] text-white font-mono outline-none"
                  />

                  <button
                    type="submit"
                    disabled={
                      pairingInput.length < 6 ||
                      relaySnap.pairingSession?.stage === 'CLAIMING' ||
                      (relaySnap.connectionState !== 'AUTHENTICATED' &&
                        relaySnap.connectionState !== 'LINKED')
                    }
                    className="w-full min-h-[48px] rounded-2xl bg-[#10B981] hover:bg-[#059669] disabled:opacity-50 text-[#0B1220] font-extrabold text-sm flex items-center justify-center gap-2 cursor-pointer"
                  >
                    {relaySnap.pairingSession?.stage === 'CLAIMING' ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        <span>Conectando...</span>
                      </>
                    ) : (
                      <>
                        <Link2 className="w-4 h-4" />
                        <span>Conectar con mi CORE</span>
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setManualPairingStep(false)}
                    className="w-full min-h-[44px] rounded-xl text-xs font-semibold text-[#94A3B8] hover:text-white cursor-pointer"
                  >
                    Continuar sin conectar por ahora
                  </button>
                </form>
              )}
            </div>
          </div>
        )}

        {/* PASO 4: PANEL DIARIO LIMPIO (VEL CORE O VEL MÓVIL) */}
        {!isLoading && currentStep === 'HOME' && identity && (
          <div className="flex-1 flex flex-col space-y-4 pb-24 sm:pb-8">
            {/* Aviso si el teléfono está pendiente de nube */}
            {identity.registrationStatus === 'pending_local' && (
              <div className="p-4 rounded-2xl bg-[#F59E0B]/15 border border-[#F59E0B]/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="text-xs text-[#FCD34D] space-y-0.5">
                  <strong className="block">Enlace en la nube pendiente</strong>
                  <span>{setupError || 'Activa la conexión para enlazar ambos teléfonos.'}</span>
                </div>
                <button
                  type="button"
                  onClick={() => void handleRetryCloudRegistration()}
                  className="min-h-[44px] px-4 rounded-xl bg-[#F59E0B] text-[#0B1220] font-bold text-xs shrink-0 cursor-pointer"
                >
                  Reintentar ahora
                </button>
              </div>
            )}

            {/* Aviso si fue revocado */}
            {isRevoked && (
              <div className="p-4 rounded-2xl bg-[#EF4444]/15 border border-[#EF4444]/40 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-[#EF4444] shrink-0 mt-0.5" />
                <div className="text-xs text-[#FCA5A5] space-y-2">
                  <strong className="block text-sm text-white">Este teléfono fue desvinculado</strong>
                  <p>
                    Tus archivos locales siguen aquí, pero necesitas volver a vincularlo o cambiar su función en Opciones.
                  </p>
                </div>
              </div>
            )}

            {/* Estado de revocación en VEL CORE cuando el móvil anterior está desconectado o sin confirmación */}
            {isCore &&
              !isRevoked &&
              (relaySnap.revocationStatus === 'PENDING' ||
                relaySnap.revocationStatus === 'PERSISTED_PEER_OFFLINE' ||
                relaySnap.revocationStatus === 'UNKNOWN') && (
                <div
                  className={`p-4 rounded-2xl border flex items-start gap-3 ${
                    relaySnap.revocationStatus === 'UNKNOWN'
                      ? 'bg-[#EF4444]/15 border-[#EF4444]/40 text-[#FCA5A5]'
                      : 'bg-[#F59E0B]/15 border-[#F59E0B]/40 text-[#FDE68A]'
                  }`}
                >
                  <AlertTriangle
                    className={`w-5 h-5 shrink-0 mt-0.5 ${
                      relaySnap.revocationStatus === 'UNKNOWN' ? 'text-[#EF4444]' : 'text-[#F59E0B]'
                    }`}
                  />
                  <div className="text-xs space-y-1">
                    <strong className="block text-sm text-white">
                      {relaySnap.revocationStatus === 'UNKNOWN'
                        ? 'ESTADO DESCONOCIDO'
                        : 'REVOCACIÓN PENDIENTE'}
                    </strong>
                    <p className="leading-relaxed">
                      {relaySnap.revocationDetail ||
                        (relaySnap.revocationStatus === 'UNKNOWN'
                          ? 'No se pudo confirmar la revocación en el servidor. No se afirma que el móvil anterior haya sido revocado.'
                          : 'El móvil anterior estaba desconectado. El servidor registró el bloqueo para cuando intente conectarse.')}
                    </p>
                  </div>
                </div>
              )}

            {/* Aviso si venció el período mensual (sin borrar nada local) */}
            {!isRevoked && isSubscriptionPaused && (
              <div className="p-4 rounded-2xl bg-[#F59E0B]/15 border border-[#F59E0B]/45 space-y-3">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-[#F59E0B] shrink-0 mt-0.5" />
                  <div className="text-xs text-[#FDE68A] space-y-1">
                    <strong className="block text-sm text-white">
                      Suscripción mensual vencida — Envío pausado
                    </strong>
                    <p className="leading-relaxed">
                      Tus fotos, archivos y notas guardados en este teléfono siguen 100% seguros aquí y no se borrarán. Renueva 30 días en Blogger con Mercado Pago para reactivar el envío al instante sin volver a instalar ni vincular.
                    </p>
                    {reactivateNotice && (
                      <p className="text-white font-semibold pt-1">{reactivateNotice}</p>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <a
                    href={OFFICIAL_BLOGGER_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="min-h-[44px] px-4 rounded-xl bg-[#00CFE8] hover:bg-[#00b8ce] text-[#0B1220] font-extrabold text-xs inline-flex items-center justify-center"
                  >
                    Renovar en Blogger
                  </a>
                  <button
                    type="button"
                    disabled={isReactivating}
                    onClick={() => void handleReactivateSubscription()}
                    className="min-h-[44px] px-4 rounded-xl bg-[#18263E] hover:bg-[#22324C] border border-[#22324C] text-white font-bold text-xs inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    {isReactivating && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    <span>Ya pagué — Reactivar</span>
                  </button>
                </div>
              </div>
            )}

            {reactivateNotice && !isSubscriptionPaused && (
              <div className="p-3 rounded-2xl bg-[#10B981]/15 border border-[#10B981]/40 text-xs text-[#A7F3D0]">
                {reactivateNotice}
              </div>
            )}

            {/* Tarjeta de estado de conexión */}
            {!isRevoked && identity.registrationStatus !== 'pending_local' && (
              <div
                className={`p-4 rounded-2xl border flex items-center justify-between gap-3 ${
                  connectionDisplay.code === 'ESTADO_DESCONOCIDO'
                    ? 'bg-[#EF4444]/10 border-[#EF4444]/40'
                    : isPeerOnline
                    ? 'bg-[#10B981]/10 border-[#10B981]/35'
                    : isPaired
                    ? 'bg-[#111C2E] border-[#22324C]'
                    : 'bg-[#111C2E] border-[#00CFE8]/35'
                }`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div
                    className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                      connectionDisplay.code === 'ESTADO_DESCONOCIDO'
                        ? 'bg-[#EF4444]/20 text-[#EF4444]'
                        : isPeerOnline
                        ? 'bg-[#10B981]/20 text-[#10B981]'
                        : connectionDisplay.code === 'CONECTANDO'
                        ? 'bg-[#00CFE8]/20 text-[#00CFE8]'
                        : 'bg-[#18263E] text-[#F59E0B]'
                    }`}
                  >
                    {connectionDisplay.code === 'CONECTANDO' ? (
                      <Loader2 className="w-5 h-5 animate-spin" />
                    ) : connectionDisplay.code === 'ESTADO_DESCONOCIDO' ? (
                      <AlertTriangle className="w-5 h-5" />
                    ) : isPeerOnline ? (
                      <Wifi className="w-5 h-5" />
                    ) : (
                      <WifiOff className="w-5 h-5" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-bold text-white truncate">
                      {connectionDisplay.code === 'SIN_CONEXION'
                        ? 'SIN CONEXIÓN — guardado localmente hasta que decidas reintentar'
                        : connectionDisplay.code === 'CONECTANDO'
                        ? 'CONECTANDO con el servidor VEL...'
                        : connectionDisplay.code === 'ESTADO_DESCONOCIDO'
                        ? 'ESTADO DESCONOCIDO — no se pudo confirmar la conexión con el servidor'
                        : isPeerOnline
                        ? isCore
                          ? 'CONECTADO con tu VEL MÓVIL'
                          : 'CONECTADO con tu VEL CORE'
                        : isPaired
                        ? isCore
                          ? 'CONECTADO al servidor · esperando a tu VEL MÓVIL'
                          : 'CONECTADO al servidor · VEL CORE no está en línea'
                        : isCore
                        ? 'Aún no vinculaste un VEL MÓVIL'
                        : 'Conéctate a tu VEL CORE para enviar copias'}
                    </p>
                    <p className="text-xs text-[#94A3B8]">
                      {isMovil
                        ? 'Los elementos pendientes permanecen aquí hasta que toques Reintentar.'
                        : `${transferSnap.stats.itemCount} respaldo(s) guardados en este teléfono`}
                    </p>
                  </div>
                </div>

                {!isPaired && (
                  <button
                    type="button"
                    onClick={openPairingStep}
                    className={`min-h-[44px] px-4 rounded-xl font-bold text-xs shrink-0 cursor-pointer ${
                      isCore ? 'bg-[#00CFE8] text-[#0B1220]' : 'bg-[#10B981] text-[#0B1220]'
                    }`}
                  >
                    Conectar
                  </button>
                )}
              </div>
            )}

            {actionNotice && (
              <div className="p-3 rounded-2xl bg-[#F59E0B]/15 border border-[#F59E0B]/40 text-xs text-[#FCD34D]">
                {actionNotice}
              </div>
            )}

            {/* Progreso entrante en VEL CORE */}
            {isCore && transferSnap.incomingProgress.length > 0 && (
              <div className="p-4 rounded-2xl bg-[#111C2E] border border-[#00CFE8]/40 space-y-2">
                <p className="text-xs font-bold text-[#00CFE8]">Recibiendo desde tu VEL MÓVIL...</p>
                {transferSnap.incomingProgress.map((inc) => (
                  <div key={inc.itemId} className="space-y-1">
                    <div className="flex justify-between text-xs text-white">
                      <span className="truncate">{inc.title}</span>
                      <span>{inc.progressPercent}%</span>
                    </div>
                    <div className="h-2 rounded-full bg-[#0B1220] overflow-hidden">
                      <div
                        className="h-full bg-[#00CFE8] transition-all"
                        style={{ width: `${inc.progressPercent}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Acciones rápidas en escritorio o parte superior de lista */}
            <input
              ref={mediaInputRef}
              type="file"
              accept="image/*,video/*"
              multiple
              onChange={(e) => void handleFilesSelected(e)}
              className="hidden"
            />
            <input
              ref={fileInputRef}
              type="file"
              accept="*/*"
              multiple
              onChange={(e) => void handleFilesSelected(e)}
              className="hidden"
            />

            {isMovil ? (
              <div className="grid grid-cols-3 gap-2.5">
                <button
                  type="button"
                  onClick={() => mediaInputRef.current?.click()}
                  className="min-h-[68px] p-3 rounded-2xl bg-[#111C2E] hover:bg-[#18263E] border border-[#00CFE8]/35 flex flex-col items-center justify-center gap-1.5 text-xs font-bold text-white cursor-pointer active:scale-[0.98]"
                >
                  <Camera className="w-5 h-5 text-[#00CFE8]" />
                  <span>Foto / Vídeo</span>
                </button>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="min-h-[68px] p-3 rounded-2xl bg-[#111C2E] hover:bg-[#18263E] border border-[#22324C] flex flex-col items-center justify-center gap-1.5 text-xs font-bold text-white cursor-pointer active:scale-[0.98]"
                >
                  <Upload className="w-5 h-5 text-[#F59E0B]" />
                  <span>Archivo</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowNoteComposer(true)}
                  className="min-h-[68px] p-3 rounded-2xl bg-[#10B981] hover:bg-[#059669] flex flex-col items-center justify-center gap-1.5 text-xs font-extrabold text-[#0B1220] cursor-pointer active:scale-[0.98]"
                >
                  <Plus className="w-5 h-5" />
                  <span>Nueva nota</span>
                </button>
              </div>
            ) : (
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-sm font-extrabold text-white">Tus copias en VEL CORE</h2>
                <button
                  type="button"
                  onClick={() => setShowNoteComposer(true)}
                  className="min-h-[44px] px-4 rounded-xl bg-[#00CFE8] hover:bg-[#00b8ce] text-[#0B1220] font-bold text-xs flex items-center gap-1.5 cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  <span>Nueva nota</span>
                </button>
              </div>
            )}

            {/* Filtros */}
            <div className="flex items-center gap-2 overflow-x-auto pb-1">
              {(isMovil
                ? [
                    { id: 'all', label: 'Todo' },
                    { id: 'pending', label: 'Pendientes' },
                    { id: 'synced', label: 'En CORE ✓' }
                  ]
                : [
                    { id: 'all', label: 'Todo' },
                    { id: 'media', label: 'Fotos y vídeos' },
                    { id: 'file', label: 'Archivos' },
                    { id: 'note', label: 'Notas' }
                  ]
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setFilterTab(tab.id as any)}
                  className={`min-h-[40px] px-4 rounded-xl text-xs font-bold whitespace-nowrap cursor-pointer transition-colors ${
                    filterTab === tab.id
                      ? isCore
                        ? 'bg-[#00CFE8] text-[#0B1220]'
                        : 'bg-[#10B981] text-[#0B1220]'
                      : 'bg-[#111C2E] text-[#94A3B8] border border-[#22324C] hover:text-white'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Lista unificada de elementos */}
            {filteredItems.length === 0 ? (
              <div className="flex-1 min-h-[200px] p-8 rounded-3xl bg-[#111C2E]/60 border border-dashed border-[#22324C] flex flex-col items-center justify-center text-center space-y-2">
                <Shield className="w-8 h-8 text-[#64748B]" />
                <p className="text-sm font-bold text-white">
                  {isMovil ? 'Todavía no guardaste nada aquí' : 'Aún no hay copias guardadas'}
                </p>
                <p className="text-xs text-[#94A3B8] max-w-xs leading-relaxed">
                  {isMovil
                    ? 'Elige una foto, vídeo, archivo o nota arriba. Se guardará aquí y se enviará a tu VEL CORE.'
                    : 'Cuando envíes fotos, archivos o notas desde tu VEL MÓVIL, aparecerán guardados aquí.'}
                </p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {filteredItems.map((item) => {
                  const isConfirmingDelete = confirmDeleteId === item.id;
                  return (
                    <div
                      key={item.id}
                      className="p-3.5 rounded-2xl bg-[#111C2E] border border-[#22324C] space-y-2.5"
                    >
                      <div className="flex items-center gap-3">
                        <button
                          type="button"
                          onClick={() => void handleOpenItem(item)}
                          className="flex-1 flex items-center gap-3 min-w-0 text-left cursor-pointer"
                        >
                          <div className="w-11 h-11 rounded-xl bg-[#0B1220] border border-[#22324C] flex items-center justify-center shrink-0">
                            {renderItemIcon(item.kind)}
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="text-sm font-bold text-white truncate">{item.title}</p>
                            <div className="flex items-center gap-2 text-xs text-[#94A3B8] flex-wrap">
                              <span>{formatBytesHuman(item.sizeBytes)}</span>
                              <span>·</span>
                              <span>
                                {new Date(item.createdAt).toLocaleDateString('es-AR', {
                                  day: '2-digit',
                                  month: 'short',
                                  hour: '2-digit',
                                  minute: '2-digit'
                                })}
                              </span>
                            </div>
                          </div>
                        </button>

                        <div className="flex items-center gap-1.5 shrink-0">
                          {isCore && item.kind !== 'note' && (
                            <button
                              type="button"
                              onClick={() => void handleDownloadDirect(item)}
                              className="min-w-[44px] min-h-[44px] rounded-xl bg-[#0B1220] hover:bg-[#18263E] border border-[#22324C] text-[#00CFE8] flex items-center justify-center cursor-pointer"
                              aria-label="Descargar"
                              title="Descargar"
                            >
                              <Download className="w-4 h-4" />
                            </button>
                          )}

                          {!isConfirmingDelete && (
                            <button
                              type="button"
                              onClick={() => setConfirmDeleteId(item.id)}
                              className="min-w-[44px] min-h-[44px] rounded-xl bg-[#0B1220] hover:bg-[#EF4444]/15 border border-[#22324C] hover:border-[#EF4444]/40 text-[#94A3B8] hover:text-[#EF4444] flex items-center justify-center cursor-pointer"
                              aria-label={isMovil ? 'Borrar de este móvil' : 'Eliminar'}
                              title={isMovil ? 'Borrar de este móvil' : 'Eliminar'}
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Estado de copia en MÓVIL */}
                      {isMovil && (
                        <div className="flex items-center justify-between gap-2 pt-0.5">
                          {item.syncStatus === 'synced' ? (
                            <span className="text-xs font-semibold text-[#10B981] flex items-center gap-1.5">
                              <CheckCircle className="w-3.5 h-3.5" />
                              <span>Copiado en VEL CORE</span>
                            </span>
                          ) : item.syncStatus === 'sending' ? (
                            <div className="flex-1 space-y-1">
                              <div className="flex justify-between text-xs text-[#00CFE8] font-semibold">
                                <span>Enviando al CORE...</span>
                                <span>{item.progressPercent ?? 0}%</span>
                              </div>
                              <div className="h-1.5 rounded-full bg-[#0B1220] overflow-hidden">
                                <div
                                  className="h-full bg-[#00CFE8] transition-all"
                                  style={{ width: `${item.progressPercent ?? 0}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <div className="flex items-center justify-between w-full gap-2">
                              <span
                                className={`text-xs font-semibold ${
                                  item.syncStatus === 'error' ||
                                  item.errorMessage?.includes('ESTADO DESCONOCIDO')
                                    ? 'text-[#FCA5A5]'
                                    : 'text-[#F59E0B]'
                                }`}
                              >
                                {item.errorMessage
                                  ? item.errorMessage
                                  : item.syncStatus === 'error'
                                  ? 'Error al enviar'
                                  : isPeerOnline
                                  ? 'Pendiente — toca Reintentar para enviar'
                                  : 'SIN CONEXIÓN — guardado localmente'}
                              </span>
                              {!isRevoked && (
                                <button
                                  type="button"
                                  onClick={() => void transferManagerRef.current?.retryItem(item.id)}
                                  className="min-h-[36px] px-3 rounded-xl bg-[#18263E] text-[#00CFE8] text-xs font-bold cursor-pointer shrink-0"
                                >
                                  Reintentar
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Confirmación explícita de borrado */}
                      {isConfirmingDelete && (
                        <div className="p-3 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/35 space-y-2">
                          <p className="text-xs text-[#FCA5A5]">
                            {isMovil
                              ? '¿Borrar de este móvil? La copia que ya enviaste a VEL CORE seguirá intacta.'
                              : '¿Eliminar permanentemente esta copia de VEL CORE?'}
                          </p>
                          <div className="flex gap-2">
                            <button
                              type="button"
                              onClick={() => void handleDeleteItem(item.id)}
                              className="flex-1 min-h-[44px] rounded-xl bg-[#EF4444] text-white font-bold text-xs cursor-pointer"
                            >
                              {isMovil ? 'Borrar de este móvil' : 'Sí, eliminar'}
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDeleteId(null)}
                              className="flex-1 min-h-[44px] rounded-xl bg-[#18263E] text-white font-semibold text-xs cursor-pointer"
                            >
                              Cancelar
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Modal para escribir una nota */}
      {showNoteComposer && (
        <div
          className="fixed inset-0 z-[90] bg-black/80 backdrop-blur-sm flex items-end sm:items-center justify-center sm:p-4"
          onClick={() => setShowNoteComposer(false)}
        >
          <form
            onSubmit={(e) => void handleSaveNote(e)}
            className="w-full sm:max-w-md bg-[#111C2E] border-t sm:border border-[#22324C] rounded-t-3xl sm:rounded-3xl p-5 space-y-4 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="w-10 h-1.5 bg-[#22324C] rounded-full mx-auto sm:hidden" />

            <div className="flex items-center justify-between">
              <h3 className="text-base font-extrabold text-white">Nueva nota</h3>
              <button
                type="button"
                onClick={() => setShowNoteComposer(false)}
                className="min-w-[44px] min-h-[44px] rounded-xl text-[#94A3B8] hover:text-white flex items-center justify-center cursor-pointer"
                aria-label="Cerrar"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <input
              type="text"
              value={noteTitle}
              onChange={(e) => setNoteTitle(e.target.value)}
              placeholder="Título (opcional)"
              className="w-full h-12 px-3.5 rounded-2xl bg-[#0B1220] border border-[#22324C] focus:border-[#00CFE8] text-sm text-white outline-none"
            />

            <textarea
              rows={4}
              value={noteBody}
              onChange={(e) => setNoteBody(e.target.value)}
              placeholder="Escribe aquí tu nota..."
              className="w-full p-3.5 rounded-2xl bg-[#0B1220] border border-[#22324C] focus:border-[#00CFE8] text-sm text-white outline-none resize-none"
            />

            {noteError && <p className="text-xs text-[#FCA5A5]">{noteError}</p>}

            <button
              type="submit"
              disabled={isSavingNote}
              className={`w-full min-h-[48px] rounded-2xl font-extrabold text-sm cursor-pointer ${
                isMovil ? 'bg-[#10B981] text-[#0B1220]' : 'bg-[#00CFE8] text-[#0B1220]'
              }`}
            >
              {isSavingNote
                ? 'Guardando...'
                : isMovil
                ? 'Guardar aquí y enviar al CORE'
                : 'Guardar en VEL CORE'}
            </button>
          </form>
        </div>
      )}

      {/* Visor de elemento */}
      <ItemPreviewModal item={previewItem} onClose={() => setPreviewItem(null)} />

      {/* Modal de opciones */}
      {identity && (
        <SettingsModal
          open={showSettings}
          onClose={() => setShowSettings(false)}
          identity={identity}
          stats={transferSnap.stats}
          pwa={pwa}
          peerOnline={isPeerOnline}
          isPairingPending={relaySnap.pairingSession?.stage === 'CLAIMING'}
          revocationStatus={relaySnap.revocationStatus}
          revocationDetail={relaySnap.revocationDetail}
          commercialUser={
            commercialUser ? { uid: commercialUser.uid, email: commercialUser.email || '' } : null
          }
          commercialAccount={commercialAccount}
          subscriptionStatus={effectiveSubStatus}
          needsEmailLinkConfirmation={needsEmailLinkConfirmation}
          onSendAccountEmailLink={async (email) => {
            try {
              await sendPasswordlessSignInLink(email);
              return { success: true };
            } catch (err: any) {
              return {
                success: false,
                error: getAuthErrorMessage(String(err?.code || ''))
              };
            }
          }}
          onCompleteEmailLink={async (email) => {
            const res = await completePasswordlessSignInLink(email);
            if (res.completed) {
              setNeedsEmailLinkConfirmation(false);
              return { success: true };
            }
            return { success: false, error: res.error || 'No se pudo completar el acceso.' };
          }}
          onRefreshAccountStatus={async () => {
            if (!auth.currentUser) {
              return { success: false, error: 'Inicia sesión con tu correo primero.' };
            }
            try {
              const token = await auth.currentUser.getIdToken(true);
              const statusRes = await fetchCommercialAccountStatus(token);
              if (!statusRes.success) {
                return { success: false, error: statusRes.error };
              }
              if (statusRes.account) setCommercialAccount(statusRes.account);
              if (statusRes.subscriptionStatus) setSessionSubStatus(statusRes.subscriptionStatus);

              const bindRes = await bindCommercialAccountToDevice(token);
              if (bindRes.success && bindRes.identity) {
                setIdentity(bindRes.identity);
                if (bindRes.subscriptionStatus) setSessionSubStatus(bindRes.subscriptionStatus);
              }
              if (relayConfig.configured && relayConfig.wssUrl) {
                relayClientRef.current?.forceReconnect();
              }
              return { success: true };
            } catch (err: any) {
              return { success: false, error: err?.message || 'Error consultando cuenta.' };
            }
          }}
          onSignOutAccount={async () => {
            await logoutUser().catch(() => {});
            setCommercialUser(null);
            setCommercialAccount(null);
          }}
          onDeactivateAccount={async (confirmText) => {
            if (!auth.currentUser) {
              return { success: false, error: 'Debes iniciar sesión primero.' };
            }
            const token = await auth.currentUser.getIdToken(true);
            const res = await requestAccountDeactivation(token, confirmText);
            if (res.success) {
              if (res.revokedDeviceIds?.includes(identity.deviceId)) {
                relayClientRef.current?.disconnect();
                const updated = await loadPersistedDeviceIdentity();
                if (updated) setIdentity(updated);
              }
              setCommercialAccount((prev) =>
                prev ? { ...prev, estado: 'cancelado', venceEl: null } : null
              );
              setSessionSubStatus({
                linked: true,
                active: false,
                estado: 'cancelado',
                venceEl: null,
                reason: 'Cuenta dada de baja.'
              });
              await logoutUser().catch(() => {});
              setCommercialUser(null);
            }
            return res;
          }}
          onOpenInstallGuide={() => setDismissedInstallStep(false)}
          onStartPairing={openPairingStep}
          onReplaceMobile={async () => {
            if (!identity.pairedPeerDeviceId) {
              return {
                success: false,
                persistedInFirestore: false,
                disconnectedLive: false,
                revocationStatus: 'UNKNOWN',
                error: 'ESTADO DESCONOCIDO: no hay móvil vinculado para reemplazar.'
              };
            }
            return relayClientRef.current!.replacePairedMobile(identity.pairedPeerDeviceId);
          }}
          onUnlinkPeer={async () => {
            if (!identity.pairedPeerDeviceId) {
              return { success: false, error: 'No hay móvil vinculado.' };
            }
            const res = await relayClientRef.current!.revokePairedTerminal(identity.pairedPeerDeviceId);
            return { success: res.success, error: res.error };
          }}
          onConfirmRoleChange={async (keyword) => {
            const res = await executeControlledRoleChange(keyword);
            if (res.success) {
              relayClientRef.current?.disconnect();
              setIdentity(null);
              setManualPairingStep(false);
              setFilterTab('all');
            }
            return res;
          }}
          onRetryCloudSync={handleRetryCloudRegistration}
        />
      )}
    </div>
  );
}
export default App;
