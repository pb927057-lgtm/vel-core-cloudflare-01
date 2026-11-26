import { useState, useEffect, useCallback } from 'react';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

export interface PWAInstallState {
  isInstallable: boolean;
  isInstalled: boolean;
  isIOS: boolean;
  isAndroid: boolean;
  swUpdateAvailable: boolean;
  promptInstall: () => Promise<'accepted' | 'dismissed' | 'unavailable'>;
  applySwUpdate: () => Promise<void>;
}

function checkIsStandalone(): boolean {
  if (typeof window === 'undefined') return false;
  const matchStandalone =
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(display-mode: standalone)').matches;
  const iosStandalone = (window.navigator as any).standalone === true;
  return Boolean(matchStandalone || iosStandalone);
}

export function usePWAInstall(): PWAInstallState {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstalled, setIsInstalled] = useState<boolean>(checkIsStandalone);
  const [swUpdateAvailable, setSwUpdateAvailable] = useState<boolean>(false);

  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
  const isIOS = /iPad|iPhone|iPod/.test(ua) && !(window as any).MSStream;
  const isAndroid = /Android/i.test(ua);

  useEffect(() => {
    setIsInstalled(checkIsStandalone());

    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
    };

    const handleAppInstalled = () => {
      setIsInstalled(true);
      setDeferredPrompt(null);
    };

    const handleSwUpdateReady = () => {
      setSwUpdateAvailable(true);
    };

    const mediaQuery =
      typeof window.matchMedia === 'function'
        ? window.matchMedia('(display-mode: standalone)')
        : null;
    const handleDisplayModeChange = () => {
      if (checkIsStandalone()) {
        setIsInstalled(true);
        setDeferredPrompt(null);
      }
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    window.addEventListener('appinstalled', handleAppInstalled);
    window.addEventListener('vel-sw-update-ready', handleSwUpdateReady);
    mediaQuery?.addEventListener?.('change', handleDisplayModeChange);

    // Verificar si ya existe un waiting SW al montar
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistration?.().then((reg) => {
        if (reg?.waiting && navigator.serviceWorker.controller) {
          setSwUpdateAvailable(true);
        }
      }).catch(() => {});
    }

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
      window.removeEventListener('appinstalled', handleAppInstalled);
      window.removeEventListener('vel-sw-update-ready', handleSwUpdateReady);
      mediaQuery?.removeEventListener?.('change', handleDisplayModeChange);
    };
  }, []);

  const promptInstall = useCallback(async (): Promise<'accepted' | 'dismissed' | 'unavailable'> => {
    if (!deferredPrompt) return 'unavailable';
    await deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    setDeferredPrompt(null);
    if (outcome === 'accepted') {
      setIsInstalled(true);
    }
    return outcome;
  }, [deferredPrompt]);

  const applySwUpdate = useCallback(async () => {
    if (!('serviceWorker' in navigator)) {
      window.location.reload();
      return;
    }
    try {
      const reg = await navigator.serviceWorker.getRegistration();
      if (reg?.waiting) {
        let reloaded = false;
        const onControllerChange = () => {
          if (reloaded) return;
          reloaded = true;
          window.location.reload();
        };
        navigator.serviceWorker.addEventListener('controllerchange', onControllerChange, { once: true });
        reg.waiting.postMessage({ type: 'SKIP_WAITING' });
        setTimeout(() => {
          if (!reloaded) window.location.reload();
        }, 1200);
        return;
      }
    } catch {
      // Fallback directo
    }
    window.location.reload();
  }, []);

  return {
    isInstallable: Boolean(deferredPrompt) && !isInstalled,
    isInstalled,
    isIOS,
    isAndroid,
    swUpdateAvailable,
    promptInstall,
    applySwUpdate
  };
}

export function useOnlineStatus(): boolean {
  const [isOnline, setIsOnline] = useState<boolean>(() =>
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );

  useEffect(() => {
    const goOnline = () => setIsOnline(true);
    const goOffline = () => setIsOnline(false);

    window.addEventListener('online', goOnline);
    window.addEventListener('offline', goOffline);
    return () => {
      window.removeEventListener('online', goOnline);
      window.removeEventListener('offline', goOffline);
    };
  }, []);

  return isOnline;
}
