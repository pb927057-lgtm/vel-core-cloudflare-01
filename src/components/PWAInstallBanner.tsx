import React, { useState } from 'react';
import { Download, Smartphone, WifiOff, RefreshCw, CheckCircle, X } from 'lucide-react';
import { PWAInstallState } from '../hooks/usePWAInstall';

interface PWAInstallButtonProps {
  pwa: PWAInstallState;
  compact?: boolean;
}

export const PWAInstallButton: React.FC<PWAInstallButtonProps> = ({ pwa, compact = false }) => {
  const [showManualModal, setShowManualModal] = useState(false);

  if (pwa.isInstalled) {
    return (
      <span
        className="px-2.5 min-h-[36px] rounded-xl text-[11px] font-semibold flex items-center gap-1.5 bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/30 shrink-0"
        title="VEL se está ejecutando como aplicación instalada"
      >
        <CheckCircle className="w-3.5 h-3.5" />
        <span className="hidden sm:inline">App instalada</span>
      </span>
    );
  }

  const handleClick = async () => {
    if (pwa.isInstallable) {
      const outcome = await pwa.promptInstall();
      if (outcome === 'unavailable') {
        setShowManualModal(true);
      }
    } else {
      setShowManualModal(true);
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => void handleClick()}
        className={
          compact
            ? 'px-3 min-h-[40px] rounded-xl text-xs font-bold flex items-center gap-1.5 bg-[#10B981] hover:bg-[#059669] text-[#0B1220] transition-all cursor-pointer shadow-md shrink-0'
            : 'w-full min-h-[48px] rounded-2xl bg-[#10B981] hover:bg-[#059669] text-[#0B1220] font-bold text-sm flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md'
        }
        title="Instalar VEL en la pantalla principal de este teléfono"
      >
        <Download className="w-4 h-4" />
        <span>{compact ? 'Instalar' : 'Instalar aplicación VEL'}</span>
      </button>

      {showManualModal && (
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[100] flex items-end sm:items-center justify-center sm:p-4"
          onClick={() => setShowManualModal(false)}
        >
          <div
            className="max-w-sm w-full bg-[#111C2E] border-t sm:border border-[#22324C] rounded-t-3xl sm:rounded-3xl p-5 space-y-4 shadow-2xl text-sm"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-[#22324C] pb-3">
              <div className="flex items-center gap-2 text-[#00CFE8] font-bold">
                <Smartphone className="w-4 h-4" />
                <span>Instalar VEL en tu teléfono</span>
              </div>
              <button
                type="button"
                onClick={() => setShowManualModal(false)}
                className="min-w-[44px] min-h-[44px] rounded-xl text-[#94A3B8] hover:text-white flex items-center justify-center cursor-pointer"
                aria-label="Cerrar"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {pwa.isIOS ? (
              <div className="space-y-2 text-[#CBD5E1] text-xs leading-relaxed">
                <p className="text-white font-semibold">En Safari (iPhone / iPad):</p>
                <ol className="list-decimal list-inside space-y-1.5">
                  <li>Toca el ícono <strong className="text-white">Compartir</strong> (cuadrado con flecha).</li>
                  <li>Elige <strong className="text-[#00CFE8]">"Agregar a inicio"</strong>.</li>
                  <li>Toca <strong className="text-white">Agregar</strong> y abre VEL desde su ícono.</li>
                </ol>
              </div>
            ) : (
              <div className="space-y-2 text-[#CBD5E1] text-xs leading-relaxed">
                <p className="text-white font-semibold">En Chrome / Android:</p>
                <ol className="list-decimal list-inside space-y-1.5">
                  <li>Toca los tres puntos <strong className="text-white">⋮</strong> arriba a la derecha.</li>
                  <li>Elige <strong className="text-[#00CFE8]">"Instalar aplicación"</strong> o <strong className="text-white">"Agregar a la pantalla principal"</strong>.</li>
                  <li>Confirma y abre VEL desde el ícono creado en tu teléfono.</li>
                </ol>
              </div>
            )}

            <button
              type="button"
              onClick={() => setShowManualModal(false)}
              className="w-full min-h-[48px] rounded-2xl bg-[#00CFE8] text-[#0B1220] font-bold text-sm cursor-pointer"
            >
              Entendido
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export const OfflineIndicator: React.FC<{ isOnline: boolean }> = ({ isOnline }) => {
  if (isOnline) return null;
  return (
    <div className="bg-[#F59E0B]/15 border-b border-[#F59E0B]/40 text-[#FCD34D] px-4 py-2 text-xs flex items-center justify-center gap-2 text-center">
      <WifiOff className="w-3.5 h-3.5 shrink-0" />
      <span>
        <strong>SIN CONEXIÓN:</strong> tus notas y archivos permanecen guardados localmente hasta que decidas reintentar cuando vuelva internet.
      </span>
    </div>
  );
};

export const SWUpdateBanner: React.FC<{
  visible: boolean;
  onUpdate: () => Promise<void>;
}> = ({ visible, onUpdate }) => {
  if (!visible) return null;
  return (
    <div className="bg-[#00CFE8]/15 border-b border-[#00CFE8]/40 text-white px-4 py-2 text-xs flex items-center justify-center gap-3 flex-wrap">
      <span className="flex items-center gap-1.5">
        <RefreshCw className="w-3.5 h-3.5 text-[#00CFE8]" />
        <span>Hay una actualización de <strong>VEL</strong> lista.</span>
      </span>
      <button
        type="button"
        onClick={() => void onUpdate()}
        className="px-3 min-h-[36px] rounded-xl bg-[#00CFE8] hover:bg-[#00b8ce] text-[#0B1220] font-bold text-xs cursor-pointer"
      >
        Actualizar
      </button>
    </div>
  );
};
