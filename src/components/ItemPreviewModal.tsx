import React, { useEffect, useState } from 'react';
import { Download, FileText, Film, Image as ImageIcon, X } from 'lucide-react';
import { VelVaultItemRecord } from '../contracts/velContracts';
import { formatBytesHuman } from '../db/velLocalStore';

interface ItemPreviewModalProps {
  item: VelVaultItemRecord | null;
  onClose: () => void;
}

export const ItemPreviewModal: React.FC<ItemPreviewModalProps> = ({ item, onClose }) => {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!item?.blob) {
      setObjectUrl(null);
      return;
    }
    const url = URL.createObjectURL(item.blob);
    setObjectUrl(url);
    return () => {
      URL.revokeObjectURL(url);
    };
  }, [item]);

  if (!item) return null;

  const isPdf =
    item.mimeType === 'application/pdf' || item.title.toLowerCase().endsWith('.pdf');

  const handleDownload = () => {
    if (item.kind === 'note') {
      const textBlob = new Blob([`${item.title}\n\n${item.textContent || ''}`], {
        type: 'text/plain;charset=utf-8'
      });
      const url = URL.createObjectURL(textBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${item.title.replace(/[^\w\s-]/g, '').trim() || 'nota-vel'}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return;
    }
    if (!objectUrl) return;
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = item.title || 'archivo-vel';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div
      className="fixed inset-0 z-[90] bg-black/80 backdrop-blur-sm flex items-end sm:items-center justify-center sm:p-4"
      onClick={onClose}
    >
      <div
        className="w-full sm:max-w-xl bg-[#111C2E] border-t sm:border border-[#22324C] rounded-t-3xl sm:rounded-3xl max-h-[90dvh] flex flex-col overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="w-10 h-1.5 bg-[#22324C] rounded-full mx-auto mt-3 sm:hidden" />

        <div className="px-5 py-3.5 border-b border-[#22324C] flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-9 h-9 rounded-xl bg-[#0B1220] border border-[#22324C] flex items-center justify-center text-[#00CFE8] shrink-0">
              {item.kind === 'photo' ? (
                <ImageIcon className="w-4 h-4" />
              ) : item.kind === 'video' ? (
                <Film className="w-4 h-4" />
              ) : (
                <FileText className="w-4 h-4" />
              )}
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-bold text-white truncate">{item.title}</h3>
              <p className="text-xs text-[#94A3B8]">
                {formatBytesHuman(item.sizeBytes)} ·{' '}
                {new Date(item.createdAt).toLocaleString('es-AR', {
                  day: '2-digit',
                  month: 'short',
                  hour: '2-digit',
                  minute: '2-digit'
                })}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="min-w-[44px] min-h-[44px] rounded-xl text-[#94A3B8] hover:text-white hover:bg-[#18263E] flex items-center justify-center cursor-pointer shrink-0"
            aria-label="Cerrar vista"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 bg-[#0B1220]">
          {item.kind === 'note' && (
            <div className="p-4 rounded-2xl bg-[#111C2E] border border-[#22324C] text-sm text-[#E2E8F0] whitespace-pre-wrap leading-relaxed">
              {item.textContent}
            </div>
          )}

          {item.kind === 'photo' && objectUrl && (
            <div className="flex items-center justify-center">
              <img
                src={objectUrl}
                alt={item.title}
                className="max-h-[60dvh] w-auto rounded-2xl object-contain border border-[#22324C]"
              />
            </div>
          )}

          {item.kind === 'video' && objectUrl && (
            <video
              src={objectUrl}
              controls
              playsInline
              className="w-full max-h-[60dvh] rounded-2xl bg-black border border-[#22324C]"
            />
          )}

          {item.kind === 'file' && isPdf && objectUrl && (
            <iframe
              src={objectUrl}
              title={item.title}
              className="w-full h-[60dvh] rounded-2xl bg-white border border-[#22324C]"
            />
          )}

          {item.kind === 'file' && !isPdf && (
            <div className="p-6 rounded-2xl bg-[#111C2E] border border-[#22324C] text-center space-y-2">
              <FileText className="w-10 h-10 text-[#00CFE8] mx-auto" />
              <p className="text-sm font-semibold text-white">{item.title}</p>
              <p className="text-xs text-[#94A3B8]">
                Este tipo de archivo ({formatBytesHuman(item.sizeBytes)}) se abre mejor descargándolo en tu teléfono.
              </p>
            </div>
          )}
        </div>

        <div className="p-4 border-t border-[#22324C] bg-[#111C2E] flex items-center gap-3">
          <button
            type="button"
            onClick={handleDownload}
            className="flex-1 min-h-[48px] rounded-2xl bg-[#00CFE8] hover:bg-[#00b8ce] text-[#0B1220] font-bold text-sm flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99] transition-transform"
          >
            <Download className="w-4 h-4" />
            <span>Descargar en este teléfono</span>
          </button>
        </div>
      </div>
    </div>
  );
};
