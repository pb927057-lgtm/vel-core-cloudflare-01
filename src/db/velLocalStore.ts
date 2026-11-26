import {
  DeviceRole,
  VelItemKind,
  VelItemSyncStatus,
  VelVaultItemRecord,
  VelVaultItemSummary
} from '../contracts/velContracts';
import { VelUnifiedStorageAdapter, velDb } from './db';
import { hashBlobIncremental } from '../crypto/fileHash';

export const MAX_VEL_FILE_BYTES = 100 * 1024 * 1024; // 100 MB por archivo
export const VEL_CHUNK_SIZE_BYTES = 128 * 1024; // 128 KB por fragmento sobre WSS

export interface LocalStorageStats {
  itemCount: number;
  totalBytes: number;
  quotaSupported: boolean;
  usageBytes: number | null;
  quotaBytes: number | null;
}

export function classifyFileKind(fileName: string, mimeType: string): Exclude<VelItemKind, 'note'> {
  const lowerMime = (mimeType || '').toLowerCase();
  const lowerName = (fileName || '').toLowerCase();
  if (lowerMime.startsWith('image/') || /\.(jpg|jpeg|png|webp|gif|heic|heif|bmp|svg)$/.test(lowerName)) {
    return 'photo';
  }
  if (lowerMime.startsWith('video/') || /\.(mp4|mov|webm|mkv|avi|m4v)$/.test(lowerName)) {
    return 'video';
  }
  return 'file';
}

export function formatBytesHuman(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function generateItemId(prefix = 'ITEM'): string {
  const bytes = new Uint8Array(8);
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${hex}`;
}

export function toItemSummary(record: VelVaultItemRecord): VelVaultItemSummary {
  return {
    id: record.id,
    ownerRole: record.ownerRole,
    kind: record.kind,
    title: record.title,
    textContent: record.textContent,
    mimeType: record.mimeType,
    sizeBytes: record.sizeBytes,
    sha256Hex: record.sha256Hex,
    hasBlob: Boolean(record.blob),
    syncStatus: record.syncStatus,
    progressPercent: record.progressPercent,
    sourceDeviceId: record.sourceDeviceId,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    syncedAt: record.syncedAt,
    errorMessage: record.errorMessage
  };
}

export class VelLocalStore {
  private storage: VelUnifiedStorageAdapter;

  constructor(storage: VelUnifiedStorageAdapter = velDb) {
    this.storage = storage;
  }

  async listItems(): Promise<VelVaultItemSummary[]> {
    const rows = await this.storage.getAllItems();
    rows.sort((a, b) => b.createdAt - a.createdAt);
    return rows.map(toItemSummary);
  }

  async getItem(id: string): Promise<VelVaultItemRecord | null> {
    return this.storage.getItem(id);
  }

  async saveNote(
    ownerRole: DeviceRole,
    title: string,
    textContent: string,
    opts?: { id?: string; sourceDeviceId?: string; syncStatus?: VelItemSyncStatus; createdAt?: number }
  ): Promise<VelVaultItemRecord> {
    const cleanText = textContent.trim();
    const cleanTitle = (title || '').trim() || 'Nota rápida';
    if (!cleanText) {
      throw new Error('Escribe algún texto antes de guardar la nota.');
    }

    if (opts?.id) {
      const existing = await this.storage.getItem(opts.id);
      if (
        existing &&
        existing.kind === 'note' &&
        existing.ownerRole === ownerRole &&
        existing.title === cleanTitle &&
        existing.textContent === cleanText
      ) {
        return existing;
      }
    }

    const now = Date.now();
    const byteSize = new TextEncoder().encode(cleanText).byteLength;
    const record: VelVaultItemRecord = {
      id: opts?.id || generateItemId('NOTE'),
      ownerRole,
      kind: 'note',
      title: cleanTitle,
      textContent: cleanText,
      mimeType: 'text/plain;charset=utf-8',
      sizeBytes: byteSize,
      syncStatus: opts?.syncStatus ?? (ownerRole === 'TERMINAL' ? 'pending' : 'local_only'),
      sourceDeviceId: opts?.sourceDeviceId,
      createdAt: opts?.createdAt ?? now,
      updatedAt: now
    };

    await this.storage.putItem(record);
    return record;
  }

  async saveLocalFile(
    ownerRole: DeviceRole,
    file: { name: string; type?: string; size: number; blob: Blob },
    opts?: { id?: string; sourceDeviceId?: string; syncStatus?: VelItemSyncStatus; createdAt?: number }
  ): Promise<VelVaultItemRecord> {
    const cleanName = (file.name || '').trim() || `archivo-${Date.now()}`;
    const size = Number.isFinite(file.size) ? file.size : file.blob.size;
    if (size <= 0) {
      throw new Error(`El archivo "${cleanName}" está vacío.`);
    }
    if (size > MAX_VEL_FILE_BYTES) {
      throw new Error(
        `El archivo "${cleanName}" supera el límite de ${formatBytesHuman(MAX_VEL_FILE_BYTES)}.`
      );
    }

    const mimeType = (file.type || file.blob.type || 'application/octet-stream').trim();
    const kind = classifyFileKind(cleanName, mimeType);
    const now = Date.now();

    const record: VelVaultItemRecord = {
      id: opts?.id || generateItemId('FILE'),
      ownerRole,
      kind,
      title: cleanName,
      mimeType,
      sizeBytes: size,
      blob: file.blob,
      syncStatus: opts?.syncStatus ?? (ownerRole === 'TERMINAL' ? 'pending' : 'local_only'),
      progressPercent: ownerRole === 'TERMINAL' ? 0 : 100,
      sourceDeviceId: opts?.sourceDeviceId,
      createdAt: opts?.createdAt ?? now,
      updatedAt: now
    };

    await this.storage.putItem(record);
    return record;
  }

  async updateItemStatus(
    id: string,
    patch: Partial<
      Pick<VelVaultItemRecord, 'syncStatus' | 'progressPercent' | 'syncedAt' | 'errorMessage' | 'sha256Hex'>
    >
  ): Promise<VelVaultItemRecord | null> {
    const current = await this.storage.getItem(id);
    if (!current) return null;
    const updated: VelVaultItemRecord = {
      ...current,
      ...patch,
      updatedAt: Date.now()
    };
    await this.storage.putItem(updated);
    return updated;
  }

  async deleteItem(id: string): Promise<void> {
    await this.storage.deleteIncomingChunksByItemId(id).catch(() => 0);
    await this.storage.deleteItem(id);
  }

  async stageIncomingChunk(itemId: string, chunkIndex: number, data: ArrayBuffer): Promise<void> {
    await this.storage.putIncomingChunk({
      chunkKey: `${itemId}:${chunkIndex}`,
      itemId,
      chunkIndex,
      data,
      updatedAt: Date.now()
    });
  }

  async finalizeIncomingFile(meta: {
    itemId: string;
    title: string;
    fileKind: Exclude<VelItemKind, 'note'>;
    mimeType: string;
    sizeBytes: number;
    totalChunks: number;
    sourceDeviceId: string;
    createdAt: number;
    expectedSha256Hex?: string;
  }): Promise<VelVaultItemRecord> {
    const expectedNormalized =
      meta.expectedSha256Hex !== undefined ? meta.expectedSha256Hex.trim().toLowerCase() : undefined;
    if (expectedNormalized !== undefined && !/^[a-f0-9]{64}$/.test(expectedNormalized)) {
      throw new Error(`El hash SHA-256 esperado para "${meta.title}" no es válido.`);
    }

    const existing = await this.storage.getItem(meta.itemId);
    if (existing && existing.sizeBytes === meta.sizeBytes && existing.blob) {
      if (expectedNormalized !== undefined) {
        const existingHash =
          existing.sha256Hex || (await hashBlobIncremental(existing.blob, VEL_CHUNK_SIZE_BYTES));
        if (existingHash.trim().toLowerCase() !== expectedNormalized) {
          throw new Error(
            `Verificación SHA-256 fallida para "${meta.title}": el archivo existente no coincide con el original.`
          );
        }
      }
      await this.storage.deleteIncomingChunksByItemId(meta.itemId).catch(() => 0);
      return existing;
    }

    const chunks = await this.storage.getIncomingChunksByItemId(meta.itemId);
    if (chunks.length !== meta.totalChunks) {
      throw new Error(
        `Faltan partes de "${meta.title}" (${chunks.length}/${meta.totalChunks}).`
      );
    }

    const parts: BlobPart[] = [];
    let totalAssembled = 0;
    for (let i = 0; i < chunks.length; i++) {
      if (chunks[i].chunkIndex !== i) {
        throw new Error(`Fragmento fuera de orden (${i}) en "${meta.title}".`);
      }
      parts.push(chunks[i].data);
      totalAssembled += chunks[i].data.byteLength;
    }

    if (totalAssembled !== meta.sizeBytes) {
      throw new Error(
        `El tamaño recibido (${totalAssembled} B) no coincide con el esperado (${meta.sizeBytes} B).`
      );
    }

    const blob = new Blob(parts, { type: meta.mimeType || 'application/octet-stream' });
    const actualSha256Hex = await hashBlobIncremental(blob, VEL_CHUNK_SIZE_BYTES);
    if (expectedNormalized !== undefined && actualSha256Hex !== expectedNormalized) {
      throw new Error(
        `Verificación SHA-256 fallida para "${meta.title}": los datos recibidos no coinciden con el archivo original.`
      );
    }

    const now = Date.now();
    const record: VelVaultItemRecord = {
      id: meta.itemId,
      ownerRole: 'CORE',
      kind: meta.fileKind || classifyFileKind(meta.title, meta.mimeType),
      title: meta.title,
      mimeType: meta.mimeType || 'application/octet-stream',
      sizeBytes: totalAssembled,
      sha256Hex: actualSha256Hex,
      blob,
      syncStatus: 'synced',
      progressPercent: 100,
      sourceDeviceId: meta.sourceDeviceId,
      createdAt: meta.createdAt || now,
      updatedAt: now,
      syncedAt: now
    };

    await this.storage.putItem(record);
    await this.storage.deleteIncomingChunksByItemId(meta.itemId).catch(() => 0);
    return record;
  }

  async cleanupIncomingChunks(itemId: string): Promise<void> {
    await this.storage.deleteIncomingChunksByItemId(itemId).catch(() => 0);
  }

  async getStats(): Promise<LocalStorageStats> {
    const items = await this.storage.getAllItems();
    const totalBytes = items.reduce((acc, item) => acc + (item.sizeBytes || 0), 0);
    let quotaSupported = false;
    let usageBytes: number | null = null;
    let quotaBytes: number | null = null;

    if (typeof navigator !== 'undefined' && navigator.storage?.estimate) {
      try {
        const est = await navigator.storage.estimate();
        quotaSupported = true;
        usageBytes = typeof est.usage === 'number' ? est.usage : null;
        quotaBytes = typeof est.quota === 'number' ? est.quota : null;
      } catch {}
    }

    return {
      itemCount: items.length,
      totalBytes,
      quotaSupported,
      usageBytes,
      quotaBytes
    };
  }
}

export const velLocalStore = new VelLocalStore();
