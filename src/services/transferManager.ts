import {
  DeviceRole,
  RelayDataPayload,
  VelItemKind,
  VelVaultItemSummary
} from '../contracts/velContracts';
import { arrayBufferToBase64, base64ToUint8Array } from '../crypto/deviceCrypto';
import { hashBlobIncremental, toExactArrayBuffer } from '../crypto/fileHash';
import {
  LocalStorageStats,
  VEL_CHUNK_SIZE_BYTES,
  velLocalStore,
  VelLocalStore
} from '../db/velLocalStore';
import { VelRelayClient } from './relayClient';

export interface IncomingProgressItem {
  itemId: string;
  title: string;
  fileKind: Exclude<VelItemKind, 'note'>;
  receivedChunks: number;
  totalChunks: number;
  progressPercent: number;
}

export interface TransferManagerSnapshot {
  items: VelVaultItemSummary[];
  incomingProgress: IncomingProgressItem[];
  stats: LocalStorageStats;
  isSyncing: boolean;
}

interface IncomingFileSession {
  itemId: string;
  title: string;
  fileKind: Exclude<VelItemKind, 'note'>;
  mimeType: string;
  sizeBytes: number;
  totalChunks: number;
  expectedSha256Hex: string;
  receivedChunks: number;
  sourceDeviceId: string;
  createdAt: number;
}

export class VelTransferManager {
  private relayClient: VelRelayClient;
  private store: VelLocalStore;
  private role: DeviceRole;

  private items: VelVaultItemSummary[] = [];
  private stats: LocalStorageStats = {
    itemCount: 0,
    totalBytes: 0,
    quotaSupported: false,
    usageBytes: null,
    quotaBytes: null
  };
  private incomingSessions = new Map<string, IncomingFileSession>();
  private incomingQueue = new Map<string, Promise<void>>();
  private itemAckWaiters = new Map<
    string,
    {
      resolve: (res: {
        ok: boolean;
        confirmedAt?: number;
        error?: string;
        rejectedByPeer?: boolean;
        unconfirmed?: boolean;
        revoked?: boolean;
      }) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();

  private inFlightItemIds = new Set<string>();
  private sendQueueChain: Promise<void> = Promise.resolve();
  private hasNormalizedInterrupted = false;
  private isFlushing = false;
  private isDisposed = false;
  private listeners = new Set<(snap: TransferManagerSnapshot) => void>();
  private transferErrorListeners = new Set<(event: { itemId: string; title?: string; error: string }) => void>();
  private unsubscribeRelay: (() => void) | null = null;
  private unsubscribeLost: (() => void) | null = null;

  constructor(options: {
    relayClient: VelRelayClient;
    role: DeviceRole;
    store?: VelLocalStore;
  }) {
    this.relayClient = options.relayClient;
    this.role = options.role;
    this.store = options.store || velLocalStore;

    this.relayClient.setDataHandler(async (msg) => {
      await this.handleIncomingRelayData(msg.senderId, msg.payload);
    });

    // No enviar automáticamente elementos pendientes al reconectar; los elementos
    // quedan guardados localmente hasta que el usuario toque Reintentar.
    this.unsubscribeRelay = this.relayClient.subscribe((snap) => {
      if (snap.connectionState === 'REVOKED' || snap.identity?.registrationStatus === 'revoked') {
        for (const [itemId, waiter] of this.itemAckWaiters.entries()) {
          clearTimeout(waiter.timer);
          this.itemAckWaiters.delete(itemId);
          waiter.resolve({
            ok: false,
            revoked: true,
            error: 'Dispositivo revocado: no puede transferir información.'
          });
        }
      }
    });

    this.unsubscribeLost = this.relayClient.onConnectionLost((reason) => {
      const isRevokedLoss = reason === 'DEVICE_REVOKED';
      for (const [itemId, waiter] of this.itemAckWaiters.entries()) {
        clearTimeout(waiter.timer);
        this.itemAckWaiters.delete(itemId);
        waiter.resolve(
          isRevokedLoss
            ? {
                ok: false,
                revoked: true,
                error: 'Dispositivo revocado: no puede transferir información.'
              }
            : {
                ok: false,
                unconfirmed: true,
                error: `ESTADO DESCONOCIDO: conexión interrumpida (${reason}) antes de confirmar en VEL CORE. Toca Reintentar.`
              }
        );
      }
    });

    void this.refresh();
  }

  public setRole(role: DeviceRole) {
    this.role = role;
  }

  public dispose(): void {
    this.isDisposed = true;
    this.relayClient.setDataHandler(null);
    if (this.unsubscribeRelay) {
      this.unsubscribeRelay();
      this.unsubscribeRelay = null;
    }
    if (this.unsubscribeLost) {
      this.unsubscribeLost();
      this.unsubscribeLost = null;
    }
    for (const waiter of this.itemAckWaiters.values()) {
      clearTimeout(waiter.timer);
      waiter.resolve({ ok: false, error: 'Servicio cerrado.' });
    }
    this.itemAckWaiters.clear();
    this.listeners.clear();
    this.transferErrorListeners.clear();
  }

  public getSnapshot(): TransferManagerSnapshot {
    const incomingProgress: IncomingProgressItem[] = Array.from(this.incomingSessions.values()).map(
      (s) => ({
        itemId: s.itemId,
        title: s.title,
        fileKind: s.fileKind,
        receivedChunks: s.receivedChunks,
        totalChunks: s.totalChunks,
        progressPercent:
          s.totalChunks > 0 ? Math.min(99, Math.round((s.receivedChunks / s.totalChunks) * 100)) : 0
      })
    );
    return {
      items: this.items,
      incomingProgress,
      stats: this.stats,
      isSyncing: this.isFlushing
    };
  }

  public subscribe(listener: (snap: TransferManagerSnapshot) => void): () => void {
    this.listeners.add(listener);
    listener(this.getSnapshot());
    return () => this.listeners.delete(listener);
  }

  public onTransferError(
    listener: (event: { itemId: string; title?: string; error: string }) => void
  ): () => void {
    this.transferErrorListeners.add(listener);
    return () => this.transferErrorListeners.delete(listener);
  }

  private emit() {
    const snap = this.getSnapshot();
    for (const l of this.listeners) l(snap);
  }

  private emitTransferError(itemId: string, error: string, title?: string) {
    for (const l of this.transferErrorListeners) {
      l({ itemId, title, error });
    }
  }

  public async refresh(): Promise<void> {
    if (this.isDisposed) return;
    let items = await this.store.listItems();
    if (!this.hasNormalizedInterrupted) {
      this.hasNormalizedInterrupted = true;
      const interrupted = items.filter(
        (i) => i.ownerRole === 'TERMINAL' && i.syncStatus === 'sending' && !this.inFlightItemIds.has(i.id)
      );
      if (interrupted.length > 0) {
        for (const it of interrupted) {
          await this.store.updateItemStatus(it.id, {
            syncStatus: 'pending',
            progressPercent: 0,
            errorMessage: 'ESTADO DESCONOCIDO: envío previo interrumpido sin confirmación. Toca Reintentar.'
          });
        }
        items = await this.store.listItems();
      }
    }
    const stats = await this.store.getStats();
    this.items = items;
    this.stats = stats;
    this.emit();
  }

  private isDeviceRevokedNow(): boolean {
    const snap = this.relayClient.getSnapshot();
    return snap.connectionState === 'REVOKED' || snap.identity?.registrationStatus === 'revoked';
  }

  private canSendImmediatelyNow(): { ok: boolean; reason?: string; revoked?: boolean } {
    const snap = this.relayClient.getSnapshot();
    if (snap.connectionState === 'REVOKED' || snap.identity?.registrationStatus === 'revoked') {
      return {
        ok: false,
        revoked: true,
        reason: 'Dispositivo revocado: no puede transferir información.'
      };
    }
    if (snap.subscriptionStatus?.linked && !snap.subscriptionStatus.active) {
      return {
        ok: false,
        reason: 'Suscripción vencida — envío pausado. Guardado localmente.'
      };
    }
    if (snap.connectionState !== 'LINKED' || !snap.peerOnline) {
      return {
        ok: false,
        reason: 'Sin conexión — guardado localmente. Toca Reintentar para enviarlo.'
      };
    }
    return { ok: true };
  }

  private enqueueSendItem(itemId: string): Promise<void> {
    if (this.isDisposed || this.role !== 'TERMINAL') return Promise.resolve();
    if (this.inFlightItemIds.has(itemId)) return this.sendQueueChain;

    this.inFlightItemIds.add(itemId);
    const task = this.sendQueueChain.then(async () => {
      if (this.isDisposed) return;
      this.isFlushing = true;
      this.emit();
      try {
        await this.sendSingleItemToCore(itemId);
      } finally {
        this.inFlightItemIds.delete(itemId);
        this.isFlushing = this.inFlightItemIds.size > 0;
        await this.refresh();
      }
    });
    this.sendQueueChain = task.catch(() => {});
    return task;
  }

  public async addNote(title: string, textContent: string): Promise<void> {
    const record = await this.store.saveNote(this.role, title, textContent);
    if (this.role === 'TERMINAL') {
      const check = this.canSendImmediatelyNow();
      if (!check.ok) {
        await this.store.updateItemStatus(record.id, {
          syncStatus: check.revoked ? 'error' : 'pending',
          progressPercent: 0,
          errorMessage: check.reason
        });
        await this.refresh();
        return;
      }
      await this.refresh();
      void this.enqueueSendItem(record.id);
      return;
    }
    await this.refresh();
  }

  public async addFiles(
    files: Array<{ name: string; type?: string; size: number; blob: Blob }>
  ): Promise<{ saved: number; errors: string[] }> {
    let saved = 0;
    const savedIds: string[] = [];
    const errors: string[] = [];
    const check = this.role === 'TERMINAL' ? this.canSendImmediatelyNow() : { ok: false };

    for (const file of files) {
      try {
        const rec = await this.store.saveLocalFile(this.role, file);
        saved++;
        if (this.role === 'TERMINAL') {
          if (!check.ok) {
            await this.store.updateItemStatus(rec.id, {
              syncStatus: check.revoked ? 'error' : 'pending',
              progressPercent: 0,
              errorMessage: check.reason
            });
          } else {
            savedIds.push(rec.id);
          }
        }
      } catch (err: any) {
        errors.push(err?.message || `No se pudo guardar ${file.name}`);
      }
    }
    await this.refresh();
    if (this.role === 'TERMINAL' && savedIds.length > 0) {
      for (const id of savedIds) {
        void this.enqueueSendItem(id);
      }
    }
    return { saved, errors };
  }

  public async retryItem(itemId: string): Promise<void> {
    if (this.isDisposed || this.role !== 'TERMINAL') return;
    const record = await this.store.getItem(itemId);
    if (!record || record.syncStatus === 'synced') {
      await this.refresh();
      return;
    }
    if (this.inFlightItemIds.has(itemId)) {
      return;
    }

    const check = this.canSendImmediatelyNow();
    if (!check.ok) {
      await this.store.updateItemStatus(itemId, {
        syncStatus: check.revoked ? 'error' : 'pending',
        progressPercent: 0,
        errorMessage: check.reason
      });
      await this.refresh();
      return;
    }

    await this.store.updateItemStatus(itemId, {
      syncStatus: 'pending',
      progressPercent: 0,
      errorMessage: undefined
    });
    await this.refresh();
    await this.enqueueSendItem(itemId);
  }

  /**
   * Elimina el elemento únicamente de este teléfono (en MÓVIL no borra la copia guardada en CORE).
   */
  public async deleteFromThisPhone(itemId: string): Promise<void> {
    await this.store.deleteItem(itemId);
    await this.refresh();
  }

  public async getItemWithBlob(itemId: string) {
    return this.store.getItem(itemId);
  }

  /**
   * Envío explícito de pendientes (solo cuando es invocado manualmente, nunca automático tras reconectar).
   */
  public async flushPendingQueue(): Promise<void> {
    if (this.isDisposed || this.role !== 'TERMINAL') return;
    const check = this.canSendImmediatelyNow();
    if (!check.ok) {
      return;
    }

    const all = await this.store.listItems();
    const pending = all
      .filter(
        (item) =>
          (item.syncStatus === 'pending' || item.syncStatus === 'sending') &&
          !this.inFlightItemIds.has(item.id)
      )
      .sort((a, b) => a.createdAt - b.createdAt);

    for (const summary of pending) {
      if (this.isDisposed) break;
      const liveCheck = this.canSendImmediatelyNow();
      if (!liveCheck.ok) break;
      await this.enqueueSendItem(summary.id);
    }
  }

  private waitForItemAck(itemId: string, timeoutMs = 20_000) {
    return new Promise<{
      ok: boolean;
      confirmedAt?: number;
      error?: string;
      rejectedByPeer?: boolean;
      unconfirmed?: boolean;
      revoked?: boolean;
    }>((resolve) => {
      const existing = this.itemAckWaiters.get(itemId);
      if (existing) {
        clearTimeout(existing.timer);
        existing.resolve({
          ok: false,
          unconfirmed: true,
          error: 'ESTADO DESCONOCIDO: reemplazado por un nuevo intento.'
        });
      }
      const timer = setTimeout(() => {
        this.itemAckWaiters.delete(itemId);
        resolve({
          ok: false,
          unconfirmed: true,
          error: 'ESTADO DESCONOCIDO: VEL CORE no confirmó la recepción a tiempo. Toca Reintentar.'
        });
      }, timeoutMs);
      this.itemAckWaiters.set(itemId, { resolve, timer });
    });
  }

  private classifyRouteFailure(
    reason?: string,
    rawError?: string
  ): { syncStatus: 'pending' | 'error'; message: string } {
    if (reason === 'DEVICE_REVOKED') {
      return {
        syncStatus: 'error',
        message: rawError || 'Dispositivo revocado: no puede transferir información.'
      };
    }
    if (reason === 'ENCRYPTION_FAILED') {
      return {
        syncStatus: 'error',
        message: rawError || 'Falló el cifrado E2EE; no se envió información.'
      };
    }
    if (reason === 'ROUTE_TIMEOUT') {
      return {
        syncStatus: 'pending',
        message: 'ESTADO DESCONOCIDO: no se pudo confirmar el envío con el servidor. Toca Reintentar.'
      };
    }
    return {
      syncStatus: 'pending',
      message: 'Sin conexión — guardado localmente. Toca Reintentar para enviarlo.'
    };
  }

  private async sendSingleItemToCore(itemId: string): Promise<void> {
    const record = await this.store.getItem(itemId);
    if (!record || record.syncStatus === 'synced') return;

    const preCheck = this.canSendImmediatelyNow();
    if (!preCheck.ok) {
      await this.store.updateItemStatus(itemId, {
        syncStatus: preCheck.revoked ? 'error' : 'pending',
        progressPercent: 0,
        errorMessage: preCheck.reason
      });
      return;
    }

    await this.store.updateItemStatus(itemId, {
      syncStatus: 'sending',
      progressPercent: 5,
      errorMessage: undefined
    });
    await this.refresh();

    if (record.kind === 'note') {
      const ackPromise = this.waitForItemAck(itemId, 15_000);
      const route = await this.relayClient.sendRelayPayload({
        kind: 'note',
        itemId: record.id,
        title: record.title,
        textContent: record.textContent || '',
        createdAt: record.createdAt
      });

      if (!route.routed) {
        const waiter = this.itemAckWaiters.get(itemId);
        if (waiter) {
          clearTimeout(waiter.timer);
          this.itemAckWaiters.delete(itemId);
        }
        const outcome = this.classifyRouteFailure(route.reason, route.error);
        await this.store.updateItemStatus(itemId, {
          syncStatus: outcome.syncStatus,
          progressPercent: 0,
          errorMessage: outcome.message
        });
        return;
      }

      const ack = await ackPromise;
      if (ack.ok) {
        await this.store.updateItemStatus(itemId, {
          syncStatus: 'synced',
          progressPercent: 100,
          syncedAt: ack.confirmedAt || Date.now(),
          errorMessage: undefined
        });
      } else {
        await this.store.updateItemStatus(itemId, {
          syncStatus: ack.revoked || ack.rejectedByPeer ? 'error' : 'pending',
          progressPercent: 0,
          errorMessage: ack.error || 'ESTADO DESCONOCIDO: no se pudo confirmar en VEL CORE. Toca Reintentar.'
        });
      }
      return;
    }

    // Envío de archivo binario en bloques de 128 KB con verificación SHA-256
    const blob = record.blob;
    if (!blob) {
      await this.store.updateItemStatus(itemId, {
        syncStatus: 'error',
        errorMessage: 'No se encontró el archivo local en este teléfono.'
      });
      return;
    }

    let fileSha256Hex: string;
    try {
      fileSha256Hex = await hashBlobIncremental(blob, VEL_CHUNK_SIZE_BYTES);
    } catch (err: any) {
      const errMsg = err?.message || 'No se pudo calcular la huella SHA-256 del archivo.';
      await this.store.updateItemStatus(itemId, {
        syncStatus: 'error',
        progressPercent: 0,
        errorMessage: errMsg
      });
      this.emitTransferError(itemId, errMsg, record.title);
      return;
    }

    await this.store.updateItemStatus(itemId, { sha256Hex: fileSha256Hex });

    const totalChunks = Math.max(1, Math.ceil(blob.size / VEL_CHUNK_SIZE_BYTES));

    const startRes = await this.relayClient.sendRelayPayload({
      kind: 'file_start',
      itemId: record.id,
      fileKind: record.kind,
      title: record.title,
      mimeType: record.mimeType,
      sizeBytes: blob.size,
      totalChunks,
      sha256Hex: fileSha256Hex,
      createdAt: record.createdAt
    });

    if (!startRes.routed) {
      const outcome = this.classifyRouteFailure(startRes.reason, startRes.error);
      await this.store.updateItemStatus(itemId, {
        syncStatus: outcome.syncStatus,
        progressPercent: 0,
        errorMessage: outcome.message
      });
      return;
    }

    for (let i = 0; i < totalChunks; i++) {
      if (this.isDeviceRevokedNow()) {
        await this.store.updateItemStatus(itemId, {
          syncStatus: 'error',
          progressPercent: 0,
          errorMessage: 'Dispositivo revocado: transferencia detenida.'
        });
        return;
      }

      const start = i * VEL_CHUNK_SIZE_BYTES;
      const end = Math.min(start + VEL_CHUNK_SIZE_BYTES, blob.size);
      const buf = await blob.slice(start, end).arrayBuffer();
      const dataBase64 = arrayBufferToBase64(buf);

      const chunkRes = await this.relayClient.sendRelayPayload(
        {
          kind: 'file_chunk',
          itemId: record.id,
          chunkIndex: i,
          totalChunks,
          dataBase64
        },
        20_000
      );

      if (!chunkRes.routed) {
        const outcome = this.classifyRouteFailure(chunkRes.reason, chunkRes.error);
        await this.store.updateItemStatus(itemId, {
          syncStatus: outcome.syncStatus,
          progressPercent: 0,
          errorMessage: outcome.message
        });
        return;
      }

      const pct = Math.min(95, Math.round(((i + 1) / totalChunks) * 90) + 5);
      await this.store.updateItemStatus(itemId, {
        syncStatus: 'sending',
        progressPercent: pct
      });
      this.items = this.items.map((item) =>
        item.id === itemId ? { ...item, syncStatus: 'sending', progressPercent: pct } : item
      );
      this.emit();
    }

    const ackPromise = this.waitForItemAck(itemId, 25_000);
    const endRes = await this.relayClient.sendRelayPayload({
      kind: 'file_end',
      itemId: record.id,
      totalChunks,
      sizeBytes: blob.size,
      sha256Hex: fileSha256Hex
    });

    if (!endRes.routed) {
      const waiter = this.itemAckWaiters.get(itemId);
      if (waiter) {
        clearTimeout(waiter.timer);
        this.itemAckWaiters.delete(itemId);
      }
      const outcome = this.classifyRouteFailure(endRes.reason, endRes.error);
      await this.store.updateItemStatus(itemId, {
        syncStatus: outcome.syncStatus,
        progressPercent: 0,
        errorMessage: outcome.message
      });
      return;
    }

    const ack = await ackPromise;
    if (ack.ok) {
      await this.store.updateItemStatus(itemId, {
        syncStatus: 'synced',
        progressPercent: 100,
        syncedAt: ack.confirmedAt || Date.now(),
        errorMessage: undefined
      });
    } else {
      await this.store.updateItemStatus(itemId, {
        syncStatus: ack.revoked || ack.rejectedByPeer ? 'error' : 'pending',
        progressPercent: 0,
        errorMessage: ack.error || 'ESTADO DESCONOCIDO: no se pudo confirmar el guardado en VEL CORE. Toca Reintentar.'
      });
      if (ack.rejectedByPeer && ack.error) {
        this.emitTransferError(itemId, ack.error, record.title);
      }
    }
  }

  private async handleIncomingRelayData(senderId: string, payload: RelayDataPayload): Promise<void> {
    if (payload.kind === 'item_ack') {
      const waiter = this.itemAckWaiters.get(payload.itemId);
      if (waiter) {
        clearTimeout(waiter.timer);
        this.itemAckWaiters.delete(payload.itemId);
        waiter.resolve({
          ok: payload.ok,
          confirmedAt: payload.confirmedAt,
          error: payload.error,
          rejectedByPeer: !payload.ok
        });
      }
      return;
    }

    // Serializar paquetes por itemId en CORE para que los fragmentos lleguen en orden exacto
    const itemId = payload.itemId;
    const prev = this.incomingQueue.get(itemId) || Promise.resolve();
    const next = prev
      .then(() => this.processCoreIncomingPayload(senderId, payload))
      .catch(() => {});
    this.incomingQueue.set(itemId, next);
    await next;
  }

  private async processCoreIncomingPayload(senderId: string, payload: RelayDataPayload): Promise<void> {
    if (this.isDisposed || this.isDeviceRevokedNow()) return;

    if (payload.kind === 'note') {
      try {
        await this.store.saveNote('CORE', payload.title, payload.textContent, {
          id: payload.itemId,
          sourceDeviceId: senderId,
          syncStatus: 'synced',
          createdAt: payload.createdAt
        });
        await this.refresh();
        await this.relayClient.sendRelayPayload({
          kind: 'item_ack',
          itemId: payload.itemId,
          ok: true,
          confirmedAt: Date.now()
        });
      } catch (err: any) {
        await this.relayClient.sendRelayPayload({
          kind: 'item_ack',
          itemId: payload.itemId,
          ok: false,
          confirmedAt: Date.now(),
          error: err?.message || 'No se pudo guardar la nota en VEL CORE.'
        });
      }
      return;
    }

    if (payload.kind === 'file_start') {
      await this.store.cleanupIncomingChunks(payload.itemId);
      this.incomingSessions.set(payload.itemId, {
        itemId: payload.itemId,
        title: payload.title,
        fileKind: payload.fileKind,
        mimeType: payload.mimeType,
        sizeBytes: payload.sizeBytes,
        totalChunks: payload.totalChunks,
        expectedSha256Hex: typeof payload.sha256Hex === 'string' ? payload.sha256Hex.trim().toLowerCase() : '',
        receivedChunks: 0,
        sourceDeviceId: senderId,
        createdAt: payload.createdAt
      });
      this.emit();
      return;
    }

    if (payload.kind === 'file_chunk') {
      const session = this.incomingSessions.get(payload.itemId);
      if (!session) return;
      const bytes = base64ToUint8Array(payload.dataBase64);
      await this.store.stageIncomingChunk(payload.itemId, payload.chunkIndex, toExactArrayBuffer(bytes));
      session.receivedChunks += 1;
      this.emit();
      return;
    }

    if (payload.kind === 'file_end') {
      const session = this.incomingSessions.get(payload.itemId);
      try {
        if (!session) {
          // Si ya existía completo de un intento previo idempotente (verificando SHA-256 si está presente)
          const existing = await this.store.getItem(payload.itemId);
          if (existing) {
            const endHash = typeof payload.sha256Hex === 'string' ? payload.sha256Hex.trim().toLowerCase() : '';
            if (endHash && existing.blob) {
              const existingHash =
                existing.sha256Hex || (await hashBlobIncremental(existing.blob, VEL_CHUNK_SIZE_BYTES));
              if (existingHash.trim().toLowerCase() !== endHash) {
                throw new Error(
                  `Verificación SHA-256 fallida para "${existing.title}": el archivo almacenado no coincide.`
                );
              }
            }
            await this.relayClient.sendRelayPayload({
              kind: 'item_ack',
              itemId: payload.itemId,
              ok: true,
              confirmedAt: Date.now()
            });
            return;
          }
          throw new Error('Sesión de archivo incompleta o no encontrada en VEL CORE.');
        }

        const startHash = session.expectedSha256Hex;
        const endHash = typeof payload.sha256Hex === 'string' ? payload.sha256Hex.trim().toLowerCase() : '';
        if (!/^[a-f0-9]{64}$/.test(startHash) || !/^[a-f0-9]{64}$/.test(endHash) || startHash !== endHash) {
          throw new Error(
            `Verificación SHA-256 rechazada para "${session.title}": el hash de origen falta o no coincide.`
          );
        }

        await this.store.finalizeIncomingFile({
          itemId: session.itemId,
          title: session.title,
          fileKind: session.fileKind,
          mimeType: session.mimeType,
          sizeBytes: payload.sizeBytes,
          totalChunks: payload.totalChunks,
          sourceDeviceId: session.sourceDeviceId,
          createdAt: session.createdAt,
          expectedSha256Hex: endHash
        });

        this.incomingSessions.delete(payload.itemId);
        await this.refresh();

        await this.relayClient.sendRelayPayload({
          kind: 'item_ack',
          itemId: payload.itemId,
          ok: true,
          confirmedAt: Date.now()
        });
      } catch (err: any) {
        const errMsg = err?.message || 'Error guardando el archivo en VEL CORE.';
        this.incomingSessions.delete(payload.itemId);
        await this.store.cleanupIncomingChunks(payload.itemId);
        this.emit();
        this.emitTransferError(payload.itemId, errMsg, session?.title);
        await this.relayClient.sendRelayPayload({
          kind: 'item_ack',
          itemId: payload.itemId,
          ok: false,
          confirmedAt: Date.now(),
          error: errMsg
        });
      }
    }
  }
}
