// src/db/db.ts
import {
  AuthorizationRecord,
  DeviceLinkRecord,
  LocalDeviceIdentityRecord,
  VelIncomingChunkRecord,
  VelVaultItemRecord
} from '../contracts/velContracts';

export interface VelDeviceConfigEntry {
  key: string;
  value: unknown;
  updatedAt: number;
}

export interface VelStorageAdapter {
  getIdentity(): Promise<LocalDeviceIdentityRecord | null>;
  saveIdentity(identity: LocalDeviceIdentityRecord): Promise<void>;
  clearIdentity(): Promise<void>;
  getConfig<T = unknown>(key: string): Promise<T | null>;
  setConfig(key: string, value: unknown): Promise<void>;
  deleteConfig(key: string): Promise<void>;
  getAuthorization(authorizationId: string): Promise<AuthorizationRecord | null>;
  saveAuthorization(record: AuthorizationRecord): Promise<void>;
  getLink(linkId: string): Promise<DeviceLinkRecord | null>;
  saveLink(record: DeviceLinkRecord): Promise<void>;
}

export interface VelUnifiedStorageAdapter extends VelStorageAdapter {
  putItem(record: VelVaultItemRecord): Promise<void>;
  getItem(id: string): Promise<VelVaultItemRecord | null>;
  getAllItems(): Promise<VelVaultItemRecord[]>;
  deleteItem(id: string): Promise<void>;
  putIncomingChunk(record: VelIncomingChunkRecord): Promise<void>;
  getIncomingChunksByItemId(itemId: string): Promise<VelIncomingChunkRecord[]>;
  deleteIncomingChunksByItemId(itemId: string): Promise<number>;
  close(): Promise<void>;
}

export const STORE_RECORDS = 'records';
export const STORE_IDENTITY = 'device_identity';
export const STORE_CONFIG = 'device_config';
export const STORE_AUTHORIZATIONS = 'authorizations_cache';
export const STORE_LINKS = 'links_cache';
export const STORE_VAULT_FILES = 'vault_files';
export const STORE_VAULT_CHUNKS = 'vault_chunks';
export const STORE_ITEMS = 'vel_items';
export const STORE_INCOMING_CHUNKS = 'vel_incoming_chunks';
export const VEL_DB_VERSION = 4;

export class VelDatabase implements VelUnifiedStorageAdapter {
  private dbName: string;
  private dbVersion: number;
  private activeDb: IDBDatabase | null = null;
  private openingPromise: Promise<IDBDatabase> | null = null;

  constructor(dbName = 'VelLocalDB', dbVersion = VEL_DB_VERSION) {
    this.dbName = dbName;
    this.dbVersion = dbVersion;
  }

  getDbName(): string {
    return this.dbName;
  }

  getDbVersion(): number {
    return this.dbVersion;
  }

  async open(): Promise<IDBDatabase> {
    if (typeof indexedDB === 'undefined') {
      throw new Error('IndexedDB no está disponible en este entorno.');
    }

    if (this.activeDb) {
      return this.activeDb;
    }

    if (this.openingPromise) {
      return this.openingPromise;
    }

    this.openingPromise = new Promise<IDBDatabase>((resolve, reject) => {
      let settled = false;
      let blockedTimer: ReturnType<typeof setTimeout> | null = null;

      const clearTimers = () => {
        if (blockedTimer !== null) {
          clearTimeout(blockedTimer);
          blockedTimer = null;
        }
      };

      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        clearTimers();
        this.openingPromise = null;
        reject(err instanceof Error ? err : new Error(String(err || 'Error al abrir IndexedDB.')));
      };

      let request: IDBOpenDBRequest;
      try {
        request = indexedDB.open(this.dbName, this.dbVersion);
      } catch (err) {
        fail(err);
        return;
      }

      request.onerror = () => {
        fail(request.error || new Error(`No se pudo abrir ${this.dbName} v${this.dbVersion}.`));
      };

      request.onblocked = () => {
        if (this.activeDb) {
          try {
            this.activeDb.close();
          } catch {}
          this.activeDb = null;
        }
        if (blockedTimer === null) {
          blockedTimer = setTimeout(() => {
            fail(new Error(`Apertura de ${this.dbName} v${this.dbVersion} bloqueada por otra pestaña.`));
          }, 750);
        }
      };

      request.onupgradeneeded = (event) => {
        const upgradeRequest = event.target as IDBOpenDBRequest;
        const db = upgradeRequest.result;
        const upgradeTx = upgradeRequest.transaction;

        if (upgradeTx) {
          upgradeTx.onerror = () => {
            fail(upgradeTx.error || new Error(`Error migrando ${this.dbName}.`));
          };
          upgradeTx.onabort = () => {
            fail(upgradeTx.error || new Error(`Migración de ${this.dbName} abortada.`));
          };
        }

        try {
          if (!db.objectStoreNames.contains(STORE_RECORDS)) {
            db.createObjectStore(STORE_RECORDS, { keyPath: 'id' });
          }
          if (!db.objectStoreNames.contains(STORE_IDENTITY)) {
            db.createObjectStore(STORE_IDENTITY, { keyPath: 'id' });
          }
          if (!db.objectStoreNames.contains(STORE_CONFIG)) {
            db.createObjectStore(STORE_CONFIG, { keyPath: 'key' });
          }
          if (!db.objectStoreNames.contains(STORE_AUTHORIZATIONS)) {
            db.createObjectStore(STORE_AUTHORIZATIONS, { keyPath: 'authorizationId' });
          }
          if (!db.objectStoreNames.contains(STORE_LINKS)) {
            db.createObjectStore(STORE_LINKS, { keyPath: 'linkId' });
          }
          if (!db.objectStoreNames.contains(STORE_VAULT_FILES)) {
            const filesStore = db.createObjectStore(STORE_VAULT_FILES, { keyPath: 'fileId' });
            filesStore.createIndex('by_status', 'status', { unique: false });
            filesStore.createIndex('by_createdAt', 'createdAt', { unique: false });
          }
          if (!db.objectStoreNames.contains(STORE_VAULT_CHUNKS)) {
            const chunksStore = db.createObjectStore(STORE_VAULT_CHUNKS, { keyPath: 'chunkKey' });
            chunksStore.createIndex('by_fileId', 'fileId', { unique: false });
          }
          if (!db.objectStoreNames.contains(STORE_ITEMS)) {
            const itemsStore = db.createObjectStore(STORE_ITEMS, { keyPath: 'id' });
            itemsStore.createIndex('by_createdAt', 'createdAt', { unique: false });
            itemsStore.createIndex('by_syncStatus', 'syncStatus', { unique: false });
          }
          if (!db.objectStoreNames.contains(STORE_INCOMING_CHUNKS)) {
            const incStore = db.createObjectStore(STORE_INCOMING_CHUNKS, { keyPath: 'chunkKey' });
            incStore.createIndex('by_itemId', 'itemId', { unique: false });
          }
        } catch (upgradeErr) {
          try {
            upgradeTx?.abort();
          } catch {}
          fail(upgradeErr);
        }
      };

      request.onsuccess = () => {
        if (settled) {
          try {
            request.result.close();
          } catch {}
          return;
        }
        settled = true;
        clearTimers();

        const db = request.result;
        this.activeDb = db;
        this.openingPromise = null;

        db.onversionchange = () => {
          try {
            db.close();
          } catch {}
          if (this.activeDb === db) {
            this.activeDb = null;
          }
        };

        db.onclose = () => {
          if (this.activeDb === db) {
            this.activeDb = null;
          }
        };

        resolve(db);
      };
    });

    return this.openingPromise;
  }

  async close(): Promise<void> {
    if (this.openingPromise) {
      try {
        await this.openingPromise;
      } catch {}
    }
    if (this.activeDb) {
      const db = this.activeDb;
      this.activeDb = null;
      try {
        db.close();
      } catch {}
    }
  }

  private async putInStore(storeName: string, value: unknown): Promise<void> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        reject(err instanceof Error ? err : new Error(String(err || 'Error escribiendo en IndexedDB.')));
      };

      const transaction = db.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.put(value);

      transaction.oncomplete = () => {
        if (settled) return;
        settled = true;
        resolve();
      };
      transaction.onerror = () => fail(transaction.error || request.error);
      transaction.onabort = () => fail(transaction.error || request.error || new Error('Transacción abortada.'));
      request.onerror = () => fail(request.error);
    });
  }

  private async getFromStore<T>(storeName: string, key: IDBValidKey): Promise<T | null> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        reject(err instanceof Error ? err : new Error(String(err || 'Error leyendo de IndexedDB.')));
      };

      const transaction = db.transaction(storeName, 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.get(key);

      request.onsuccess = () => {
        if (settled) return;
        settled = true;
        resolve((request.result as T) ?? null);
      };
      request.onerror = () => fail(request.error);
      transaction.onerror = () => fail(transaction.error || request.error);
      transaction.onabort = () => fail(transaction.error || new Error('Transacción abortada.'));
    });
  }

  private async getAllFromStore<T>(storeName: string): Promise<T[]> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        reject(err instanceof Error ? err : new Error(String(err || 'Error listando IndexedDB.')));
      };

      const transaction = db.transaction(storeName, 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.getAll();

      request.onsuccess = () => {
        if (settled) return;
        settled = true;
        resolve((request.result as T[]) || []);
      };
      request.onerror = () => fail(request.error);
      transaction.onerror = () => fail(transaction.error || request.error);
      transaction.onabort = () => fail(transaction.error || new Error('Transacción abortada.'));
    });
  }

  private async deleteFromStore(storeName: string, key: IDBValidKey): Promise<void> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        reject(err instanceof Error ? err : new Error(String(err || 'Error borrando en IndexedDB.')));
      };

      const transaction = db.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.delete(key);

      transaction.oncomplete = () => {
        if (settled) return;
        settled = true;
        resolve();
      };
      transaction.onerror = () => fail(transaction.error || request.error);
      transaction.onabort = () => fail(transaction.error || request.error || new Error('Transacción abortada.'));
      request.onerror = () => fail(request.error);
    });
  }

  async getIdentity(): Promise<LocalDeviceIdentityRecord | null> {
    return this.getFromStore<LocalDeviceIdentityRecord>(STORE_IDENTITY, 'current');
  }

  async saveIdentity(identity: LocalDeviceIdentityRecord): Promise<void> {
    await this.putInStore(STORE_IDENTITY, identity);
  }

  async clearIdentity(): Promise<void> {
    await this.deleteFromStore(STORE_IDENTITY, 'current');
  }

  async getConfig<T = unknown>(key: string): Promise<T | null> {
    const entry = await this.getFromStore<VelDeviceConfigEntry>(STORE_CONFIG, key);
    return entry ? (entry.value as T) : null;
  }

  async setConfig(key: string, value: unknown): Promise<void> {
    await this.putInStore(STORE_CONFIG, {
      key,
      value,
      updatedAt: Date.now()
    } satisfies VelDeviceConfigEntry);
  }

  async deleteConfig(key: string): Promise<void> {
    await this.deleteFromStore(STORE_CONFIG, key);
  }

  async getAuthorization(authorizationId: string): Promise<AuthorizationRecord | null> {
    return this.getFromStore<AuthorizationRecord>(STORE_AUTHORIZATIONS, authorizationId);
  }

  async saveAuthorization(record: AuthorizationRecord): Promise<void> {
    await this.putInStore(STORE_AUTHORIZATIONS, record);
  }

  async getLink(linkId: string): Promise<DeviceLinkRecord | null> {
    return this.getFromStore<DeviceLinkRecord>(STORE_LINKS, linkId);
  }

  async saveLink(record: DeviceLinkRecord): Promise<void> {
    await this.putInStore(STORE_LINKS, record);
  }

  // --- Almacén unificado v4 para ambos teléfonos (vel_items y vel_incoming_chunks) ---

  async putItem(record: VelVaultItemRecord): Promise<void> {
    await this.putInStore(STORE_ITEMS, record);
  }

  async getItem(id: string): Promise<VelVaultItemRecord | null> {
    return this.getFromStore<VelVaultItemRecord>(STORE_ITEMS, id);
  }

  async getAllItems(): Promise<VelVaultItemRecord[]> {
    return this.getAllFromStore<VelVaultItemRecord>(STORE_ITEMS);
  }

  async deleteItem(id: string): Promise<void> {
    await this.deleteFromStore(STORE_ITEMS, id);
  }

  async putIncomingChunk(record: VelIncomingChunkRecord): Promise<void> {
    await this.putInStore(STORE_INCOMING_CHUNKS, record);
  }

  async getIncomingChunksByItemId(itemId: string): Promise<VelIncomingChunkRecord[]> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        reject(err instanceof Error ? err : new Error(String(err || 'Error leyendo fragmentos temporales.')));
      };

      const transaction = db.transaction(STORE_INCOMING_CHUNKS, 'readonly');
      const store = transaction.objectStore(STORE_INCOMING_CHUNKS);
      const index = store.index('by_itemId');
      const request = index.getAll(IDBKeyRange.only(itemId));

      request.onsuccess = () => {
        if (settled) return;
        settled = true;
        const rows = ((request.result as VelIncomingChunkRecord[]) || []).slice();
        rows.sort((a, b) => a.chunkIndex - b.chunkIndex);
        resolve(rows);
      };
      request.onerror = () => fail(request.error);
      transaction.onerror = () => fail(transaction.error || request.error);
      transaction.onabort = () => fail(transaction.error || new Error('Lectura abortada.'));
    });
  }

  async deleteIncomingChunksByItemId(itemId: string): Promise<number> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      let settled = false;
      let deleted = 0;
      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        reject(err instanceof Error ? err : new Error(String(err || 'Error limpiando fragmentos temporales.')));
      };

      const transaction = db.transaction(STORE_INCOMING_CHUNKS, 'readwrite');
      const store = transaction.objectStore(STORE_INCOMING_CHUNKS);
      const index = store.index('by_itemId');
      const cursorReq = index.openCursor(IDBKeyRange.only(itemId));

      cursorReq.onerror = () => fail(cursorReq.error);
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result;
        if (!cursor) return;
        const delReq = cursor.delete();
        delReq.onerror = () => fail(delReq.error);
        deleted++;
        cursor.continue();
      };

      transaction.oncomplete = () => {
        if (settled) return;
        settled = true;
        resolve(deleted);
      };
      transaction.onerror = () => fail(transaction.error);
      transaction.onabort = () => fail(transaction.error || new Error('Borrado abortado.'));
    });
  }
}

export const velDb = new VelDatabase();
