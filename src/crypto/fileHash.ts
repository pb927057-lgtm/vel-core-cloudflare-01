/**
 * SHA-256 incremental (FIPS 180-4) sin dependencias externas ni carga completa en memoria.
 * Diseñado para calcular el hash de archivos binarios por bloques antes del cifrado y
 * verificar la integridad exacta al recibir/almacenar bloques en VEL CORE.
 */

const SHA256_K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

const INITIAL_HASH = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

export function toExactArrayBuffer(input: Uint8Array | ArrayBuffer): ArrayBuffer {
  if (input instanceof ArrayBuffer) {
    return input;
  }
  if (input.byteOffset === 0 && input.byteLength === input.buffer.byteLength && input.buffer instanceof ArrayBuffer) {
    return input.buffer;
  }
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer;
}

export function toUint8Array(input: Uint8Array | ArrayBuffer): Uint8Array {
  return input instanceof Uint8Array ? input : new Uint8Array(input);
}

function compressBlock(
  state: Int32Array,
  data: Uint8Array,
  offset: number,
  w: Int32Array
): void {
  for (let i = 0; i < 16; i++) {
    const j = offset + i * 4;
    w[i] =
      ((data[j] << 24) |
        (data[j + 1] << 16) |
        (data[j + 2] << 8) |
        data[j + 3]) |
      0;
  }

  for (let i = 16; i < 64; i++) {
    const w15 = w[i - 15];
    const w2 = w[i - 2];
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }

  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];

  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) | 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) | 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) | 0;
  }

  state[0] = (state[0] + a) | 0;
  state[1] = (state[1] + b) | 0;
  state[2] = (state[2] + c) | 0;
  state[3] = (state[3] + d) | 0;
  state[4] = (state[4] + e) | 0;
  state[5] = (state[5] + f) | 0;
  state[6] = (state[6] + g) | 0;
  state[7] = (state[7] + h) | 0;
}

export class IncrementalSha256 {
  private state = new Int32Array(INITIAL_HASH);
  private block = new Uint8Array(64);
  private blockLen = 0;
  private totalBytes = 0;
  private w = new Int32Array(64);

  reset(): void {
    this.state.set(INITIAL_HASH);
    this.block.fill(0);
    this.blockLen = 0;
    this.totalBytes = 0;
  }

  getTotalBytes(): number {
    return this.totalBytes;
  }

  update(chunk: Uint8Array | ArrayBuffer): this {
    const data = toUint8Array(chunk);
    const len = data.length;
    if (len === 0) {
      return this;
    }

    this.totalBytes += len;
    let offset = 0;

    if (this.blockLen > 0) {
      const needed = 64 - this.blockLen;
      if (len < needed) {
        this.block.set(data, this.blockLen);
        this.blockLen += len;
        return this;
      }
      this.block.set(data.subarray(0, needed), this.blockLen);
      compressBlock(this.state, this.block, 0, this.w);
      this.blockLen = 0;
      offset = needed;
    }

    while (offset + 64 <= len) {
      compressBlock(this.state, data, offset, this.w);
      offset += 64;
    }

    if (offset < len) {
      const remaining = len - offset;
      this.block.set(data.subarray(offset), 0);
      this.blockLen = remaining;
    }

    return this;
  }

  /**
   * Calcula el digest SHA-256 final (32 bytes) sin mutar el estado acumulado,
   * permitiendo consultas idempotentes.
   */
  digest(): Uint8Array {
    const stateCopy = new Int32Array(this.state);
    const tailBlock = new Uint8Array(64);
    if (this.blockLen > 0) {
      tailBlock.set(this.block.subarray(0, this.blockLen), 0);
    }
    const wCopy = new Int32Array(64);

    let pos = this.blockLen;
    tailBlock[pos++] = 0x80;

    if (pos > 56) {
      tailBlock.fill(0, pos, 64);
      compressBlock(stateCopy, tailBlock, 0, wCopy);
      tailBlock.fill(0, 0, 56);
    } else {
      tailBlock.fill(0, pos, 56);
    }

    // Longitud total en bits (big-endian 64 bits; soporta > 4 GB con exactitud hasta 2^53 bytes)
    const highBits = Math.floor(this.totalBytes / 0x20000000) >>> 0;
    const lowBits = (this.totalBytes * 8) >>> 0;

    tailBlock[56] = (highBits >>> 24) & 0xff;
    tailBlock[57] = (highBits >>> 16) & 0xff;
    tailBlock[58] = (highBits >>> 8) & 0xff;
    tailBlock[59] = highBits & 0xff;
    tailBlock[60] = (lowBits >>> 24) & 0xff;
    tailBlock[61] = (lowBits >>> 16) & 0xff;
    tailBlock[62] = (lowBits >>> 8) & 0xff;
    tailBlock[63] = lowBits & 0xff;

    compressBlock(stateCopy, tailBlock, 0, wCopy);

    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const word = stateCopy[i];
      out[i * 4] = (word >>> 24) & 0xff;
      out[i * 4 + 1] = (word >>> 16) & 0xff;
      out[i * 4 + 2] = (word >>> 8) & 0xff;
      out[i * 4 + 3] = word & 0xff;
    }
    return out;
  }

  digestHex(): string {
    const bytes = this.digest();
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }
}

export function computeSha256Hex(input: Uint8Array | ArrayBuffer): string {
  return new IncrementalSha256().update(input).digestHex();
}

/**
 * Calcula el SHA-256 de un Blob o File por ventanas de lectura sin cargarlo completo en RAM.
 */
export async function hashBlobIncremental(
  blob: Blob,
  sliceSize = 512 * 1024,
  onProgress?: (bytesProcessed: number, totalBytes: number) => void
): Promise<string> {
  if (sliceSize <= 0) {
    throw new Error('sliceSize debe ser mayor que 0.');
  }

  const hasher = new IncrementalSha256();
  const total = blob.size;
  let offset = 0;

  while (offset < total) {
    const end = Math.min(offset + sliceSize, total);
    const buf = await blob.slice(offset, end).arrayBuffer();
    hasher.update(buf);
    offset = end;
    if (onProgress) {
      onProgress(offset, total);
    }
  }

  return hasher.digestHex();
}
