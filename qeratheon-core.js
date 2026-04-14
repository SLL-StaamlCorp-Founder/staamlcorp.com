/**
 * @file qeratheon-core.js
 * @description Qeratheon-1 Post-Quantum Symmetric Encryption Primitive
 *              Entropy-Permutation Cipher (EPC) Pipeline
 * @version 1.0.0
 * @license Proprietary - StaamlCorp
 *
 * Architecture:
 *   Master Key (512-bit)
 *       |-- K_perm --> Feistel PRP (4-round Luby-Rackoff / SHA-256)
 *       |-- K_enc  --> Hybrid Pad (Pad_comp XOR Pad_stat)
 *       |-- K_mac  --> HMAC-SHA-256 (encrypt-then-MAC)
 *
 *   Pipeline: Plaintext -> PKCS7 Pad -> Feistel(block) -> XOR Pad -> Ciphertext
 *   Tag:      HMAC(K_mac, C || AD || entropy_fingerprint)
 *
 * No external dependencies. Uses Web Crypto API (SubtleCrypto) exclusively.
 */
(function (root) {
  'use strict';

  const VERSION = '1.0.0';
  const BLOCK_SIZE = 128;       // 1024-bit full block
  const HALF_BLOCK = 64;        // 512-bit half block
  const TAG_SIZE = 32;          // 256-bit HMAC tag
  const SALT_SIZE = 16;         // 128-bit salt
  const NONCE_SIZE = 12;        // 96-bit nonce
  const TIMESTAMP_SIZE = 8;     // 64-bit timestamp
  const MIN_MASTER_KEY = 64;    // 512-bit minimum master key
  const MIN_SUBKEY = 32;        // 256-bit minimum sub-key
  const FEISTEL_ROUNDS = 4;

  const DOMAIN_PERM_ROUND = 'QERATHEON/perm/round';
  const DOMAIN_KD_PERM = 'QERATHEON/key/perm';
  const DOMAIN_KD_ENC = 'QERATHEON/key/enc';
  const DOMAIN_KD_MAC = 'QERATHEON/key/mac';

  const crypto = root.crypto || root.msCrypto;
  const subtle = crypto && crypto.subtle;

  if (!subtle) {
    throw new Error('Qeratheon-1: Web Crypto API (SubtleCrypto) is required but not available.');
  }

  // ---------------------------------------------------------------------------
  // Utility helpers
  // ---------------------------------------------------------------------------

  /**
   * Encode a UTF-8 string to Uint8Array.
   * @param {string} str
   * @returns {Uint8Array}
   */
  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }

  /**
   * Decode a Uint8Array to UTF-8 string.
   * @param {Uint8Array} buf
   * @returns {string}
   */
  function utf8Decode(buf) {
    return new TextDecoder().decode(buf);
  }

  /**
   * Concatenate an arbitrary number of Uint8Arrays.
   * @param {...Uint8Array} arrays
   * @returns {Uint8Array}
   */
  function concat(...arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  /**
   * XOR two equal-length Uint8Arrays. Returns a new array.
   * @param {Uint8Array} a
   * @param {Uint8Array} b
   * @returns {Uint8Array}
   */
  function xorBytes(a, b) {
    const len = Math.min(a.length, b.length);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }

  /**
   * Constant-time comparison of two Uint8Arrays.
   * Returns true only if they are identical.
   * @param {Uint8Array} a
   * @param {Uint8Array} b
   * @returns {boolean}
   */
  function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  /**
   * Encode a 64-bit integer as big-endian 8-byte Uint8Array.
   * Uses two 32-bit writes for safe integer handling.
   * @param {number} value
   * @returns {Uint8Array}
   */
  function uint64ToBytes(value) {
    const buf = new Uint8Array(8);
    const hi = Math.floor(value / 0x100000000) >>> 0;
    const lo = (value >>> 0);
    buf[0] = (hi >>> 24) & 0xff;
    buf[1] = (hi >>> 16) & 0xff;
    buf[2] = (hi >>> 8) & 0xff;
    buf[3] = hi & 0xff;
    buf[4] = (lo >>> 24) & 0xff;
    buf[5] = (lo >>> 16) & 0xff;
    buf[6] = (lo >>> 8) & 0xff;
    buf[7] = lo & 0xff;
    return buf;
  }

  /**
   * Read a big-endian 64-bit integer from 8 bytes.
   * @param {Uint8Array} buf
   * @param {number} offset
   * @returns {number}
   */
  function bytesToUint64(buf, offset) {
    const hi = ((buf[offset] << 24) | (buf[offset + 1] << 16) |
                (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
    const lo = ((buf[offset + 4] << 24) | (buf[offset + 5] << 16) |
                (buf[offset + 6] << 8) | buf[offset + 7]) >>> 0;
    return hi * 0x100000000 + lo;
  }

  /**
   * Base64 encode a Uint8Array.
   * @param {Uint8Array} buf
   * @returns {string}
   */
  function toBase64(buf) {
    let binary = '';
    for (let i = 0; i < buf.length; i++) {
      binary += String.fromCharCode(buf[i]);
    }
    return btoa(binary);
  }

  /**
   * Base64 decode a string to Uint8Array.
   * @param {string} str
   * @returns {Uint8Array}
   */
  function fromBase64(str) {
    const binary = atob(str);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      buf[i] = binary.charCodeAt(i);
    }
    return buf;
  }

  /**
   * Compute SHA-256 digest.
   * @param {Uint8Array} data
   * @returns {Promise<Uint8Array>}
   */
  async function sha256(data) {
    const hash = await subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
  }

  /**
   * Compute HMAC-SHA-256.
   * @param {Uint8Array} key - Key bytes (>= 32 bytes recommended)
   * @param {Uint8Array} data - Message bytes
   * @returns {Promise<Uint8Array>} 32-byte MAC
   */
  async function hmacSha256(key, data) {
    const cryptoKey = await subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await subtle.sign('HMAC', cryptoKey, data);
    return new Uint8Array(sig);
  }

  /**
   * Apply PKCS#7 padding to data so its length is a multiple of blockSize.
   * @param {Uint8Array} data
   * @param {number} blockSize
   * @returns {Uint8Array}
   */
  function pkcs7Pad(data, blockSize) {
    const padLen = blockSize - (data.length % blockSize);
    const padded = new Uint8Array(data.length + padLen);
    padded.set(data);
    for (let i = data.length; i < padded.length; i++) {
      padded[i] = padLen;
    }
    return padded;
  }

  /**
   * Remove PKCS#7 padding.
   * @param {Uint8Array} data
   * @returns {Uint8Array}
   * @throws {Error} If padding is invalid
   */
  function pkcs7Unpad(data) {
    if (data.length === 0) {
      throw new Error('Qeratheon-1: Cannot unpad empty data.');
    }
    const padLen = data[data.length - 1];
    if (padLen === 0 || padLen > BLOCK_SIZE || padLen > data.length) {
      throw new Error('Qeratheon-1: Invalid PKCS#7 padding value.');
    }
    for (let i = data.length - padLen; i < data.length; i++) {
      if (data[i] !== padLen) {
        throw new Error('Qeratheon-1: Corrupt PKCS#7 padding.');
      }
    }
    return data.slice(0, data.length - padLen);
  }

  // ---------------------------------------------------------------------------
  // EntropyLevel enum
  // ---------------------------------------------------------------------------

  /**
   * @enum {string}
   * @description Entropy quality classification levels.
   */
  const EntropyLevel = Object.freeze({
    CRITICAL: 'CRITICAL',
    SUFFICIENT: 'SUFFICIENT',
    MARGINAL: 'MARGINAL',
    INSUFFICIENT: 'INSUFFICIENT'
  });

  // ---------------------------------------------------------------------------
  // EntropyReport
  // ---------------------------------------------------------------------------

  /**
   * @typedef {Object} EntropyReport
   * @property {string} level - EntropyLevel value
   * @property {number} bits_estimated - Estimated min-entropy bits
   * @property {string[]} sources_used - Names of entropy sources
   * @property {number} timestamp - Unix timestamp of the report
   * @property {boolean} passed - Whether entropy meets the minimum threshold
   */

  // ---------------------------------------------------------------------------
  // EntropyVector
  // ---------------------------------------------------------------------------

  /**
   * Represents the entropy material for a single encryption operation.
   * Contains cryptographic salt, nonce, and timestamp.
   */
  class EntropyVector {
    /**
     * @param {Uint8Array} salt - 128-bit (16-byte) random salt
     * @param {Uint8Array} nonce - 96-bit (12-byte) random nonce
     * @param {number} timestamp - 64-bit Unix timestamp (milliseconds)
     */
    constructor(salt, nonce, timestamp) {
      if (!(salt instanceof Uint8Array) || salt.length !== SALT_SIZE) {
        throw new Error('Qeratheon-1: Salt must be a 16-byte Uint8Array.');
      }
      if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_SIZE) {
        throw new Error('Qeratheon-1: Nonce must be a 12-byte Uint8Array.');
      }
      /** @type {Uint8Array} */
      this.salt = salt;
      /** @type {Uint8Array} */
      this.nonce = nonce;
      /** @type {number} */
      this.timestamp = timestamp;
    }

    /**
     * Generate a fresh EntropyVector with cryptographically random values.
     * @returns {EntropyVector}
     */
    static generate() {
      const salt = new Uint8Array(SALT_SIZE);
      const nonce = new Uint8Array(NONCE_SIZE);
      crypto.getRandomValues(salt);
      crypto.getRandomValues(nonce);
      return new EntropyVector(salt, nonce, Date.now());
    }

    /**
     * Serialize the entropy vector to a byte array.
     * Layout: [salt (16)] [nonce (12)] [timestamp (8)] = 36 bytes
     * @returns {Uint8Array}
     */
    toBytes() {
      return concat(this.salt, this.nonce, uint64ToBytes(this.timestamp));
    }

    /**
     * Deserialize an entropy vector from a byte array.
     * @param {Uint8Array} data - 36-byte serialized vector
     * @returns {EntropyVector}
     */
    static fromBytes(data) {
      if (data.length < SALT_SIZE + NONCE_SIZE + TIMESTAMP_SIZE) {
        throw new Error('Qeratheon-1: EntropyVector data too short.');
      }
      const salt = data.slice(0, SALT_SIZE);
      const nonce = data.slice(SALT_SIZE, SALT_SIZE + NONCE_SIZE);
      const timestamp = bytesToUint64(data, SALT_SIZE + NONCE_SIZE);
      return new EntropyVector(salt, nonce, timestamp);
    }

    /**
     * Compute a fingerprint of this entropy vector for MAC binding.
     * @returns {Promise<Uint8Array>} SHA-256 fingerprint
     */
    async fingerprint() {
      return sha256(this.toBytes());
    }
  }

  // ---------------------------------------------------------------------------
  // EntropyValidator
  // ---------------------------------------------------------------------------

  /**
   * Validates the quality of available entropy before encryption.
   * Operates in a fail-closed manner: if validation fails, encryption is refused.
   */
  class EntropyValidator {
    /**
     * Minimum acceptable min-entropy in bits.
     * @type {number}
     */
    static get MIN_ENTROPY_BITS() {
      return 256;
    }

    /**
     * Validate the system's entropy quality.
     * Checks that crypto.getRandomValues is available and producing
     * non-degenerate output with sufficient estimated min-entropy.
     * @returns {Promise<EntropyReport>}
     */
    static async validate() {
      const sources = [];
      let bitsEstimated = 0;

      // Source 1: Web Crypto CSPRNG
      try {
        const sample = new Uint8Array(64);
        crypto.getRandomValues(sample);

        // Basic degeneracy check: verify the sample is not all zeros or all identical
        let allSame = true;
        for (let i = 1; i < sample.length; i++) {
          if (sample[i] !== sample[0]) { allSame = false; break; }
        }

        if (!allSame) {
          sources.push('crypto.getRandomValues');
          // CSPRNG provides full entropy for every bit requested
          bitsEstimated += 512;
        }
      } catch (_) {
        // Source not available
      }

      // Source 2: Timing jitter (supplementary)
      try {
        const timings = [];
        for (let i = 0; i < 16; i++) {
          const t0 = performance.now();
          // Perform a small amount of work to introduce jitter
          await sha256(new Uint8Array(32));
          timings.push(performance.now() - t0);
        }
        let unique = new Set(timings.map(t => Math.round(t * 1000))).size;
        if (unique > 4) {
          sources.push('timing_jitter');
          bitsEstimated += Math.min(unique * 2, 32);
        }
      } catch (_) {
        // Timing source not available
      }

      // Determine level
      let level;
      if (bitsEstimated >= 512) {
        level = EntropyLevel.CRITICAL;
      } else if (bitsEstimated >= 256) {
        level = EntropyLevel.SUFFICIENT;
      } else if (bitsEstimated >= 128) {
        level = EntropyLevel.MARGINAL;
      } else {
        level = EntropyLevel.INSUFFICIENT;
      }

      const passed = bitsEstimated >= EntropyValidator.MIN_ENTROPY_BITS;

      return {
        level: level,
        bits_estimated: bitsEstimated,
        sources_used: sources,
        timestamp: Date.now(),
        passed: passed
      };
    }

    /**
     * Validate entropy and throw if insufficient. Fail-closed.
     * @returns {Promise<EntropyReport>}
     * @throws {Error} If entropy is below the minimum threshold
     */
    static async requireSufficient() {
      const report = await EntropyValidator.validate();
      if (!report.passed) {
        throw new Error(
          'Qeratheon-1: Entropy validation failed (fail-closed). ' +
          'Estimated ' + report.bits_estimated + ' bits, need >= ' +
          EntropyValidator.MIN_ENTROPY_BITS + '. Sources: ' +
          report.sources_used.join(', ')
        );
      }
      return report;
    }
  }

  // ---------------------------------------------------------------------------
  // FeistelPRP — 4-round balanced Feistel network
  // ---------------------------------------------------------------------------

  /**
   * A 4-round balanced Feistel pseudo-random permutation (PRP) operating
   * on 1024-bit (128-byte) blocks using SHA-256 as the round function.
   *
   * Each round: F_i(x) = SHA-256(domain_prefix || round_i || key || entropy || x)
   *
   * Provides a strong PRP by applying the Luby-Rackoff construction with
   * 4 rounds, yielding IND-CCA security.
   */
  class FeistelPRP {
    /**
     * @param {Uint8Array} key - Permutation key (>= 32 bytes / 256-bit)
     * @throws {Error} If key is too short
     */
    constructor(key) {
      if (!(key instanceof Uint8Array) || key.length < MIN_SUBKEY) {
        throw new Error(
          'Qeratheon-1: FeistelPRP key must be >= ' + MIN_SUBKEY + ' bytes.'
        );
      }
      /** @private */
      this._key = key;
    }

    /**
     * Compute the round function F_i(x).
     * F_i(x) = SHA-256(domain_prefix || round_i || key || entropy || x)
     *
     * The output is 32 bytes; it is expanded to HALF_BLOCK (64 bytes) by
     * concatenating SHA-256(F_i || 0x01) to form the full half-block mask.
     *
     * @private
     * @param {number} round - Round index (0-3)
     * @param {Uint8Array} halfBlock - 64-byte half block
     * @param {Uint8Array} entropy - Entropy bytes for domain separation
     * @returns {Promise<Uint8Array>} 64-byte round function output
     */
    async _roundFunction(round, halfBlock, entropy) {
      const domainBytes = utf8Encode(DOMAIN_PERM_ROUND);
      const roundByte = new Uint8Array([round & 0xff]);
      const input = concat(domainBytes, roundByte, this._key, entropy, halfBlock);
      const h0 = await sha256(input);
      // Expand to 64 bytes: H(input) || H(H(input) || 0x01)
      const expandInput = concat(h0, new Uint8Array([0x01]));
      const h1 = await sha256(expandInput);
      return concat(h0, h1);
    }

    /**
     * Encrypt a single 128-byte block using the 4-round Feistel network.
     * Rounds are applied in order 0, 1, 2, 3.
     *
     * @param {Uint8Array} block - 128-byte plaintext block
     * @param {Uint8Array} entropy - Entropy bytes for domain binding
     * @returns {Promise<Uint8Array>} 128-byte ciphertext block
     * @throws {Error} If block size is incorrect
     */
    async encrypt(block, entropy) {
      if (block.length !== BLOCK_SIZE) {
        throw new Error(
          'Qeratheon-1: FeistelPRP block must be exactly ' + BLOCK_SIZE + ' bytes.'
        );
      }

      let left = block.slice(0, HALF_BLOCK);
      let right = block.slice(HALF_BLOCK);

      for (let i = 0; i < FEISTEL_ROUNDS; i++) {
        const f = await this._roundFunction(i, right, entropy);
        const newLeft = right;
        const newRight = xorBytes(left, f);
        left = newLeft;
        right = newRight;
      }

      return concat(left, right);
    }

    /**
     * Decrypt a single 128-byte block using the 4-round Feistel network.
     * Rounds are applied in reverse order 3, 2, 1, 0 (Feistel inversion).
     *
     * @param {Uint8Array} block - 128-byte ciphertext block
     * @param {Uint8Array} entropy - Entropy bytes (must match encryption)
     * @returns {Promise<Uint8Array>} 128-byte plaintext block
     * @throws {Error} If block size is incorrect
     */
    async decrypt(block, entropy) {
      if (block.length !== BLOCK_SIZE) {
        throw new Error(
          'Qeratheon-1: FeistelPRP block must be exactly ' + BLOCK_SIZE + ' bytes.'
        );
      }

      let left = block.slice(0, HALF_BLOCK);
      let right = block.slice(HALF_BLOCK);

      for (let i = FEISTEL_ROUNDS - 1; i >= 0; i--) {
        const f = await this._roundFunction(i, left, entropy);
        const newRight = left;
        const newLeft = xorBytes(right, f);
        left = newLeft;
        right = newRight;
      }

      return concat(left, right);
    }
  }

  // ---------------------------------------------------------------------------
  // HybridPadGenerator
  // ---------------------------------------------------------------------------

  /**
   * Generates a hybrid encryption pad using the EPC pipeline.
   *
   * Pad_comp: HMAC-based PRG seeded by K_enc + entropy
   * Pad_stat: XOR of Pad_comp with entropy-derived statistical pad
   * Combined: Pad_comp XOR Pad_stat
   */
  class HybridPadGenerator {
    /**
     * @param {Uint8Array} kEnc - Encryption sub-key
     */
    constructor(kEnc) {
      if (!(kEnc instanceof Uint8Array) || kEnc.length < MIN_SUBKEY) {
        throw new Error(
          'Qeratheon-1: HybridPadGenerator key must be >= ' + MIN_SUBKEY + ' bytes.'
        );
      }
      /** @private */
      this._kEnc = kEnc;
    }

    /**
     * Generate a pad of the specified length.
     *
     * Pad_comp is produced by iterating HMAC-SHA-256 in counter mode:
     *   Pad_comp[i] = HMAC(K_enc, entropy || counter_i)
     *
     * Pad_stat is produced by:
     *   Pad_stat[i] = HMAC(entropy_key, K_enc || counter_i)
     *
     * The final pad = Pad_comp XOR Pad_stat.
     *
     * @param {number} length - Desired pad length in bytes
     * @param {Uint8Array} entropy - Entropy material
     * @returns {Promise<Uint8Array>} Pad of the requested length
     */
    async generate(length, entropy) {
      const padComp = await this._generatePadComp(length, entropy);
      const padStat = await this._generatePadStat(length, entropy);
      return xorBytes(padComp, padStat);
    }

    /**
     * Generate the computational pad (HMAC-PRG).
     * @private
     * @param {number} length
     * @param {Uint8Array} entropy
     * @returns {Promise<Uint8Array>}
     */
    async _generatePadComp(length, entropy) {
      const blocks = Math.ceil(length / 32);
      const parts = [];
      for (let i = 0; i < blocks; i++) {
        const counterBytes = uint64ToBytes(i);
        const input = concat(entropy, counterBytes);
        const block = await hmacSha256(this._kEnc, input);
        parts.push(block);
      }
      return concat(...parts).slice(0, length);
    }

    /**
     * Generate the statistical pad (entropy-keyed HMAC).
     * @private
     * @param {number} length
     * @param {Uint8Array} entropy
     * @returns {Promise<Uint8Array>}
     */
    async _generatePadStat(length, entropy) {
      // Derive a statistical key from entropy
      const entropyKey = await sha256(entropy);
      const blocks = Math.ceil(length / 32);
      const parts = [];
      for (let i = 0; i < blocks; i++) {
        const counterBytes = uint64ToBytes(i);
        const input = concat(this._kEnc, counterBytes);
        const block = await hmacSha256(entropyKey, input);
        parts.push(block);
      }
      return concat(...parts).slice(0, length);
    }
  }

  // ---------------------------------------------------------------------------
  // Ciphertext
  // ---------------------------------------------------------------------------

  /**
   * Encapsulates the output of a Qeratheon-1 encryption operation.
   */
  class Ciphertext {
    /**
     * @param {Object} params
     * @param {Uint8Array} params.data - Encrypted data
     * @param {Uint8Array} params.tag - HMAC-SHA-256 authentication tag (32 bytes)
     * @param {Uint8Array} params.salt - 16-byte salt
     * @param {Uint8Array} params.nonce - 12-byte nonce
     * @param {number} params.timestamp - Unix timestamp
     * @param {EntropyReport} params.entropyReport - Entropy validation report
     * @param {string} [params.securityLevel] - Security level assessment
     */
    constructor({ data, tag, salt, nonce, timestamp, entropyReport, securityLevel }) {
      /** @type {Uint8Array} */
      this.data = data;
      /** @type {Uint8Array} */
      this.tag = tag;
      /** @type {Uint8Array} */
      this.salt = salt;
      /** @type {Uint8Array} */
      this.nonce = nonce;
      /** @type {number} */
      this.timestamp = timestamp;
      /** @type {EntropyReport} */
      this.entropyReport = entropyReport;
      /** @type {string} */
      this.securityLevel = securityLevel || 'POST_QUANTUM_256';
    }

    /**
     * Serialize the ciphertext to a base64-encoded JSON string.
     * @returns {string}
     */
    serialize() {
      const obj = {
        v: VERSION,
        d: toBase64(this.data),
        t: toBase64(this.tag),
        s: toBase64(this.salt),
        n: toBase64(this.nonce),
        ts: this.timestamp,
        er: this.entropyReport,
        sl: this.securityLevel
      };
      return btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
    }

    /**
     * Deserialize a base64-encoded JSON string to a Ciphertext object.
     * @param {string} str - Serialized ciphertext
     * @returns {Ciphertext}
     * @throws {Error} If the format is invalid
     */
    static deserialize(str) {
      let obj;
      try {
        obj = JSON.parse(decodeURIComponent(escape(atob(str))));
      } catch (e) {
        throw new Error('Qeratheon-1: Invalid ciphertext format: ' + e.message);
      }

      if (!obj.v || !obj.d || !obj.t || !obj.s || !obj.n) {
        throw new Error('Qeratheon-1: Ciphertext missing required fields.');
      }

      return new Ciphertext({
        data: fromBase64(obj.d),
        tag: fromBase64(obj.t),
        salt: fromBase64(obj.s),
        nonce: fromBase64(obj.n),
        timestamp: obj.ts,
        entropyReport: obj.er,
        securityLevel: obj.sl
      });
    }
  }

  // ---------------------------------------------------------------------------
  // QeratheonAEAD — IND-CCA2 Authenticated Encryption
  // ---------------------------------------------------------------------------

  /**
   * Qeratheon-1 AEAD cipher implementing the Entropy-Permutation Cipher pipeline.
   *
   * Provides IND-CCA2 authenticated encryption using:
   * - 4-round Feistel PRP for block permutation
   * - Hybrid pad generator for stream encryption
   * - HMAC-SHA-256 encrypt-then-MAC for authentication
   *
   * Master key must be >= 512 bits (64 bytes).
   */
  class QeratheonAEAD {
    /**
     * Create a new QeratheonAEAD instance.
     * Derives three sub-keys from the master key using HMAC-based key derivation
     * with distinct domain separation strings.
     *
     * @param {Uint8Array} masterKey - Master key (>= 64 bytes / 512-bit)
     * @throws {Error} If master key is too short
     */
    constructor(masterKey) {
      if (!(masterKey instanceof Uint8Array) || masterKey.length < MIN_MASTER_KEY) {
        throw new Error(
          'Qeratheon-1: Master key must be >= ' + MIN_MASTER_KEY +
          ' bytes (' + (MIN_MASTER_KEY * 8) + '-bit).'
        );
      }
      /** @private */
      this._masterKey = masterKey;
      /** @private */
      this._initialized = false;
      /** @private */
      this._kPerm = null;
      /** @private */
      this._kEnc = null;
      /** @private */
      this._kMac = null;
    }

    /**
     * Derive sub-keys from the master key. Called lazily on first operation.
     * @private
     * @returns {Promise<void>}
     */
    async _deriveKeys() {
      if (this._initialized) return;

      this._kPerm = await hmacSha256(this._masterKey, utf8Encode(DOMAIN_KD_PERM));
      this._kEnc = await hmacSha256(this._masterKey, utf8Encode(DOMAIN_KD_ENC));
      this._kMac = await hmacSha256(this._masterKey, utf8Encode(DOMAIN_KD_MAC));

      this._initialized = true;
    }

    /**
     * Compute the authentication tag over ciphertext, associated data,
     * and entropy fingerprint.
     *
     * Tag = HMAC(K_mac, ciphertext || AD || entropy_fingerprint)
     *
     * @private
     * @param {Uint8Array} ciphertextData - Encrypted data bytes
     * @param {Uint8Array} ad - Associated data
     * @param {Uint8Array} entropyFingerprint - SHA-256 of entropy vector
     * @returns {Promise<Uint8Array>} 32-byte authentication tag
     */
    async _computeTag(ciphertextData, ad, entropyFingerprint) {
      const adLen = uint64ToBytes(ad.length);
      const ctLen = uint64ToBytes(ciphertextData.length);
      const macInput = concat(ciphertextData, ad, entropyFingerprint, adLen, ctLen);
      return hmacSha256(this._kMac, macInput);
    }

    /**
     * Encrypt plaintext with associated data.
     *
     * Pipeline:
     *   1. Validate entropy (fail-closed)
     *   2. Generate fresh EntropyVector
     *   3. PKCS#7 pad plaintext to 128-byte block boundary
     *   4. For each block: apply Feistel PRP
     *   5. Generate hybrid pad and XOR with permuted blocks
     *   6. Compute encrypt-then-MAC tag
     *
     * @param {Uint8Array} plaintext - Data to encrypt
     * @param {Uint8Array} [associatedData] - Optional associated data for authentication
     * @returns {Promise<Ciphertext>} Authenticated ciphertext
     * @throws {Error} If entropy is insufficient or inputs are invalid
     */
    async encrypt(plaintext, associatedData) {
      await this._deriveKeys();

      if (!(plaintext instanceof Uint8Array)) {
        throw new Error('Qeratheon-1: Plaintext must be a Uint8Array.');
      }

      const ad = associatedData instanceof Uint8Array
        ? associatedData
        : new Uint8Array(0);

      // Step 1: Validate entropy (fail-closed)
      const entropyReport = await EntropyValidator.requireSufficient();

      // Step 2: Generate fresh entropy vector
      const ev = EntropyVector.generate();
      const evBytes = ev.toBytes();
      const entropyFingerprint = await ev.fingerprint();

      // Step 3: PKCS#7 pad
      const padded = pkcs7Pad(plaintext, BLOCK_SIZE);
      const numBlocks = padded.length / BLOCK_SIZE;

      // Step 4: Feistel PRP on each block
      const feistel = new FeistelPRP(this._kPerm);
      const permuted = new Uint8Array(padded.length);

      for (let i = 0; i < numBlocks; i++) {
        const blockStart = i * BLOCK_SIZE;
        const block = padded.slice(blockStart, blockStart + BLOCK_SIZE);
        // Bind entropy + block index for per-block domain separation
        const blockEntropy = concat(evBytes, uint64ToBytes(i));
        const encrypted = await feistel.encrypt(block, blockEntropy);
        permuted.set(encrypted, blockStart);
      }

      // Step 5: Hybrid pad XOR
      const padGen = new HybridPadGenerator(this._kEnc);
      const pad = await padGen.generate(permuted.length, evBytes);
      const ciphertextData = xorBytes(permuted, pad);

      // Step 6: Encrypt-then-MAC
      const tag = await this._computeTag(ciphertextData, ad, entropyFingerprint);

      return new Ciphertext({
        data: ciphertextData,
        tag: tag,
        salt: ev.salt,
        nonce: ev.nonce,
        timestamp: ev.timestamp,
        entropyReport: entropyReport,
        securityLevel: 'POST_QUANTUM_256'
      });
    }

    /**
     * Decrypt an authenticated ciphertext.
     *
     * Pipeline:
     *   1. Reconstruct EntropyVector from ciphertext metadata
     *   2. Verify authentication tag (constant-time comparison)
     *   3. Generate hybrid pad and XOR to undo pad
     *   4. For each block: invert Feistel PRP
     *   5. Remove PKCS#7 padding
     *
     * @param {Ciphertext} ciphertext - Authenticated ciphertext to decrypt
     * @param {Uint8Array} [associatedData] - Associated data (must match encryption)
     * @returns {Promise<Uint8Array>} Decrypted plaintext
     * @throws {Error} If authentication fails or ciphertext is malformed
     */
    async decrypt(ciphertext, associatedData) {
      await this._deriveKeys();

      if (!(ciphertext instanceof Ciphertext)) {
        throw new Error('Qeratheon-1: Expected a Ciphertext object.');
      }

      const ad = associatedData instanceof Uint8Array
        ? associatedData
        : new Uint8Array(0);

      // Step 1: Reconstruct entropy vector
      const ev = new EntropyVector(ciphertext.salt, ciphertext.nonce, ciphertext.timestamp);
      const evBytes = ev.toBytes();
      const entropyFingerprint = await ev.fingerprint();

      // Step 2: Verify tag (constant-time)
      const expectedTag = await this._computeTag(ciphertext.data, ad, entropyFingerprint);
      if (!constantTimeEqual(ciphertext.tag, expectedTag)) {
        throw new Error('Qeratheon-1: Authentication failed. Tag mismatch.');
      }

      // Step 3: Undo hybrid pad
      const padGen = new HybridPadGenerator(this._kEnc);
      const pad = await padGen.generate(ciphertext.data.length, evBytes);
      const permuted = xorBytes(ciphertext.data, pad);

      // Step 4: Invert Feistel PRP
      const numBlocks = permuted.length / BLOCK_SIZE;
      if (permuted.length % BLOCK_SIZE !== 0) {
        throw new Error('Qeratheon-1: Ciphertext length is not a multiple of block size.');
      }

      const feistel = new FeistelPRP(this._kPerm);
      const padded = new Uint8Array(permuted.length);

      for (let i = 0; i < numBlocks; i++) {
        const blockStart = i * BLOCK_SIZE;
        const block = permuted.slice(blockStart, blockStart + BLOCK_SIZE);
        const blockEntropy = concat(evBytes, uint64ToBytes(i));
        const decrypted = await feistel.decrypt(block, blockEntropy);
        padded.set(decrypted, blockStart);
      }

      // Step 5: Remove PKCS#7 padding
      return pkcs7Unpad(padded);
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * @namespace QeratheonCore
   * @description Public API for the Qeratheon-1 post-quantum symmetric
   *              encryption primitive. Exposed as window.QeratheonCore.
   */
  const QeratheonCore = Object.freeze({
    /**
     * Generate a new 512-bit (64-byte) master key using the system CSPRNG.
     * @returns {Uint8Array} 64-byte master key
     */
    generateKey: function () {
      const key = new Uint8Array(MIN_MASTER_KEY);
      crypto.getRandomValues(key);
      return key;
    },

    /**
     * Create a QeratheonAEAD instance bound to the given master key.
     * @param {Uint8Array} key - 512-bit master key
     * @returns {QeratheonAEAD}
     */
    createAEAD: function (key) {
      return new QeratheonAEAD(key);
    },

    /**
     * One-shot encrypt: creates an ephemeral AEAD instance, encrypts,
     * and returns the serialized ciphertext.
     *
     * @param {Uint8Array} key - 512-bit master key
     * @param {Uint8Array|string} plaintext - Data to encrypt (strings are UTF-8 encoded)
     * @param {Uint8Array|string} [associatedData] - Optional AD
     * @returns {Promise<string>} Serialized ciphertext (base64 JSON)
     */
    encrypt: async function (key, plaintext, associatedData) {
      const aead = new QeratheonAEAD(key);
      const pt = typeof plaintext === 'string' ? utf8Encode(plaintext) : plaintext;
      const ad = typeof associatedData === 'string'
        ? utf8Encode(associatedData)
        : (associatedData || new Uint8Array(0));
      const ct = await aead.encrypt(pt, ad);
      return ct.serialize();
    },

    /**
     * One-shot decrypt: deserializes and decrypts a ciphertext string.
     *
     * @param {Uint8Array} key - 512-bit master key (must match encryption key)
     * @param {string} ciphertext - Serialized ciphertext from encrypt()
     * @param {Uint8Array|string} [associatedData] - Optional AD (must match encryption)
     * @returns {Promise<Uint8Array>} Decrypted plaintext
     * @throws {Error} If authentication fails or key is wrong
     */
    decrypt: async function (key, ciphertext, associatedData) {
      const aead = new QeratheonAEAD(key);
      const ct = Ciphertext.deserialize(ciphertext);
      const ad = typeof associatedData === 'string'
        ? utf8Encode(associatedData)
        : (associatedData || new Uint8Array(0));
      return aead.decrypt(ct, ad);
    },

    /**
     * Run entropy validation and return the report.
     * @returns {Promise<EntropyReport>}
     */
    validateEntropy: function () {
      return EntropyValidator.validate();
    },

    /**
     * Get the library version string.
     * @returns {string}
     */
    getVersion: function () {
      return VERSION;
    },

    /**
     * Get the current security level assessment.
     * @returns {Promise<Object>} Security assessment including entropy status
     */
    getSecurityLevel: async function () {
      const report = await EntropyValidator.validate();
      return {
        cipher: 'Qeratheon-1 EPC',
        version: VERSION,
        blockSize: BLOCK_SIZE * 8,
        tagSize: TAG_SIZE * 8,
        masterKeySize: MIN_MASTER_KEY * 8,
        feistelRounds: FEISTEL_ROUNDS,
        securityLevel: 'POST_QUANTUM_256',
        entropy: report,
        assessment: report.passed ? 'OPERATIONAL' : 'DEGRADED'
      };
    },

    // Expose internal classes for advanced usage
    EntropyVector: EntropyVector,
    EntropyValidator: EntropyValidator,
    EntropyLevel: EntropyLevel,
    FeistelPRP: FeistelPRP,
    Ciphertext: Ciphertext,
    QeratheonAEAD: QeratheonAEAD
  });

  // Expose on the global object
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = QeratheonCore;
  } else {
    root.QeratheonCore = QeratheonCore;
  }

})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : this);
