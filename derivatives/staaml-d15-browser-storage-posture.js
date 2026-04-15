'use strict';

/**
 * StaamlCorp Temporal Security Derivative D15
 * Browser Storage Posture Controller
 *
 * U.S. Patent Application No. 19/640,793
 * (c) 2024-2026 StaamlCorp. All rights reserved.
 *
 * @version 1.0.0
 * @license Proprietary - StaamlCorp
 */
(function (globalThis) {

  const PostureLevel = Object.freeze({
    UNTRUSTED: 0, RESTRICTED: 1, STANDARD: 2,
    ELEVATED: 3, PRIVILEGED: 4, CRITICAL: 5
  });

  function generateId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    return [hex.slice(0,8), hex.slice(8,12), hex.slice(12,16), hex.slice(16,20), hex.slice(20)].join('-');
  }

  function now() { return new Date().toISOString(); }

  async function sha256(data) {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
    return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
  }

class D15Engine {
    constructor() {
      this.storageRecords = new Map();
      this.stats = { written: 0, validated: 0, purged: 0 };
      this.postureLevel = PostureLevel.PROVISIONAL;
      this.policyEpoch = 0;
    }

    /**
     * Write to storage with posture binding
     * @param {string} key
     * @param {*} value
     * @param {number} postureRequired
     * @returns {boolean}
     */
    setWithPosture(key, value, postureRequired) {
      const record = {
        key,
        value,
        postureRequired,
        epoch: this.policyEpoch,
        storedAt: now()
      };
      this.storageRecords.set(key, record);
      this.stats.written++;
      return true;
    }

    /**
     * Retrieve from storage with validation
     * @param {string} key
     * @returns {*}
     */
    getWithValidation(key) {
      const record = this.storageRecords.get(key);
      if (!record) return null;

      const meetsPosture = this.postureLevel >= record.postureRequired;
      const sameEpoch = record.epoch === this.policyEpoch;

      if (meetsPosture && sameEpoch) {
        this.stats.validated++;
        return record.value;
      }
      return null;
    }

    /**
     * Purge expired entries from storage
     * @returns {number} Count of purged entries
     */
    purgeExpired() {
      let count = 0;
      for (const [key, record] of this.storageRecords) {
        const isExpired = record.epoch < this.policyEpoch ||
                          this.postureLevel < record.postureRequired;
        if (isExpired) {
          this.storageRecords.delete(key);
          count++;
          this.stats.purged++;
        }
      }
      return count;
    }

    /**
     * Get storage statistics
     * @returns {Object}
     */
    getStorageStats() {
      return {
        totalRecords: this.storageRecords.size,
        policyEpoch: this.policyEpoch,
        ...this.stats
      };
    }

    /**
     * Handle posture transition
     * @param {number} priorLevel
     * @param {number} currentLevel
     * @param {number} delta
     */
    onPostureTransition(priorLevel, currentLevel, delta) {
      this.postureLevel = currentLevel;
      if (delta < 0) {
        this.policyEpoch++;
        this.purgeExpired();
      }
    }
  }

  globalThis.StaamlD15 = { PostureLevel, D15Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
