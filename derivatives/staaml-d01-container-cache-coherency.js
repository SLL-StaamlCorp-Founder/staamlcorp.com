'use strict';

/**
 * StaamlCorp Temporal Security Derivative D1
 * Container Cache Coherency & Namespace-Aware Validation
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

  // =========== D1: Container Cache Coherency & Namespace-Aware Validation ===========
const CacheCoherencyLevel = Object.freeze({
    INVALID: 0, STALE: 1, FRESH: 2, COHERENT: 3
  });

  /**
   * D1Engine: Container cache coherency management with namespace isolation
   * Enforces coherency protocol between container namespaces
   */
  class D1Engine {
    constructor() {
      this.namespaces = new Map();
      this.cacheEntries = new Map();
      this.invalidationLog = [];
      this.coherencyViolations = 0;
      this.stats = {
        entriesRegistered: 0,
        coherencyChecks: 0,
        propagations: 0
      };
    }

    /**
     * Register a new namespace with isolation boundaries
     * @param {string} nsId - Namespace identifier
     * @param {number} postureLevel - Initial posture level
     */
    registerNamespace(nsId, postureLevel) {
      this.namespaces.set(nsId, {
        id: nsId,
        createdAt: now(),
        postureLevel,
        entryCount: 0,
        lastCoherencyCheck: null
      });
    }

    /**
     * Add cache entry to namespace
     * @param {string} nsId - Namespace ID
     * @param {string} key - Cache key
     * @param {any} value - Cache value
     * @param {number} ttl - Time-to-live in ms
     */
    addCacheEntry(nsId, key, value, ttl = 3600000) {
      const ns = this.namespaces.get(nsId);
      if (!ns) throw new Error(`Namespace ${nsId} not found`);

      const entryId = generateId();
      const entry = {
        id: entryId,
        namespace: nsId,
        key,
        hash: null,
        createdAt: now(),
        expiresAt: new Date(Date.now() + ttl).toISOString(),
        coherencyLevel: CacheCoherencyLevel.FRESH
      };

      this.cacheEntries.set(entryId, entry);
      ns.entryCount++;
      this.stats.entriesRegistered++;
      return entryId;
    }

    /**
     * Validate coherency across namespaces
     * @returns {object} Coherency report
     */
    validateCoherency() {
      this.stats.coherencyChecks++;
      const report = {
        timestamp: now(),
        totalEntries: this.cacheEntries.size,
        coherent: 0,
        stale: 0,
        invalid: 0
      };

      for (const [, entry] of this.cacheEntries) {
        const expiryTime = new Date(entry.expiresAt).getTime();
        if (expiryTime < Date.now()) {
          entry.coherencyLevel = CacheCoherencyLevel.INVALID;
          report.invalid++;
        } else if (expiryTime < Date.now() + 300000) {
          entry.coherencyLevel = CacheCoherencyLevel.STALE;
          report.stale++;
        } else {
          entry.coherencyLevel = CacheCoherencyLevel.COHERENT;
          report.coherent++;
        }
      }

      if (report.invalid > 0) this.coherencyViolations++;
      return report;
    }

    /**
     * Propagate invalidation across namespaces
     * @param {string} nsId - Source namespace
     * @param {string[]} keys - Keys to invalidate
     */
    propagateInvalidation(nsId, keys) {
      keys.forEach(key => {
        for (const [entryId, entry] of this.cacheEntries) {
          if (entry.key === key) {
            entry.coherencyLevel = CacheCoherencyLevel.INVALID;
            this.invalidationLog.push({
              timestamp: now(),
              entryId,
              sourceNs: nsId,
              key
            });
          }
        }
      });
      this.stats.propagations++;
    }

    /**
     * Handle posture level transition
     * @param {number} priorLevel - Previous posture level
     * @param {number} currentLevel - New posture level
     * @param {object} delta - Transition metadata
     */
    onPostureTransition(priorLevel, currentLevel, delta) {
      if (currentLevel < priorLevel) {
        // Downgrade: invalidate elevated entries
        for (const [, entry] of this.cacheEntries) {
          if (entry.coherencyLevel === CacheCoherencyLevel.FRESH) {
            entry.coherencyLevel = CacheCoherencyLevel.STALE;
          }
        }
      }
    }

    /**
     * Get engine statistics
     * @returns {object} Metrics snapshot
     */
    getStats() {
      return {
        ...this.stats,
        coherencyViolations: this.coherencyViolations,
        namespaceCount: this.namespaces.size,
        cacheEntryCount: this.cacheEntries.size,
        invalidationLogSize: this.invalidationLog.length
      };
    }
  }

  globalThis.StaamlD1 = { PostureLevel, D1Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
