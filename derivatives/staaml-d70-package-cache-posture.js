'use strict';

/**
 * StaamlCorp Temporal Security Derivative D70
 * Package Manager Cache Posture Gate
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

  // =========== D70: Package Manager Cache Posture Gate ===========
/**
   * D70Engine: npm/pip/cargo/Maven caches validated and gated
   */
  class D70Engine {
    constructor() {
      this.caches = new Map();
      this.packages = new Map();
      this.blacklist = new Set();
      this.stats = {
        cachesRegistered: 0,
        packagesValidated: 0,
        blockedPackages: 0,
        blacklistHits: 0
      };
    }

    /**
     * Register a package manager cache
     */
    registerCache(cacheId, manager = 'npm', location = '') {
      this.caches.set(cacheId, {
        id: cacheId,
        manager,
        location,
        registered: now(),
        active: true
      });
      this.stats.cachesRegistered++;
      return cacheId;
    }

    /**
     * Validate a package against blacklist and posture
     */
    validatePackage(cacheId, packageName, version, currentPostureLevel) {
      this.stats.packagesValidated++;
      const cache = this.caches.get(cacheId);
      if (!cache) return null;

      const blacklistKey = `${packageName}@${version}`;
      const isBlacklisted = this.blacklist.has(blacklistKey);

      const minPosture = isBlacklisted ? PostureLevel.CRITICAL : PostureLevel.TRUSTED;
      const valid = !isBlacklisted && currentPostureLevel >= minPosture;

      if (isBlacklisted) this.stats.blacklistHits++;
      if (!valid) this.stats.blockedPackages++;

      const validation = {
        cacheId,
        packageName,
        version,
        valid,
        blacklisted: isBlacklisted,
        validated: now()
      };

      this.packages.set(blacklistKey, validation);
      return validation;
    }

    /**
     * Block a blacklisted package
     */
    blockBlacklisted(packageName, version, reason = '') {
      const key = `${packageName}@${version}`;
      this.blacklist.add(key);

      const blocked = {
        key,
        packageName,
        version,
        reason,
        blockedAt: now()
      };

      return blocked;
    }

    /**
     * Get package manager statistics
     */
    getPackageStats() {
      return {
        ...this.stats,
        registeredCaches: this.caches.size,
        blacklistedCount: this.blacklist.size,
        cachedValidations: this.packages.size
      };
    }

    /**
     * Handle posture transitions
     */
    onPostureTransition(priorLevel, currentLevel, delta) {
      const revalidations = [];

      if (currentLevel < priorLevel) {
        this.packages.forEach((validation, key) => {
          if (validation.valid && currentLevel < PostureLevel.TRUSTED) {
            revalidations.push(key);
          }
        });
      }

      return { revalidatedPackages: revalidations.length };
    }

    /**
     * Get comprehensive statistics
     */
    getStats() {
      return this.getPackageStats();
    }
  }

  globalThis.StaamlD70 = { PostureLevel, D70Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
