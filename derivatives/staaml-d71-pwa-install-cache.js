'use strict';

/**
 * StaamlCorp Temporal Security Derivative D71
 * PWA Installation Cache Posture Controller
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

// =========== D71: PWA Installation Cache Posture Controller ===========

  /**
   * D71Engine: PWA manifests/service workers/push subscriptions validated
   */
  class D71Engine {
    constructor() {
      this.pwas = new Map();
      this.serviceWorkers = new Map();
      this.pushSubscriptions = new Map();
      this.stats = {
        pwasRegistered: 0,
        manifestsValidated: 0,
        serviceWorkersInvalidated: 0,
        subscriptionsRevoked: 0
      };
    }

    /**
     * Register a PWA
     */
    registerPWA(pwaId, name, scope = '/') {
      this.pwas.set(pwaId, {
        id: pwaId,
        name,
        scope,
        registered: now(),
        active: true
      });
      this.stats.pwasRegistered++;
      return pwaId;
    }

    /**
     * Validate PWA manifest against posture
     */
    validateManifest(pwaId, manifestContent = {}, currentPostureLevel) {
      this.stats.manifestsValidated++;
      const pwa = this.pwas.get(pwaId);
      if (!pwa) return null;

      const minPosture = manifestContent.minPostureLevel || PostureLevel.TRUSTED;
      const valid = currentPostureLevel >= minPosture;

      return {
        pwaId,
        valid,
        manifestScope: pwa.scope,
        requiredPosture: minPosture,
        currentPosture: currentPostureLevel,
        validated: now()
      };
    }

    /**
     * Invalidate service worker on posture downgrade
     */
    invalidateServiceWorker(pwaId, swId = null) {
      const pwa = this.pwas.get(pwaId);
      if (!pwa) return null;

      const swForPWA = swId ?
        this.serviceWorkers.get(swId) :
        Array.from(this.serviceWorkers.values())
          .find(sw => sw.pwaId === pwaId);

      if (swForPWA) {
        swForPWA.active = false;
        swForPWA.invalidatedAt = now();
        this.stats.serviceWorkersInvalidated++;

        return {
          pwaId,
          serviceWorker: swForPWA.id,
          invalidated: true
        };
      }

      return null;
    }

    /**
     * Revoke push subscriptions
     */
    revokePushSubscriptions(pwaId, subscriptionIds = []) {
      const revoked = [];

      subscriptionIds.forEach(subId => {
        const sub = this.pushSubscriptions.get(subId);
        if (sub && sub.pwaId === pwaId) {
          sub.active = false;
          sub.revokedAt = now();
          revoked.push(subId);
          this.stats.subscriptionsRevoked++;
        }
      });

      return {
        pwaId,
        revokedCount: revoked.length,
        revoked
      };
    }

    /**
     * Get PWA statistics
     */
    getPWAStats() {
      const activeServiceWorkers = Array.from(this.serviceWorkers.values())
        .filter(sw => sw.active).length;

      const activeSubscriptions = Array.from(this.pushSubscriptions.values())
        .filter(sub => sub.active).length;

      return {
        ...this.stats,
        registeredPWAs: Array.from(this.pwas.values())
          .filter(p => p.active).length,
        activeServiceWorkers,
        activeSubscriptions
      };
    }

    /**
     * Handle posture transitions
     */
    onPostureTransition(priorLevel, currentLevel, delta) {
      const invalidations = [];
      const revocations = [];

      if (currentLevel < priorLevel) {
        // Posture downgrade
        this.pwas.forEach((pwa, pwaId) => {
          const swResult = this.invalidateServiceWorker(pwaId);
          if (swResult) invalidations.push(swResult);

          const subs = Array.from(this.pushSubscriptions.values())
            .filter(s => s.pwaId === pwaId && s.active)
            .map(s => s.id);

          if (subs.length > 0) {
            const revResult = this.revokePushSubscriptions(pwaId, subs);
            revocations.push(revResult);
          }
        });
      }

      return { invalidations, revocations };
    }

    /**
     * Get comprehensive statistics
     */
    getStats() {
      return this.getPWAStats();
    }
  }

  globalThis.StaamlD71 = { PostureLevel, D71Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
