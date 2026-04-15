'use strict';

/**
 * StaamlCorp Temporal Security Derivative D48
 * Multi-Tenant Posture Isolation in Shared Caches
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

// ---------------------------------------------------------------------------
  // D48 -- Multi-Tenant Posture Isolation
  // ---------------------------------------------------------------------------

  /**
   * Represents a tenant boundary with a derived key and cache namespace.
   * @class
   */
  class TenantBoundary {
    /**
     * @param {Object} opts
     * @param {string} opts.tenantId
     * @param {string} opts.derivedKey
     * @param {string} opts.cacheNamespace
     * @param {number} opts.postureLevel
     */
    constructor(opts) {
      this.tenantId       = opts.tenantId;
      this.derivedKey     = opts.derivedKey;
      this.cacheNamespace = opts.cacheNamespace;
      this.postureLevel   = opts.postureLevel;
      this.createdAt      = now();
    }
  }

  /**
   * D48 Engine -- Multi-Tenant Posture Isolation.
   * Provides cryptographic tenant separation with per-tenant HMAC-bound cache.
   * @class
   */
  class D48Engine {
    /**
     * @param {string} masterKeyHex
     */
    constructor(masterKeyHex) {
      /** @type {string} */
      this._masterKeyHex = masterKeyHex;
      /** @type {CryptoKey|null} */
      this._cryptoKey = null;
      /** @type {Map<string, TenantBoundary>} */
      this._tenants = new Map();
      /** @type {Array<Object>} */
      this._violations = [];
    }

    /**
     * @private
     * @returns {Promise<CryptoKey>}
     */
    async _key() {
      if (!this._cryptoKey) {
        this._cryptoKey = await importHmacKey(this._masterKeyHex);
      }
      return this._cryptoKey;
    }

    /**
     * Register a new tenant and derive its key and cache namespace.
     * @param {string} tenantId
     * @param {number} postureLevel
     * @returns {Promise<TenantBoundary>}
     */
    async registerTenant(tenantId, postureLevel) {
      const key = await this._key();
      const derivedKey = await hmacSign(key, 'QERATHEON/tenant/' + tenantId);
      const cacheNamespace = await hmacSign(key, 'QERATHEON/cache/' + tenantId);
      const boundary = new TenantBoundary({
        tenantId:       tenantId,
        derivedKey:     derivedKey,
        cacheNamespace: cacheNamespace.slice(0, 16),
        postureLevel:   postureLevel
      });
      this._tenants.set(tenantId, boundary);
      return boundary;
    }

    /**
     * Validate whether a tenant may access a resource belonging to another tenant.
     * @param {string} tenantId - The requesting tenant.
     * @param {string} resourceTenantId - The tenant that owns the resource.
     * @returns {{allowed: boolean, reason: string}}
     */
    validateAccess(tenantId, resourceTenantId) {
      if (tenantId === resourceTenantId) {
        return { allowed: true, reason: 'SAME_TENANT' };
      }
      this._logViolation(tenantId, resourceTenantId, 'CROSS_TENANT_ACCESS');
      return { allowed: false, reason: 'CROSS_TENANT_ACCESS_DENIED' };
    }

    /**
     * Get the HMAC-derived cache namespace for a tenant.
     * @param {string} tenantId
     * @returns {string|null}
     */
    getCacheNamespace(tenantId) {
      const boundary = this._tenants.get(tenantId);
      return boundary ? boundary.cacheNamespace : null;
    }

    /**
     * Detect a cross-tenant data leak by checking tenant boundaries.
     * @param {*} data - The data being transferred (not inspected, presence check only).
     * @param {string} sourceTenant
     * @param {string} destTenant
     * @returns {boolean} true if a leak is detected
     */
    detectCrossTenantLeak(data, sourceTenant, destTenant) {
      if (sourceTenant !== destTenant) {
        this._logViolation(sourceTenant, destTenant, 'CROSS_TENANT_LEAK');
        return true;
      }
      return false;
    }

    /**
     * Generate an isolation report.
     * @returns {{tenants: number, violations: Array<Object>, status: string}}
     */
    isolationReport() {
      const violations = [...this._violations];
      return {
        tenants:    this._tenants.size,
        violations: violations,
        status:     violations.length === 0 ? 'CLEAN' : 'VIOLATIONS_DETECTED'
      };
    }

    /** @private */
    _logViolation(sourceTenant, destTenant, type) {
      this._violations.push({
        sourceTenant: sourceTenant,
        destTenant:   destTenant,
        type:         type,
        timestamp:    now()
      });
    }
  }

  globalThis.StaamlD48 = { PostureLevel, generateId, now, sha256 };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
