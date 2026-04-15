'use strict';

/**
 * StaamlCorp Temporal Security Derivative D43
 * HTTP Posture-Aware Caching Protocol Extensions
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

// =========================================================================
  // D43: Network Posture Binding
  // =========================================================================

  /**
   * @typedef {Object} EndpointRegistration
   * @property {string} endpointId
   * @property {string} url
   * @property {string} category
   * @property {number[]} allowedPostureLevels
   * @property {string[]} allowedTenants
   * @property {string} registeredAt
   * @property {string} hash
   * @property {boolean} active
   */

  /**
   * @typedef {Object} NetworkRequest
   * @property {string} endpointId
   * @property {string} tenantId
   * @property {number} postureLevel
   * @property {string} method
   * @property {string} timestamp
   */

  /**
   * @typedef {Object} NetworkDecision
   * @property {string} endpointId
   * @property {boolean} permitted
   * @property {string} reason
   * @property {string} category
   * @property {boolean} postureCheck
   * @property {boolean} tenantCheck
   */

  /** Endpoint categories */
  const EndpointCategory = Object.freeze({
    INTERNAL: 'INTERNAL',
    EXTERNAL: 'EXTERNAL',
    HEALTHCARE_API: 'HEALTHCARE_API',
    FHIR_SERVER: 'FHIR_SERVER',
    IDENTITY_PROVIDER: 'IDENTITY_PROVIDER',
    ML_INFERENCE: 'ML_INFERENCE',
    MONITORING: 'MONITORING',
    BLOCKED: 'BLOCKED'
  });

  /** Private/internal IP patterns for SSRF detection */
  const SSRF_PATTERNS = [
    { pattern: /^https?:\/\/127\.\d+\.\d+\.\d+/i, reason: 'Localhost (127.x.x.x)' },
    { pattern: /^https?:\/\/localhost/i, reason: 'Localhost' },
    { pattern: /^https?:\/\/0\.0\.0\.0/i, reason: 'Unspecified address (0.0.0.0)' },
    { pattern: /^https?:\/\/10\.\d+\.\d+\.\d+/i, reason: 'Private IP (10.x.x.x)' },
    { pattern: /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i, reason: 'Private IP (172.16-31.x.x)' },
    { pattern: /^https?:\/\/192\.168\.\d+\.\d+/i, reason: 'Private IP (192.168.x.x)' },
    { pattern: /^https?:\/\/169\.254\.\d+\.\d+/i, reason: 'Link-local / metadata endpoint (169.254.x.x)' },
    { pattern: /^https?:\/\/\[::1\]/i, reason: 'IPv6 localhost' },
    { pattern: /^https?:\/\/\[fc/i, reason: 'IPv6 unique local' },
    { pattern: /^https?:\/\/\[fd/i, reason: 'IPv6 unique local' },
    { pattern: /^https?:\/\/\[fe80:/i, reason: 'IPv6 link-local' },
    { pattern: /^https?:\/\/metadata\.google/i, reason: 'Cloud metadata endpoint' },
    { pattern: /^https?:\/\/100\.100\.100\.200/i, reason: 'Alibaba metadata endpoint' },
    { pattern: /169\.254\.169\.254/i, reason: 'AWS/Azure/GCP metadata endpoint' }
  ];

  /**
   * D43 Network Posture Binding Engine.
   * SSRF prevention with endpoint allowlist and emergency lockdown.
   */
  class D43Engine {
    constructor() {
      /** @type {Map<string, EndpointRegistration>} endpointId -> registration */
      this._endpoints = new Map();
      /** @type {Map<string, EndpointRegistration>} url -> registration (for URL lookup) */
      this._urlIndex = new Map();
      /** @type {Map<string, NetworkDecision[]>} tenantId -> decisions */
      this._networkLog = new Map();
      /** @type {boolean} */
      this._lockdown = false;
      /** @type {string} */
      this._lockdownReason = '';
      /** @type {string} */
      this._lockdownCode = '';
    }

    /**
     * Register an endpoint in the allowlist.
     * @param {string} url
     * @param {string} category - EndpointCategory value
     * @param {number[]} allowedPostureLevels
     * @param {string[]} allowedTenants
     * @returns {Promise<EndpointRegistration>}
     */
    async registerEndpoint(url, category, allowedPostureLevels, allowedTenants) {
      var endpointId = generateId();
      var registeredAt = now();
      var hash = await sha256(url + '|' + category + '|' + registeredAt);

      /** @type {EndpointRegistration} */
      var registration = {
        endpointId: endpointId,
        url: url,
        category: category,
        allowedPostureLevels: allowedPostureLevels.slice(),
        allowedTenants: allowedTenants.slice(),
        registeredAt: registeredAt,
        hash: hash,
        active: true
      };

      this._endpoints.set(endpointId, registration);
      this._urlIndex.set(url, registration);
      return registration;
    }

    /**
     * Evaluate a network request against the endpoint allowlist.
     * @param {NetworkRequest} request
     * @returns {NetworkDecision}
     */
    evaluateRequest(request) {
      var logDecision = function (decision, self) {
        if (!self._networkLog.has(request.tenantId)) {
          self._networkLog.set(request.tenantId, []);
        }
        self._networkLog.get(request.tenantId).push(decision);
        return decision;
      };

      // Lockdown check
      if (this._lockdown) {
        return logDecision({
          endpointId: request.endpointId,
          permitted: false,
          reason: 'Emergency lockdown active: ' + this._lockdownReason,
          category: '',
          postureCheck: false,
          tenantCheck: false
        }, this);
      }

      // Find endpoint
      var endpoint = this._endpoints.get(request.endpointId);
      if (!endpoint) {
        return logDecision({
          endpointId: request.endpointId,
          permitted: false,
          reason: 'Endpoint not registered in allowlist',
          category: '',
          postureCheck: false,
          tenantCheck: false
        }, this);
      }

      // Active check
      if (!endpoint.active) {
        return logDecision({
          endpointId: request.endpointId,
          permitted: false,
          reason: 'Endpoint is deactivated',
          category: endpoint.category,
          postureCheck: false,
          tenantCheck: false
        }, this);
      }

      // Blocked category check
      if (endpoint.category === EndpointCategory.BLOCKED) {
        return logDecision({
          endpointId: request.endpointId,
          permitted: false,
          reason: 'Endpoint is in BLOCKED category',
          category: endpoint.category,
          postureCheck: false,
          tenantCheck: false
        }, this);
      }

      // Posture check
      var postureOk = endpoint.allowedPostureLevels.indexOf(request.postureLevel) !== -1;
      if (!postureOk) {
        return logDecision({
          endpointId: request.endpointId,
          permitted: false,
          reason: 'Posture level ' + request.postureLevel + ' not in allowed levels: [' + endpoint.allowedPostureLevels.join(', ') + ']',
          category: endpoint.category,
          postureCheck: false,
          tenantCheck: false
        }, this);
      }

      // Tenant check
      var tenantOk = endpoint.allowedTenants.length === 0 || endpoint.allowedTenants.indexOf(request.tenantId) !== -1;
      if (!tenantOk) {
        return logDecision({
          endpointId: request.endpointId,
          permitted: false,
          reason: 'Tenant ' + request.tenantId + ' not in allowed tenants',
          category: endpoint.category,
          postureCheck: true,
          tenantCheck: false
        }, this);
      }

      return logDecision({
        endpointId: request.endpointId,
        permitted: true,
        reason: 'Request permitted',
        category: endpoint.category,
        postureCheck: true,
        tenantCheck: true
      }, this);
    }

    /**
     * Detect SSRF indicators in a URL.
     * @param {string} url
     * @returns {{detected: boolean, reason: string, indicators: string[]}}
     */
    detectSSRF(url) {
      var indicators = [];

      for (var i = 0; i < SSRF_PATTERNS.length; i++) {
        SSRF_PATTERNS[i].pattern.lastIndex = 0;
        if (SSRF_PATTERNS[i].pattern.test(url)) {
          indicators.push(SSRF_PATTERNS[i].reason);
        }
      }

      // Additional checks
      // URL with credentials
      if (/@/.test(url) && /^https?:\/\/[^/]*:.*@/i.test(url)) {
        indicators.push('URL contains embedded credentials');
      }

      // Hex/octal IP encoding bypass
      if (/0x[0-9a-f]{2,}/i.test(url)) {
        indicators.push('Hex-encoded IP address detected');
      }

      // DNS rebinding indicators
      if (/\.local\b/i.test(url) || /\.internal\b/i.test(url)) {
        indicators.push('Internal DNS name detected');
      }

      // Protocol smuggling
      if (/^(gopher|file|dict|ldap|tftp):/i.test(url)) {
        indicators.push('Non-HTTP protocol detected: possible protocol smuggling');
      }

      return {
        detected: indicators.length > 0,
        reason: indicators.length > 0 ? indicators[0] : '',
        indicators: indicators
      };
    }

    /**
     * Activate emergency lockdown - block ALL external traffic.
     * @param {string} reason
     */
    emergencyLockdown(reason) {
      this._lockdown = true;
      this._lockdownReason = reason || 'No reason provided';
      // Generate authorization code for lifting
      var codeBytes = new Uint8Array(16);
      crypto.getRandomValues(codeBytes);
      this._lockdownCode = Array.from(codeBytes, function (b) { return b.toString(16).padStart(2, '0'); }).join('');
      return this._lockdownCode;
    }

    /**
     * Lift the emergency lockdown.
     * @param {string} authorizationCode
     * @returns {boolean} Whether lockdown was successfully lifted
     */
    liftLockdown(authorizationCode) {
      if (!this._lockdown) return false;
      if (authorizationCode !== this._lockdownCode) return false;
      this._lockdown = false;
      this._lockdownReason = '';
      this._lockdownCode = '';
      return true;
    }

    /**
     * Get the network decision log for a tenant.
     * @param {string} tenantId
     * @returns {NetworkDecision[]}
     */
    getNetworkLog(tenantId) {
      return (this._networkLog.get(tenantId) || []).slice();
    }

    /**
     * Get all registered endpoints.
     * @returns {EndpointRegistration[]}
     */
    getRegisteredEndpoints() {
      return Array.from(this._endpoints.values());
    }
  }

  globalThis.StaamlD43 = { PostureLevel, generateId, now, sha256 };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
