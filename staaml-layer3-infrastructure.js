/**
 * STAAML Layer 3 Infrastructure Security Derivatives
 * staaml.com - Static GitHub Pages Deployment
 *
 * Implements D33, D35, D36, D38, D43, D50 from the STAAML derivative framework.
 * All cryptographic operations use the Web Crypto API.
 * No external dependencies.
 *
 * @version 1.0.0
 * @license Proprietary - Staaml
 */
(function () {
  'use strict';

  // =========================================================================
  // Shared Constants & Utilities
  // =========================================================================

  /** @enum {number} */
  const PostureLevel = Object.freeze({
    UNTRUSTED: 0,
    RESTRICTED: 1,
    STANDARD: 2,
    ELEVATED: 3,
    PRIVILEGED: 4,
    CRITICAL: 5
  });

  const POSTURE_NAMES = Object.freeze([
    'UNTRUSTED', 'RESTRICTED', 'STANDARD', 'ELEVATED', 'PRIVILEGED', 'CRITICAL'
  ]);

  /**
   * Generate a cryptographically random UUID v4.
   * @returns {string}
   */
  function generateId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    return [
      hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
      hex.slice(16, 20), hex.slice(20)
    ].join('-');
  }

  /**
   * Get current ISO timestamp.
   * @returns {string}
   */
  function now() {
    return new Date().toISOString();
  }

  /** @type {CryptoKey|null} */
  let _hmacKey = null;

  /**
   * Import a master key for HMAC-SHA256 signing.
   * @param {string} masterKey - Hex-encoded or raw string key
   * @returns {Promise<CryptoKey>}
   */
  async function importHmacKey(masterKey) {
    const enc = new TextEncoder();
    const keyData = enc.encode(masterKey);
    return crypto.subtle.importKey(
      'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
    );
  }

  /**
   * Compute HMAC-SHA256 signature.
   * @param {string} data
   * @returns {Promise<string>} Hex-encoded signature
   */
  async function hmacSign(data) {
    if (!_hmacKey) throw new Error('STAAML Layer 3 not initialized. Call StaamlLayer3.init(masterKey) first.');
    const enc = new TextEncoder();
    const sig = await crypto.subtle.sign('HMAC', _hmacKey, enc.encode(data));
    return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Verify HMAC-SHA256 signature.
   * @param {string} data
   * @param {string} signature - Hex-encoded
   * @returns {Promise<boolean>}
   */
  async function hmacVerify(data, signature) {
    if (!_hmacKey) return false;
    const enc = new TextEncoder();
    const sigBytes = new Uint8Array(signature.match(/.{2}/g).map(h => parseInt(h, 16)));
    return crypto.subtle.verify('HMAC', _hmacKey, sigBytes, enc.encode(data));
  }

  /**
   * Compute SHA-256 hash.
   * @param {string} data
   * @returns {Promise<string>} Hex-encoded hash
   */
  async function sha256(data) {
    const enc = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', enc.encode(data));
    return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
  }

  // =========================================================================
  // D33: Posture-Aware Execution Gate
  // =========================================================================

  /**
   * @typedef {Object} SkillAttestation
   * @property {string} skillName
   * @property {string} skillHash
   * @property {number} postureLevel
   * @property {string[]} authorizedCategories
   * @property {string[]} authorizedResources
   * @property {string[]} authorizedEndpoints
   * @property {string} signerId
   * @property {string} signedAt
   * @property {string} signature
   * @property {string} expiresAt
   * @property {boolean} revoked
   */

  /**
   * @typedef {Object} ExecutionRequest
   * @property {string} skillName
   * @property {string} tenantId
   * @property {boolean} sensitiveRequired
   * @property {string[]} categories
   * @property {string[]} resources
   * @property {string[]} targetEndpoints
   * @property {string} timestamp
   */

  /**
   * @typedef {Object} ExecutionDecision
   * @property {string} skillName
   * @property {boolean} permitted
   * @property {string} reason
   * @property {number} requiredPosture
   * @property {number} actualPosture
   * @property {boolean} attestationValid
   * @property {boolean} accessAuthorized
   * @property {string} timestamp
   */

  const D33_DOMAIN_PREFIX = 'QERATHEON/skill/attest';

  /** Skill posture levels for D33 */
  const SkillPosture = Object.freeze({
    UNTRUSTED: 0,
    BASIC: 1,
    VERIFIED: 2,
    AUTHORIZED: 3,
    ADMIN: 4,
    SYSTEM: 5
  });

  /**
   * D33 Posture-Aware Execution Gate Engine.
   * Skill execution gating by posture level. Unattested skills default to UNTRUSTED.
   * Only cryptographically attested skills (posture 3+) can access sensitive data.
   */
  class D33Engine {
    constructor() {
      /** @type {Map<string, SkillAttestation>} */
      this._attestations = new Map();
      /** @type {Map<string, ExecutionDecision[]>} */
      this._executionLog = new Map();
      /** @type {Map<string, string>} */
      this._blockedSkills = new Map();
    }

    /**
     * Create a cryptographic attestation for a skill.
     * @param {string} skillName
     * @param {string} skillContent - Raw skill source/content for hashing
     * @param {number} postureLevel - SkillPosture level (0-5)
     * @param {string} signerId - Identity of the signer
     * @param {string[]} categories - Authorized data categories
     * @param {string[]} resources - Authorized resources
     * @param {string[]} endpoints - Authorized endpoints
     * @param {number} [ttlHours=24] - Time-to-live in hours
     * @returns {Promise<SkillAttestation>}
     */
    async attestSkill(skillName, skillContent, postureLevel, signerId, categories, resources, endpoints, ttlHours) {
      if (postureLevel < 0 || postureLevel > 5) {
        throw new RangeError('Posture level must be between 0 and 5');
      }
      ttlHours = ttlHours || 24;

      const skillHash = await sha256(skillContent);
      const signedAt = now();
      const expiresAt = new Date(Date.now() + ttlHours * 3600000).toISOString();

      const sigPayload = [
        D33_DOMAIN_PREFIX, skillName, skillHash,
        String(postureLevel), signerId, signedAt, expiresAt,
        categories.sort().join(','),
        resources.sort().join(','),
        endpoints.sort().join(',')
      ].join('|');

      const signature = await hmacSign(sigPayload);

      /** @type {SkillAttestation} */
      const attestation = {
        skillName,
        skillHash,
        postureLevel,
        authorizedCategories: categories.slice(),
        authorizedResources: resources.slice(),
        authorizedEndpoints: endpoints.slice(),
        signerId,
        signedAt,
        signature,
        expiresAt,
        revoked: false
      };

      this._attestations.set(skillName, attestation);
      return attestation;
    }

    /**
     * Evaluate an execution request through the 8-check gating pipeline.
     * @param {ExecutionRequest} request
     * @returns {Promise<ExecutionDecision>}
     */
    async evaluateExecution(request) {
      const ts = request.timestamp || now();

      const makeDecision = (permitted, reason, requiredPosture, actualPosture, attestationValid, accessAuthorized) => {
        /** @type {ExecutionDecision} */
        const decision = {
          skillName: request.skillName,
          permitted,
          reason,
          requiredPosture,
          actualPosture,
          attestationValid,
          accessAuthorized,
          timestamp: ts
        };
        if (!this._executionLog.has(request.skillName)) {
          this._executionLog.set(request.skillName, []);
        }
        this._executionLog.get(request.skillName).push(decision);
        return decision;
      };

      // Check 0: blocked
      if (this._blockedSkills.has(request.skillName)) {
        return makeDecision(false, 'Skill is blocked: ' + this._blockedSkills.get(request.skillName), 0, 0, false, false);
      }

      // Check 1: attestation exists
      const att = this._attestations.get(request.skillName);
      if (!att) {
        return makeDecision(false, 'No attestation found; skill defaults to UNTRUSTED', request.sensitiveRequired ? SkillPosture.AUTHORIZED : SkillPosture.BASIC, SkillPosture.UNTRUSTED, false, false);
      }

      // Check 2: not revoked
      if (att.revoked) {
        return makeDecision(false, 'Attestation has been revoked', 0, att.postureLevel, false, false);
      }

      // Check 3: not expired
      if (new Date(att.expiresAt) < new Date(ts)) {
        return makeDecision(false, 'Attestation has expired', 0, att.postureLevel, false, false);
      }

      // Check 4: signature valid
      const sigPayload = [
        D33_DOMAIN_PREFIX, att.skillName, att.skillHash,
        String(att.postureLevel), att.signerId, att.signedAt, att.expiresAt,
        att.authorizedCategories.slice().sort().join(','),
        att.authorizedResources.slice().sort().join(','),
        att.authorizedEndpoints.slice().sort().join(',')
      ].join('|');

      const sigValid = await hmacVerify(sigPayload, att.signature);
      if (!sigValid) {
        return makeDecision(false, 'Attestation signature verification failed', 0, att.postureLevel, false, false);
      }

      // Check 5: posture sufficient
      const requiredPosture = request.sensitiveRequired ? SkillPosture.AUTHORIZED : SkillPosture.BASIC;
      if (att.postureLevel < requiredPosture) {
        return makeDecision(false, 'Insufficient posture level: requires ' + requiredPosture + ', has ' + att.postureLevel, requiredPosture, att.postureLevel, true, false);
      }

      // Check 6: categories authorized
      if (request.categories && request.categories.length > 0) {
        const unauthorized = request.categories.filter(c => !att.authorizedCategories.includes(c));
        if (unauthorized.length > 0) {
          return makeDecision(false, 'Unauthorized categories: ' + unauthorized.join(', '), requiredPosture, att.postureLevel, true, false);
        }
      }

      // Check 7: resources authorized
      if (request.resources && request.resources.length > 0) {
        const unauthorized = request.resources.filter(r => !att.authorizedResources.includes(r));
        if (unauthorized.length > 0) {
          return makeDecision(false, 'Unauthorized resources: ' + unauthorized.join(', '), requiredPosture, att.postureLevel, true, false);
        }
      }

      // Check 8: endpoints authorized
      if (request.targetEndpoints && request.targetEndpoints.length > 0) {
        const unauthorized = request.targetEndpoints.filter(e => !att.authorizedEndpoints.includes(e));
        if (unauthorized.length > 0) {
          return makeDecision(false, 'Unauthorized endpoints: ' + unauthorized.join(', '), requiredPosture, att.postureLevel, true, false);
        }
      }

      return makeDecision(true, 'All 8 checks passed', requiredPosture, att.postureLevel, true, true);
    }

    /**
     * Block a skill from execution.
     * @param {string} skillName
     * @param {string} reason
     */
    blockSkill(skillName, reason) {
      this._blockedSkills.set(skillName, reason || 'No reason provided');
      const att = this._attestations.get(skillName);
      if (att) {
        att.revoked = true;
      }
    }

    /**
     * Get execution log for a skill.
     * @param {string} skillName
     * @returns {ExecutionDecision[]}
     */
    getExecutionLog(skillName) {
      return (this._executionLog.get(skillName) || []).slice();
    }

    /**
     * Get all blocked skill names.
     * @returns {Set<string>}
     */
    getBlockedSkills() {
      return new Set(this._blockedSkills.keys());
    }
  }

  // =========================================================================
  // D35: Posture-Bound Filesystem Attestation
  // =========================================================================

  /**
   * @typedef {Object} FileAttestation
   * @property {string} fileId
   * @property {string} filePath
   * @property {string} fileHash
   * @property {string} tenantId
   * @property {number} postureLevel
   * @property {string} attestedAt
   * @property {string} signerId
   * @property {string} signature
   * @property {string[]} allowedOperations
   * @property {number} size
   * @property {string} lastModified
   */

  /**
   * @typedef {Object} FileAccessRequest
   * @property {string} filePath
   * @property {string} tenantId
   * @property {string} operation - READ, WRITE, DELETE, LIST
   * @property {number} postureLevel
   * @property {string} timestamp
   */

  /**
   * @typedef {Object} FileAccessDecision
   * @property {string} filePath
   * @property {boolean} permitted
   * @property {string} reason
   * @property {boolean} attestationValid
   * @property {boolean} pathValid
   * @property {boolean} postureCheck
   */

  const D35_DOMAIN_PREFIX = 'QERATHEON/fs/attest';

  /** Path traversal patterns */
  const TRAVERSAL_PATTERNS = [
    /\.\.\//g,
    /\.\.\\/g,
    /\.\.$/,
    /%2e%2e/gi,
    /%252e%252e/gi,
    /\.\./g,
    /\/\.\//g,
    /\\.\\/g,
    /~\//g,
    /\0/g
  ];

  const TRAVERSAL_PATTERN_NAMES = [
    'dot-dot-slash', 'dot-dot-backslash', 'trailing-dot-dot',
    'url-encoded-traversal', 'double-url-encoded-traversal',
    'dot-dot-sequence', 'dot-slash', 'backslash-dot',
    'home-expansion', 'null-byte'
  ];

  /** Valid file operations */
  const FileOperation = Object.freeze({
    READ: 'READ',
    WRITE: 'WRITE',
    DELETE: 'DELETE',
    LIST: 'LIST'
  });

  /**
   * D35 Posture-Bound Filesystem Attestation Engine.
   * Path traversal prevention, sandbox escape detection, cross-tenant file access blocking.
   */
  class D35Engine {
    constructor() {
      /** @type {Map<string, FileAttestation>} tenant:path -> attestation */
      this._attestations = new Map();
      /** @type {Map<string, string>} tenantId -> jail root path */
      this._tenantJails = new Map();
      /** @type {Map<string, FileAccessDecision[]>} tenantId -> decisions */
      this._accessLog = new Map();
    }

    /**
     * Set the jail root for a tenant. All file paths must be within this root.
     * @param {string} tenantId
     * @param {string} jailRoot - Absolute path prefix
     */
    setTenantJail(tenantId, jailRoot) {
      // Normalize: ensure trailing slash
      const normalized = jailRoot.endsWith('/') ? jailRoot : jailRoot + '/';
      this._tenantJails.set(tenantId, normalized);
    }

    /**
     * Normalize a file path, resolving relative components.
     * @param {string} filePath
     * @returns {string}
     */
    _normalizePath(filePath) {
      // Remove null bytes
      let path = filePath.replace(/\0/g, '');
      // Decode percent-encoded characters
      try { path = decodeURIComponent(path); } catch (e) { /* ignore decode errors */ }
      // Normalize separators
      path = path.replace(/\\/g, '/');
      // Resolve . and ..
      const parts = path.split('/');
      const resolved = [];
      for (const part of parts) {
        if (part === '.' || part === '') continue;
        if (part === '..') {
          resolved.pop();
        } else {
          resolved.push(part);
        }
      }
      return '/' + resolved.join('/');
    }

    /**
     * Validate a file path against a tenant's jail.
     * @param {string} filePath
     * @param {string} tenantId
     * @returns {{valid: boolean, normalizedPath: string, reason: string}}
     */
    validatePath(filePath, tenantId) {
      const traversalCheck = this.detectTraversal(filePath);
      if (traversalCheck.detected) {
        return {
          valid: false,
          normalizedPath: '',
          reason: 'Path traversal detected: ' + traversalCheck.pattern
        };
      }

      const normalized = this._normalizePath(filePath);
      const jail = this._tenantJails.get(tenantId);

      if (!jail) {
        return {
          valid: false,
          normalizedPath: normalized,
          reason: 'No jail configured for tenant: ' + tenantId
        };
      }

      if (!normalized.startsWith(jail.replace(/\/$/, ''))) {
        return {
          valid: false,
          normalizedPath: normalized,
          reason: 'Path escapes tenant jail. Jail: ' + jail + ', Path: ' + normalized
        };
      }

      return { valid: true, normalizedPath: normalized, reason: 'Path is within tenant jail' };
    }

    /**
     * Detect path traversal attempts.
     * @param {string} filePath
     * @returns {{detected: boolean, pattern: string}}
     */
    detectTraversal(filePath) {
      for (let i = 0; i < TRAVERSAL_PATTERNS.length; i++) {
        // Reset regex lastIndex
        TRAVERSAL_PATTERNS[i].lastIndex = 0;
        if (TRAVERSAL_PATTERNS[i].test(filePath)) {
          return { detected: true, pattern: TRAVERSAL_PATTERN_NAMES[i] };
        }
      }
      return { detected: false, pattern: '' };
    }

    /**
     * Attest a file for a specific tenant.
     * @param {string} filePath
     * @param {string} content - File content for hashing
     * @param {string} tenantId
     * @param {number} postureLevel
     * @param {string} signerId
     * @param {string[]} operations - Allowed operations: READ, WRITE, DELETE, LIST
     * @returns {Promise<FileAttestation>}
     */
    async attestFile(filePath, content, tenantId, postureLevel, signerId, operations) {
      const pathValidation = this.validatePath(filePath, tenantId);
      if (!pathValidation.valid) {
        throw new Error('Cannot attest file: ' + pathValidation.reason);
      }

      const normalizedPath = pathValidation.normalizedPath;
      const fileHash = await sha256(content);
      const fileId = generateId();
      const attestedAt = now();

      const sigPayload = [
        D35_DOMAIN_PREFIX, fileId, normalizedPath, fileHash,
        tenantId, String(postureLevel), signerId, attestedAt,
        operations.sort().join(',')
      ].join('|');

      const signature = await hmacSign(sigPayload);

      /** @type {FileAttestation} */
      const attestation = {
        fileId,
        filePath: normalizedPath,
        fileHash,
        tenantId,
        postureLevel,
        attestedAt,
        signerId,
        signature,
        allowedOperations: operations.slice(),
        size: new TextEncoder().encode(content).length,
        lastModified: attestedAt
      };

      const key = tenantId + ':' + normalizedPath;
      this._attestations.set(key, attestation);
      return attestation;
    }

    /**
     * Evaluate a file access request.
     * @param {FileAccessRequest} request
     * @returns {Promise<FileAccessDecision>}
     */
    async evaluateAccess(request) {
      const ts = request.timestamp || now();

      const logDecision = (decision) => {
        if (!this._accessLog.has(request.tenantId)) {
          this._accessLog.set(request.tenantId, []);
        }
        this._accessLog.get(request.tenantId).push(decision);
        return decision;
      };

      // Validate path
      const pathValidation = this.validatePath(request.filePath, request.tenantId);
      if (!pathValidation.valid) {
        return logDecision({
          filePath: request.filePath,
          permitted: false,
          reason: pathValidation.reason,
          attestationValid: false,
          pathValid: false,
          postureCheck: false
        });
      }

      const normalizedPath = pathValidation.normalizedPath;
      const key = request.tenantId + ':' + normalizedPath;
      const att = this._attestations.get(key);

      // Attestation exists check
      if (!att) {
        return logDecision({
          filePath: normalizedPath,
          permitted: false,
          reason: 'No attestation found for file',
          attestationValid: false,
          pathValid: true,
          postureCheck: false
        });
      }

      // Verify signature
      const sigPayload = [
        D35_DOMAIN_PREFIX, att.fileId, att.filePath, att.fileHash,
        att.tenantId, String(att.postureLevel), att.signerId, att.attestedAt,
        att.allowedOperations.slice().sort().join(',')
      ].join('|');

      const sigValid = await hmacVerify(sigPayload, att.signature);
      if (!sigValid) {
        return logDecision({
          filePath: normalizedPath,
          permitted: false,
          reason: 'Attestation signature verification failed',
          attestationValid: false,
          pathValid: true,
          postureCheck: false
        });
      }

      // Cross-tenant check
      if (att.tenantId !== request.tenantId) {
        return logDecision({
          filePath: normalizedPath,
          permitted: false,
          reason: 'Cross-tenant access denied',
          attestationValid: true,
          pathValid: true,
          postureCheck: false
        });
      }

      // Posture level check
      if (request.postureLevel < att.postureLevel) {
        return logDecision({
          filePath: normalizedPath,
          permitted: false,
          reason: 'Insufficient posture level: requires ' + att.postureLevel + ', has ' + request.postureLevel,
          attestationValid: true,
          pathValid: true,
          postureCheck: false
        });
      }

      // Operation check
      if (!att.allowedOperations.includes(request.operation)) {
        return logDecision({
          filePath: normalizedPath,
          permitted: false,
          reason: 'Operation not permitted: ' + request.operation + '. Allowed: ' + att.allowedOperations.join(', '),
          attestationValid: true,
          pathValid: true,
          postureCheck: true
        });
      }

      return logDecision({
        filePath: normalizedPath,
        permitted: true,
        reason: 'Access granted',
        attestationValid: true,
        pathValid: true,
        postureCheck: true
      });
    }

    /**
     * Get the access log for a tenant.
     * @param {string} tenantId
     * @returns {FileAccessDecision[]}
     */
    getAccessLog(tenantId) {
      return (this._accessLog.get(tenantId) || []).slice();
    }
  }

  // =========================================================================
  // D36: Runtime Environment Attestation
  // =========================================================================

  /**
   * @typedef {Object} EnvironmentBaseline
   * @property {string} baselineId
   * @property {Object} variables
   * @property {string} timestamp
   * @property {string} hash
   * @property {boolean} signed
   */

  /**
   * @typedef {Object} EnvironmentCheck
   * @property {string} checkId
   * @property {string} timestamp
   * @property {Array} deviations
   * @property {Array} overrides
   * @property {Array} injections
   * @property {string} result - CLEAN, TAMPERED, SUSPICIOUS
   */

  /** Monitored environment variables (for non-browser context reference) */
  const MONITORED_ENV_VARS = Object.freeze([
    'PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PIP_INDEX_URL',
    'NPM_CONFIG_REGISTRY', 'GIT_DIR', 'GIT_WORK_TREE', 'PYTHONPATH',
    'NODE_PATH', 'HTTP_PROXY', 'HTTPS_PROXY', 'SSL_CERT_FILE',
    'CC', 'CXX', 'EDITOR'
  ]);

  /** Suspicious patterns for injection detection */
  const INJECTION_PATTERNS = Object.freeze([
    { pattern: /https?:\/\/(?!registry\.npmjs\.org|pypi\.org|github\.com)/i, severity: 'HIGH', name: 'suspicious-registry-url' },
    { pattern: /\/tmp\//i, severity: 'MEDIUM', name: 'temp-directory-reference' },
    { pattern: /eval\s*\(/i, severity: 'CRITICAL', name: 'eval-injection' },
    { pattern: /javascript:/i, severity: 'CRITICAL', name: 'javascript-protocol' },
    { pattern: /data:text\/html/i, severity: 'HIGH', name: 'data-uri-html' },
    { pattern: /<script/i, severity: 'CRITICAL', name: 'script-tag-injection' },
    { pattern: /on\w+\s*=/i, severity: 'HIGH', name: 'event-handler-injection' },
    { pattern: /document\.write/i, severity: 'HIGH', name: 'document-write' },
    { pattern: /\.constructor\s*\(/i, severity: 'HIGH', name: 'constructor-access' },
    { pattern: /__proto__/i, severity: 'CRITICAL', name: 'proto-pollution' },
    { pattern: /prototype\s*\[/i, severity: 'CRITICAL', name: 'prototype-bracket-access' }
  ]);

  /**
   * D36 Runtime Environment Attestation Engine.
   * Detects environment variable injection, prototype pollution,
   * script injection, and other runtime tampering in the browser context.
   */
  class D36Engine {
    constructor() {
      /** @type {EnvironmentBaseline|null} */
      this._baseline = null;
      /** @type {EnvironmentCheck[]} */
      this._checkHistory = [];
      /** @type {number|null} */
      this._monitorInterval = null;

      // Snapshot critical prototypes at construction time
      this._originalPrototypes = {
        objectKeys: Object.getOwnPropertyNames(Object.prototype),
        arrayKeys: Object.getOwnPropertyNames(Array.prototype),
        functionKeys: Object.getOwnPropertyNames(Function.prototype),
        promiseKeys: Object.getOwnPropertyNames(Promise.prototype)
      };
    }

    /**
     * Capture the current environment as a baseline.
     * In the browser context: captures navigator properties, window properties,
     * loaded scripts, CSP, cookies, localStorage keys, and prototype states.
     * @returns {Promise<EnvironmentBaseline>}
     */
    async captureBaseline() {
      const variables = {};

      // Navigator properties
      if (typeof navigator !== 'undefined') {
        variables['navigator.userAgent'] = navigator.userAgent || '';
        variables['navigator.language'] = navigator.language || '';
        variables['navigator.languages'] = JSON.stringify(navigator.languages || []);
        variables['navigator.platform'] = navigator.platform || '';
        variables['navigator.cookieEnabled'] = String(navigator.cookieEnabled);
        variables['navigator.onLine'] = String(navigator.onLine);
        variables['navigator.hardwareConcurrency'] = String(navigator.hardwareConcurrency || 0);
      }

      // Document properties
      if (typeof document !== 'undefined') {
        variables['document.cookie'] = document.cookie || '';
        variables['document.referrer'] = document.referrer || '';
        variables['document.domain'] = document.domain || '';

        // CSP meta tags
        const cspMetas = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
        variables['csp.meta.count'] = String(cspMetas.length);
        cspMetas.forEach(function (meta, i) {
          variables['csp.meta.' + i] = meta.getAttribute('content') || '';
        });

        // Loaded scripts
        const scripts = document.querySelectorAll('script');
        variables['scripts.count'] = String(scripts.length);
        scripts.forEach(function (script, i) {
          variables['script.' + i + '.src'] = script.src || '';
          variables['script.' + i + '.type'] = script.type || '';
          if (!script.src && script.textContent) {
            variables['script.' + i + '.hash'] = String(script.textContent.length);
          }
        });
      }

      // localStorage keys
      if (typeof localStorage !== 'undefined') {
        try {
          const keys = [];
          for (var i = 0; i < localStorage.length; i++) {
            keys.push(localStorage.key(i));
          }
          variables['localStorage.keys'] = JSON.stringify(keys.sort());
        } catch (e) {
          variables['localStorage.keys'] = 'ACCESS_DENIED';
        }
      }

      // Prototype state
      variables['proto.Object'] = JSON.stringify(Object.getOwnPropertyNames(Object.prototype).sort());
      variables['proto.Array'] = JSON.stringify(Object.getOwnPropertyNames(Array.prototype).sort());
      variables['proto.Function'] = JSON.stringify(Object.getOwnPropertyNames(Function.prototype).sort());
      variables['proto.Promise'] = JSON.stringify(Object.getOwnPropertyNames(Promise.prototype).sort());

      // Window property count (detect injected globals)
      if (typeof window !== 'undefined') {
        variables['window.propertyCount'] = String(Object.getOwnPropertyNames(window).length);
      }

      const baselineId = generateId();
      const timestamp = now();
      const hash = await sha256(JSON.stringify(variables));

      const baseline = {
        baselineId: baselineId,
        variables: variables,
        timestamp: timestamp,
        hash: hash,
        signed: !!_hmacKey
      };

      if (_hmacKey) {
        baseline.signature = await hmacSign(baselineId + '|' + hash + '|' + timestamp);
      }

      this._baseline = baseline;
      return baseline;
    }

    /**
     * Check the current environment against the baseline.
     * @returns {Promise<EnvironmentCheck>}
     */
    async checkEnvironment() {
      if (!this._baseline) {
        await this.captureBaseline();
      }

      const currentVars = {};
      const deviations = [];
      const overrides = [];
      const injections = [];

      // Re-capture current state
      if (typeof navigator !== 'undefined') {
        currentVars['navigator.userAgent'] = navigator.userAgent || '';
        currentVars['navigator.language'] = navigator.language || '';
        currentVars['navigator.platform'] = navigator.platform || '';
      }

      if (typeof document !== 'undefined') {
        // Cookie changes
        const currentCookie = document.cookie || '';
        if (this._baseline.variables['document.cookie'] !== undefined && currentCookie !== this._baseline.variables['document.cookie']) {
          deviations.push({
            variable: 'document.cookie',
            baseline: this._baseline.variables['document.cookie'],
            current: currentCookie,
            severity: 'MEDIUM'
          });
        }

        // CSP meta changes
        const cspMetas = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
        const baselineCount = parseInt(this._baseline.variables['csp.meta.count'] || '0', 10);
        if (cspMetas.length !== baselineCount) {
          deviations.push({
            variable: 'csp.meta.count',
            baseline: String(baselineCount),
            current: String(cspMetas.length),
            severity: 'CRITICAL'
          });
        }

        // Script injection
        const scripts = document.querySelectorAll('script');
        const baselineScriptCount = parseInt(this._baseline.variables['scripts.count'] || '0', 10);
        if (scripts.length > baselineScriptCount) {
          injections.push({
            type: 'script-injection',
            detail: 'New scripts detected: baseline=' + baselineScriptCount + ', current=' + scripts.length,
            severity: 'CRITICAL',
            count: scripts.length - baselineScriptCount
          });
        }
      }

      // Prototype pollution check
      const currentObjectKeys = Object.getOwnPropertyNames(Object.prototype).sort();
      const baselineObjectKeys = this._originalPrototypes.objectKeys.slice().sort();
      if (JSON.stringify(currentObjectKeys) !== JSON.stringify(baselineObjectKeys)) {
        const added = currentObjectKeys.filter(function (k) { return baselineObjectKeys.indexOf(k) === -1; });
        injections.push({
          type: 'prototype-pollution',
          target: 'Object.prototype',
          addedProperties: added,
          severity: 'CRITICAL'
        });
      }

      const currentArrayKeys = Object.getOwnPropertyNames(Array.prototype).sort();
      const baselineArrayKeys = this._originalPrototypes.arrayKeys.slice().sort();
      if (JSON.stringify(currentArrayKeys) !== JSON.stringify(baselineArrayKeys)) {
        const added = currentArrayKeys.filter(function (k) { return baselineArrayKeys.indexOf(k) === -1; });
        injections.push({
          type: 'prototype-pollution',
          target: 'Array.prototype',
          addedProperties: added,
          severity: 'CRITICAL'
        });
      }

      const currentFunctionKeys = Object.getOwnPropertyNames(Function.prototype).sort();
      const baselineFunctionKeys = this._originalPrototypes.functionKeys.slice().sort();
      if (JSON.stringify(currentFunctionKeys) !== JSON.stringify(baselineFunctionKeys)) {
        const added = currentFunctionKeys.filter(function (k) { return baselineFunctionKeys.indexOf(k) === -1; });
        injections.push({
          type: 'prototype-pollution',
          target: 'Function.prototype',
          addedProperties: added,
          severity: 'CRITICAL'
        });
      }

      const currentPromiseKeys = Object.getOwnPropertyNames(Promise.prototype).sort();
      const baselinePromiseKeys = this._originalPrototypes.promiseKeys.slice().sort();
      if (JSON.stringify(currentPromiseKeys) !== JSON.stringify(baselinePromiseKeys)) {
        const added = currentPromiseKeys.filter(function (k) { return baselinePromiseKeys.indexOf(k) === -1; });
        injections.push({
          type: 'prototype-pollution',
          target: 'Promise.prototype',
          addedProperties: added,
          severity: 'CRITICAL'
        });
      }

      // Navigator property changes
      if (typeof navigator !== 'undefined') {
        var navChecks = ['navigator.userAgent', 'navigator.language', 'navigator.platform'];
        for (var n = 0; n < navChecks.length; n++) {
          var key = navChecks[n];
          if (this._baseline.variables[key] !== undefined && currentVars[key] !== this._baseline.variables[key]) {
            overrides.push({
              variable: key,
              baseline: this._baseline.variables[key],
              current: currentVars[key],
              severity: 'HIGH'
            });
          }
        }
      }

      // localStorage tampering
      if (typeof localStorage !== 'undefined') {
        try {
          var currentKeys = [];
          for (var li = 0; li < localStorage.length; li++) {
            currentKeys.push(localStorage.key(li));
          }
          var currentKeysStr = JSON.stringify(currentKeys.sort());
          if (this._baseline.variables['localStorage.keys'] !== undefined &&
            currentKeysStr !== this._baseline.variables['localStorage.keys'] &&
            this._baseline.variables['localStorage.keys'] !== 'ACCESS_DENIED') {
            deviations.push({
              variable: 'localStorage.keys',
              baseline: this._baseline.variables['localStorage.keys'],
              current: currentKeysStr,
              severity: 'MEDIUM'
            });
          }
        } catch (e) { /* ignore */ }
      }

      // Determine result
      var result = 'CLEAN';
      if (injections.length > 0) {
        result = 'TAMPERED';
      } else if (deviations.length > 0 || overrides.length > 0) {
        result = 'SUSPICIOUS';
      }

      /** @type {EnvironmentCheck} */
      var check = {
        checkId: generateId(),
        timestamp: now(),
        deviations: deviations,
        overrides: overrides,
        injections: injections,
        result: result
      };

      this._checkHistory.push(check);
      return check;
    }

    /**
     * Detect injection patterns in a variable name/value pair.
     * @param {string} variableName
     * @param {string} value
     * @returns {{injected: boolean, pattern: string, severity: string}}
     */
    detectInjection(variableName, value) {
      if (typeof value !== 'string') {
        value = String(value);
      }

      for (var i = 0; i < INJECTION_PATTERNS.length; i++) {
        INJECTION_PATTERNS[i].pattern.lastIndex = 0;
        if (INJECTION_PATTERNS[i].pattern.test(value)) {
          return {
            injected: true,
            pattern: INJECTION_PATTERNS[i].name,
            severity: INJECTION_PATTERNS[i].severity
          };
        }
      }
      return { injected: false, pattern: '', severity: 'NONE' };
    }

    /**
     * Start continuous environment monitoring.
     * @param {number} [intervalMs=30000] - Check interval in milliseconds
     */
    monitorContinuous(intervalMs) {
      var self = this;
      intervalMs = intervalMs || 30000;

      if (this._monitorInterval) {
        clearInterval(this._monitorInterval);
      }

      this._monitorInterval = setInterval(function () {
        self.checkEnvironment().catch(function (err) {
          console.error('[STAAML D36] Environment check failed:', err);
        });
      }, intervalMs);
    }

    /**
     * Stop continuous monitoring.
     */
    stopMonitoring() {
      if (this._monitorInterval) {
        clearInterval(this._monitorInterval);
        this._monitorInterval = null;
      }
    }

    /**
     * Get the history of environment checks.
     * @returns {EnvironmentCheck[]}
     */
    getCheckHistory() {
      return this._checkHistory.slice();
    }
  }

  // =========================================================================
  // D38: Posture-Bound Resource Quotas
  // =========================================================================

  /**
   * @typedef {Object} ResourceQuota
   * @property {string} resourceType
   * @property {number} maxValue
   * @property {number} currentUsage
   * @property {number} postureLevel
   * @property {number} windowMs
   * @property {Array} violations
   */

  /**
   * @typedef {Object} QuotaViolation
   * @property {string} violationId
   * @property {string} tenantId
   * @property {string} resourceType
   * @property {number} requestedAmount
   * @property {number} limit
   * @property {string} timestamp
   * @property {boolean} blocked
   */

  /** Resource types */
  const ResourceType = Object.freeze({
    CPU_TIME: 'CPU_TIME',
    MEMORY: 'MEMORY',
    NETWORK_BANDWIDTH: 'NETWORK_BANDWIDTH',
    STORAGE: 'STORAGE',
    REQUEST_RATE: 'REQUEST_RATE',
    PAYLOAD_SIZE: 'PAYLOAD_SIZE',
    FILE_COUNT: 'FILE_COUNT',
    CONCURRENT_CONNECTIONS: 'CONCURRENT_CONNECTIONS'
  });

  /** Quota profiles per posture level (values in bytes for size, count for rate) */
  const QUOTA_PROFILES = Object.freeze({
    0: { // UNTRUSTED
      PAYLOAD_SIZE: 1 * 1024 * 1024,          // 1MB
      REQUEST_RATE: 10,                         // 10 req/min
      STORAGE: 5 * 1024 * 1024,                // 5MB
      CONCURRENT_CONNECTIONS: 2,
      CPU_TIME: 5000,                           // 5s
      MEMORY: 50 * 1024 * 1024,                // 50MB
      NETWORK_BANDWIDTH: 10 * 1024 * 1024,     // 10MB
      FILE_COUNT: 10
    },
    1: { // RESTRICTED
      PAYLOAD_SIZE: 5 * 1024 * 1024,           // 5MB
      REQUEST_RATE: 30,                         // 30 req/min
      STORAGE: 25 * 1024 * 1024,               // 25MB
      CONCURRENT_CONNECTIONS: 5,
      CPU_TIME: 15000,
      MEMORY: 100 * 1024 * 1024,
      NETWORK_BANDWIDTH: 50 * 1024 * 1024,
      FILE_COUNT: 50
    },
    2: { // STANDARD
      PAYLOAD_SIZE: 10 * 1024 * 1024,          // 10MB
      REQUEST_RATE: 60,                         // 60 req/min
      STORAGE: 100 * 1024 * 1024,              // 100MB
      CONCURRENT_CONNECTIONS: 10,
      CPU_TIME: 30000,
      MEMORY: 256 * 1024 * 1024,
      NETWORK_BANDWIDTH: 100 * 1024 * 1024,
      FILE_COUNT: 200
    },
    3: { // ELEVATED
      PAYLOAD_SIZE: 50 * 1024 * 1024,          // 50MB
      REQUEST_RATE: 120,                        // 120 req/min
      STORAGE: 500 * 1024 * 1024,              // 500MB
      CONCURRENT_CONNECTIONS: 20,
      CPU_TIME: 60000,
      MEMORY: 512 * 1024 * 1024,
      NETWORK_BANDWIDTH: 500 * 1024 * 1024,
      FILE_COUNT: 1000
    },
    4: { // PRIVILEGED
      PAYLOAD_SIZE: 100 * 1024 * 1024,         // 100MB
      REQUEST_RATE: 300,                        // 300 req/min
      STORAGE: 1024 * 1024 * 1024,             // 1GB
      CONCURRENT_CONNECTIONS: 50,
      CPU_TIME: 120000,
      MEMORY: 1024 * 1024 * 1024,
      NETWORK_BANDWIDTH: 1024 * 1024 * 1024,
      FILE_COUNT: 5000
    },
    5: { // CRITICAL - unlimited (use Number.MAX_SAFE_INTEGER)
      PAYLOAD_SIZE: Number.MAX_SAFE_INTEGER,
      REQUEST_RATE: Number.MAX_SAFE_INTEGER,
      STORAGE: Number.MAX_SAFE_INTEGER,
      CONCURRENT_CONNECTIONS: Number.MAX_SAFE_INTEGER,
      CPU_TIME: Number.MAX_SAFE_INTEGER,
      MEMORY: Number.MAX_SAFE_INTEGER,
      NETWORK_BANDWIDTH: Number.MAX_SAFE_INTEGER,
      FILE_COUNT: Number.MAX_SAFE_INTEGER
    }
  });

  /** Bomb detection thresholds */
  const BOMB_THRESHOLDS = Object.freeze({
    ZIP_BOMB_RATIO: 100,      // compressed:decompressed ratio
    PIXEL_BOMB_PIXELS: 100000000, // 100 megapixels
    XML_BOMB_ENTITY_DEPTH: 10
  });

  /**
   * D38 Posture-Bound Resource Quotas Engine.
   * DoS prevention -- blocks ZIP bombs, pixel bombs, oversized payloads.
   */
  class D38Engine {
    constructor() {
      /** @type {Map<string, Map<string, ResourceQuota>>} tenantId -> resourceType -> quota */
      this._quotas = new Map();
      /** @type {Map<string, QuotaViolation[]>} tenantId -> violations */
      this._violations = new Map();
      /** @type {Map<string, number>} tenantId:resourceType -> window start timestamp */
      this._windowStarts = new Map();
    }

    /**
     * Apply a quota profile for a tenant based on posture level.
     * @param {string} tenantId
     * @param {number} postureLevel - 0-5
     */
    setQuotas(tenantId, postureLevel) {
      if (postureLevel < 0 || postureLevel > 5) {
        throw new RangeError('Posture level must be between 0 and 5');
      }

      var profile = QUOTA_PROFILES[postureLevel];
      var quotaMap = new Map();

      var resourceTypes = Object.keys(profile);
      for (var i = 0; i < resourceTypes.length; i++) {
        var rt = resourceTypes[i];
        quotaMap.set(rt, {
          resourceType: rt,
          maxValue: profile[rt],
          currentUsage: 0,
          postureLevel: postureLevel,
          windowMs: 60000, // 1 minute sliding window
          violations: []
        });
      }

      this._quotas.set(tenantId, quotaMap);
      this._violations.set(tenantId, []);
    }

    /**
     * Check if a resource usage request is within quota.
     * @param {string} tenantId
     * @param {string} resourceType
     * @param {number} requestedAmount
     * @returns {{allowed: boolean, remaining: number, limit: number}}
     */
    checkQuota(tenantId, resourceType, requestedAmount) {
      var tenantQuotas = this._quotas.get(tenantId);
      if (!tenantQuotas) {
        return { allowed: false, remaining: 0, limit: 0 };
      }

      var quota = tenantQuotas.get(resourceType);
      if (!quota) {
        return { allowed: false, remaining: 0, limit: 0 };
      }

      // Check sliding window reset
      var windowKey = tenantId + ':' + resourceType;
      var windowStart = this._windowStarts.get(windowKey);
      var currentTime = Date.now();

      if (!windowStart || (currentTime - windowStart) > quota.windowMs) {
        quota.currentUsage = 0;
        this._windowStarts.set(windowKey, currentTime);
      }

      var remaining = quota.maxValue - quota.currentUsage;
      var allowed = requestedAmount <= remaining;

      if (!allowed) {
        var violation = {
          violationId: generateId(),
          tenantId: tenantId,
          resourceType: resourceType,
          requestedAmount: requestedAmount,
          limit: quota.maxValue,
          timestamp: now(),
          blocked: true
        };
        quota.violations.push(violation);
        if (!this._violations.has(tenantId)) {
          this._violations.set(tenantId, []);
        }
        this._violations.get(tenantId).push(violation);
      }

      return {
        allowed: allowed,
        remaining: Math.max(0, remaining),
        limit: quota.maxValue
      };
    }

    /**
     * Record resource usage for a tenant.
     * @param {string} tenantId
     * @param {string} resourceType
     * @param {number} amount
     */
    recordUsage(tenantId, resourceType, amount) {
      var tenantQuotas = this._quotas.get(tenantId);
      if (!tenantQuotas) return;

      var quota = tenantQuotas.get(resourceType);
      if (!quota) return;

      // Check sliding window
      var windowKey = tenantId + ':' + resourceType;
      var windowStart = this._windowStarts.get(windowKey);
      var currentTime = Date.now();

      if (!windowStart || (currentTime - windowStart) > quota.windowMs) {
        quota.currentUsage = 0;
        this._windowStarts.set(windowKey, currentTime);
      }

      quota.currentUsage += amount;
    }

    /**
     * Detect bomb-type payloads (ZIP bombs, pixel bombs, XML bombs).
     * @param {*} data - Data to analyze. Can be ArrayBuffer, Uint8Array, string, or object with metadata.
     * @returns {{detected: boolean, type: string, ratio: number}}
     */
    detectBomb(data) {
      // ZIP bomb detection: check for high compression ratio
      if (data && typeof data === 'object' && data.compressedSize !== undefined && data.decompressedSize !== undefined) {
        var ratio = data.decompressedSize / (data.compressedSize || 1);
        if (ratio > BOMB_THRESHOLDS.ZIP_BOMB_RATIO) {
          return { detected: true, type: 'ZIP_BOMB', ratio: ratio };
        }
      }

      // Pixel bomb detection: check image dimensions
      if (data && typeof data === 'object' && data.width !== undefined && data.height !== undefined) {
        var totalPixels = data.width * data.height;
        if (totalPixels > BOMB_THRESHOLDS.PIXEL_BOMB_PIXELS) {
          return { detected: true, type: 'PIXEL_BOMB', ratio: totalPixels / BOMB_THRESHOLDS.PIXEL_BOMB_PIXELS };
        }
      }

      // XML bomb detection: check for entity expansion patterns
      if (typeof data === 'string') {
        var entityDefs = (data.match(/<!ENTITY/gi) || []).length;
        var entityRefs = (data.match(/&\w+;/g) || []).length;

        if (entityDefs > BOMB_THRESHOLDS.XML_BOMB_ENTITY_DEPTH) {
          return { detected: true, type: 'XML_BOMB', ratio: entityRefs / (entityDefs || 1) };
        }

        // Nested entity expansion (billion laughs)
        if (entityDefs > 3 && entityRefs > 100) {
          return { detected: true, type: 'XML_BOMB', ratio: entityRefs / (entityDefs || 1) };
        }
      }

      return { detected: false, type: '', ratio: 0 };
    }

    /**
     * Get quota status for all resource types for a tenant.
     * @param {string} tenantId
     * @returns {Object<string, ResourceQuota>}
     */
    getQuotaStatus(tenantId) {
      var tenantQuotas = this._quotas.get(tenantId);
      if (!tenantQuotas) return {};

      var status = {};
      tenantQuotas.forEach(function (quota, key) {
        status[key] = {
          resourceType: quota.resourceType,
          maxValue: quota.maxValue,
          currentUsage: quota.currentUsage,
          postureLevel: quota.postureLevel,
          windowMs: quota.windowMs,
          violations: quota.violations.slice()
        };
      });
      return status;
    }

    /**
     * Get violations for a tenant.
     * @param {string} tenantId
     * @returns {QuotaViolation[]}
     */
    getViolations(tenantId) {
      return (this._violations.get(tenantId) || []).slice();
    }

    /**
     * Reset the sliding window for a tenant's resource type.
     * @param {string} tenantId
     * @param {string} resourceType
     */
    resetWindow(tenantId, resourceType) {
      var windowKey = tenantId + ':' + resourceType;
      this._windowStarts.delete(windowKey);

      var tenantQuotas = this._quotas.get(tenantId);
      if (tenantQuotas) {
        var quota = tenantQuotas.get(resourceType);
        if (quota) {
          quota.currentUsage = 0;
        }
      }
    }
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

  // =========================================================================
  // D50: Smart Contract Posture Binding
  // =========================================================================

  /**
   * @typedef {Object} SkillContract
   * @property {string} contractId
   * @property {string} skillName
   * @property {string} skillHash
   * @property {number[]} authorizedPostureLevels
   * @property {string[]} authorizedTenants
   * @property {string[]} authorizedOperations
   * @property {string} grantedBy
   * @property {string} grantedAt
   * @property {string} expiresAt
   * @property {string} signature
   * @property {boolean} revoked
   * @property {number} version
   */

  /**
   * @typedef {Object} ContractVerification
   * @property {string} contractId
   * @property {string} skillName
   * @property {boolean} verified
   * @property {string} reason
   * @property {boolean} signatureValid
   * @property {boolean} postureValid
   * @property {boolean} tenantValid
   * @property {boolean} expired
   * @property {boolean} revoked
   */

  const D50_DOMAIN_PREFIX = 'QERATHEON/contract/skill';

  /**
   * D50 Smart Contract Posture Binding Engine.
   * Cryptographic skill authorization contracts -- skills must have valid signed contracts.
   */
  class D50Engine {
    constructor() {
      /** @type {Map<string, SkillContract>} contractId -> contract */
      this._contracts = new Map();
      /** @type {Map<string, string>} skillName -> contractId (latest) */
      this._skillIndex = new Map();
      /** @type {ContractVerification[]} */
      this._verificationLog = [];
    }

    /**
     * Create a signed skill authorization contract.
     * @param {string} skillName
     * @param {string} skillContent - Raw skill content for hashing
     * @param {number[]} postureLevels - Authorized posture levels
     * @param {string[]} tenantIds - Authorized tenant IDs
     * @param {string[]} operations - Authorized operations
     * @param {string} grantedBy - Identity of the granter
     * @param {number} [ttlHours=24] - Time-to-live in hours
     * @returns {Promise<SkillContract>}
     */
    async createContract(skillName, skillContent, postureLevels, tenantIds, operations, grantedBy, ttlHours) {
      ttlHours = ttlHours || 24;

      var contractId = generateId();
      var skillHash = await sha256(skillContent);
      var grantedAt = now();
      var expiresAt = new Date(Date.now() + ttlHours * 3600000).toISOString();

      // Determine version
      var existingContractId = this._skillIndex.get(skillName);
      var version = 1;
      if (existingContractId) {
        var existing = this._contracts.get(existingContractId);
        if (existing) {
          version = existing.version + 1;
        }
      }

      var sigPayload = [
        D50_DOMAIN_PREFIX, contractId, skillName, skillHash,
        postureLevels.slice().sort().join(','),
        tenantIds.slice().sort().join(','),
        operations.slice().sort().join(','),
        grantedBy, grantedAt, expiresAt, String(version)
      ].join('|');

      var signature = await hmacSign(sigPayload);

      /** @type {SkillContract} */
      var contract = {
        contractId: contractId,
        skillName: skillName,
        skillHash: skillHash,
        authorizedPostureLevels: postureLevels.slice(),
        authorizedTenants: tenantIds.slice(),
        authorizedOperations: operations.slice(),
        grantedBy: grantedBy,
        grantedAt: grantedAt,
        expiresAt: expiresAt,
        signature: signature,
        revoked: false,
        version: version
      };

      this._contracts.set(contractId, contract);
      this._skillIndex.set(skillName, contractId);
      return contract;
    }

    /**
     * Verify a skill's contract for a specific tenant, posture level, and operation.
     * @param {string} skillName
     * @param {string} tenantId
     * @param {number} postureLevel
     * @param {string} operation
     * @returns {Promise<ContractVerification>}
     */
    async verifyContract(skillName, tenantId, postureLevel, operation) {
      var logVerification = function (v, self) {
        self._verificationLog.push(v);
        return v;
      };

      // Find latest contract for skill
      var contractId = this._skillIndex.get(skillName);
      if (!contractId) {
        return logVerification({
          contractId: '',
          skillName: skillName,
          verified: false,
          reason: 'No contract found for skill',
          signatureValid: false,
          postureValid: false,
          tenantValid: false,
          expired: false,
          revoked: false
        }, this);
      }

      var contract = this._contracts.get(contractId);
      if (!contract) {
        return logVerification({
          contractId: contractId,
          skillName: skillName,
          verified: false,
          reason: 'Contract data not found',
          signatureValid: false,
          postureValid: false,
          tenantValid: false,
          expired: false,
          revoked: false
        }, this);
      }

      // Check revoked
      if (contract.revoked) {
        return logVerification({
          contractId: contractId,
          skillName: skillName,
          verified: false,
          reason: 'Contract has been revoked',
          signatureValid: false,
          postureValid: false,
          tenantValid: false,
          expired: false,
          revoked: true
        }, this);
      }

      // Check expired
      var isExpired = new Date(contract.expiresAt) < new Date();
      if (isExpired) {
        return logVerification({
          contractId: contractId,
          skillName: skillName,
          verified: false,
          reason: 'Contract has expired',
          signatureValid: false,
          postureValid: false,
          tenantValid: false,
          expired: true,
          revoked: false
        }, this);
      }

      // Verify signature
      var sigPayload = [
        D50_DOMAIN_PREFIX, contract.contractId, contract.skillName, contract.skillHash,
        contract.authorizedPostureLevels.slice().sort().join(','),
        contract.authorizedTenants.slice().sort().join(','),
        contract.authorizedOperations.slice().sort().join(','),
        contract.grantedBy, contract.grantedAt, contract.expiresAt, String(contract.version)
      ].join('|');

      var signatureValid = await hmacVerify(sigPayload, contract.signature);
      if (!signatureValid) {
        return logVerification({
          contractId: contractId,
          skillName: skillName,
          verified: false,
          reason: 'Contract signature verification failed',
          signatureValid: false,
          postureValid: false,
          tenantValid: false,
          expired: false,
          revoked: false
        }, this);
      }

      // Posture check
      var postureValid = contract.authorizedPostureLevels.indexOf(postureLevel) !== -1;
      if (!postureValid) {
        return logVerification({
          contractId: contractId,
          skillName: skillName,
          verified: false,
          reason: 'Posture level ' + postureLevel + ' not authorized. Allowed: [' + contract.authorizedPostureLevels.join(', ') + ']',
          signatureValid: true,
          postureValid: false,
          tenantValid: false,
          expired: false,
          revoked: false
        }, this);
      }

      // Tenant check
      var tenantValid = contract.authorizedTenants.length === 0 || contract.authorizedTenants.indexOf(tenantId) !== -1;
      if (!tenantValid) {
        return logVerification({
          contractId: contractId,
          skillName: skillName,
          verified: false,
          reason: 'Tenant ' + tenantId + ' not authorized',
          signatureValid: true,
          postureValid: true,
          tenantValid: false,
          expired: false,
          revoked: false
        }, this);
      }

      // Operation check
      var operationValid = contract.authorizedOperations.indexOf(operation) !== -1;
      if (!operationValid) {
        return logVerification({
          contractId: contractId,
          skillName: skillName,
          verified: false,
          reason: 'Operation "' + operation + '" not authorized. Allowed: [' + contract.authorizedOperations.join(', ') + ']',
          signatureValid: true,
          postureValid: true,
          tenantValid: true,
          expired: false,
          revoked: false
        }, this);
      }

      return logVerification({
        contractId: contractId,
        skillName: skillName,
        verified: true,
        reason: 'Contract verification passed',
        signatureValid: true,
        postureValid: true,
        tenantValid: true,
        expired: false,
        revoked: false
      }, this);
    }

    /**
     * Revoke a contract.
     * @param {string} contractId
     * @param {string} reason
     */
    revokeContract(contractId, reason) {
      var contract = this._contracts.get(contractId);
      if (!contract) {
        throw new Error('Contract not found: ' + contractId);
      }
      contract.revoked = true;

      this._verificationLog.push({
        contractId: contractId,
        skillName: contract.skillName,
        verified: false,
        reason: 'Contract revoked: ' + (reason || 'No reason provided'),
        signatureValid: false,
        postureValid: false,
        tenantValid: false,
        expired: false,
        revoked: true
      });
    }

    /**
     * Renew a contract with a new TTL.
     * @param {string} contractId
     * @param {number} newTtlHours
     * @returns {Promise<SkillContract>}
     */
    async renewContract(contractId, newTtlHours) {
      var contract = this._contracts.get(contractId);
      if (!contract) {
        throw new Error('Contract not found: ' + contractId);
      }
      if (contract.revoked) {
        throw new Error('Cannot renew a revoked contract');
      }

      contract.expiresAt = new Date(Date.now() + newTtlHours * 3600000).toISOString();
      contract.version += 1;

      // Re-sign
      var sigPayload = [
        D50_DOMAIN_PREFIX, contract.contractId, contract.skillName, contract.skillHash,
        contract.authorizedPostureLevels.slice().sort().join(','),
        contract.authorizedTenants.slice().sort().join(','),
        contract.authorizedOperations.slice().sort().join(','),
        contract.grantedBy, contract.grantedAt, contract.expiresAt, String(contract.version)
      ].join('|');

      contract.signature = await hmacSign(sigPayload);
      return contract;
    }

    /**
     * Get all contracts.
     * @returns {SkillContract[]}
     */
    getContractInventory() {
      return Array.from(this._contracts.values());
    }

    /**
     * Get the verification log.
     * @returns {ContractVerification[]}
     */
    getVerificationLog() {
      return this._verificationLog.slice();
    }
  }

  // =========================================================================
  // Module Export
  // =========================================================================

  var _d33 = null;
  var _d35 = null;
  var _d36 = null;
  var _d38 = null;
  var _d43 = null;
  var _d50 = null;
  var _initialized = false;

  /** @namespace */
  var StaamlLayer3 = {
    VERSION: '1.0.0',

    /** Shared enums and constants */
    PostureLevel: PostureLevel,
    POSTURE_NAMES: POSTURE_NAMES,
    SkillPosture: SkillPosture,
    FileOperation: FileOperation,
    ResourceType: ResourceType,
    EndpointCategory: EndpointCategory,
    QUOTA_PROFILES: QUOTA_PROFILES,

    /**
     * Initialize the Layer 3 module with a master HMAC key.
     * Must be called before any cryptographic operations.
     * @param {string} masterKey - Key material for HMAC-SHA256
     * @returns {Promise<void>}
     */
    init: async function (masterKey) {
      if (!masterKey || typeof masterKey !== 'string') {
        throw new Error('masterKey must be a non-empty string');
      }

      _hmacKey = await importHmacKey(masterKey);

      _d33 = new D33Engine();
      _d35 = new D35Engine();
      _d36 = new D36Engine();
      _d38 = new D38Engine();
      _d43 = new D43Engine();
      _d50 = new D50Engine();

      _initialized = true;
      console.log('[STAAML Layer 3] Infrastructure Security initialized (v' + StaamlLayer3.VERSION + ')');
    },

    /** @type {D33Engine} Posture-Aware Execution Gate */
    get D33() {
      if (!_initialized) throw new Error('StaamlLayer3 not initialized. Call init(masterKey) first.');
      return _d33;
    },

    /** @type {D35Engine} Posture-Bound Filesystem Attestation */
    get D35() {
      if (!_initialized) throw new Error('StaamlLayer3 not initialized. Call init(masterKey) first.');
      return _d35;
    },

    /** @type {D36Engine} Runtime Environment Attestation */
    get D36() {
      if (!_initialized) throw new Error('StaamlLayer3 not initialized. Call init(masterKey) first.');
      return _d36;
    },

    /** @type {D38Engine} Posture-Bound Resource Quotas */
    get D38() {
      if (!_initialized) throw new Error('StaamlLayer3 not initialized. Call init(masterKey) first.');
      return _d38;
    },

    /** @type {D43Engine} Network Posture Binding */
    get D43() {
      if (!_initialized) throw new Error('StaamlLayer3 not initialized. Call init(masterKey) first.');
      return _d43;
    },

    /** @type {D50Engine} Smart Contract Posture Binding */
    get D50() {
      if (!_initialized) throw new Error('StaamlLayer3 not initialized. Call init(masterKey) first.');
      return _d50;
    },

    /**
     * Get the overall status of the Layer 3 module.
     * @returns {Object}
     */
    getStatus: function () {
      return {
        version: StaamlLayer3.VERSION,
        initialized: _initialized,
        derivatives: {
          D33: { name: 'Posture-Aware Execution Gate', ready: !!_d33 },
          D35: { name: 'Posture-Bound Filesystem Attestation', ready: !!_d35 },
          D36: { name: 'Runtime Environment Attestation', ready: !!_d36 },
          D38: { name: 'Posture-Bound Resource Quotas', ready: !!_d38 },
          D43: { name: 'Network Posture Binding', ready: !!_d43 },
          D50: { name: 'Smart Contract Posture Binding', ready: !!_d50 }
        },
        cryptoAvailable: typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined'
      };
    }
  };

  // Expose on window
  if (typeof window !== 'undefined') {
    window.StaamlLayer3 = StaamlLayer3;
  }

  // Support CommonJS/Node for testing
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = StaamlLayer3;
  }
})();
