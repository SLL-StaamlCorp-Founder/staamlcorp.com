'use strict';

/**
 * STAAML Layer 2 Governance Derivatives
 * Posture-bound governance controls for staaml.com
 *
 * Derivatives implemented:
 *   D34 - Posture-Bound Session Attestation
 *   D37 - Posture-Bound Token Lifecycle
 *   D48 - Multi-Tenant Posture Isolation
 *   D49 - Posture-Aware ML Model Cache
 *   D58 - AI Agent Behavioral Fingerprinting
 *
 * All cryptographic operations use Web Crypto API.
 * No external dependencies.
 *
 * @version 1.0.0
 * @license Proprietary - Staaml
 */
(function (globalThis) {

  // ---------------------------------------------------------------------------
  // Shared helpers
  // ---------------------------------------------------------------------------

  const _encoder = new TextEncoder();
  const _decoder = new TextDecoder();

  /**
   * Generate a hex-encoded random string.
   * @param {number} bytes - Number of random bytes.
   * @returns {string}
   */
  function randomHex(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Generate a UUID v4.
   * @returns {string}
   */
  function uuid() {
    const h = randomHex(16).split('');
    h[12] = '4';
    h[16] = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
    return [
      h.slice(0, 8).join(''),
      h.slice(8, 12).join(''),
      h.slice(12, 16).join(''),
      h.slice(16, 20).join(''),
      h.slice(20, 32).join('')
    ].join('-');
  }

  /**
   * Import raw key bytes for HMAC-SHA-256.
   * @param {string} key - Hex-encoded key.
   * @returns {Promise<CryptoKey>}
   */
  async function importHmacKey(key) {
    const raw = new Uint8Array(key.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    return crypto.subtle.importKey(
      'raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
    );
  }

  /**
   * HMAC-SHA-256 sign and return hex string.
   * @param {CryptoKey} key
   * @param {string} data
   * @returns {Promise<string>}
   */
  async function hmacSign(key, data) {
    const sig = await crypto.subtle.sign('HMAC', key, _encoder.encode(data));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * HMAC-SHA-256 verify.
   * @param {CryptoKey} key
   * @param {string} data
   * @param {string} signatureHex
   * @returns {Promise<boolean>}
   */
  async function hmacVerify(key, data, signatureHex) {
    const sigBytes = new Uint8Array(signatureHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    return crypto.subtle.verify('HMAC', key, sigBytes, _encoder.encode(data));
  }

  /**
   * SHA-256 hash of a string, returned as hex.
   * @param {string} data
   * @returns {Promise<string>}
   */
  async function sha256(data) {
    const digest = await crypto.subtle.digest('SHA-256', _encoder.encode(data));
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Current epoch time in seconds.
   * @returns {number}
   */
  function now() {
    return Math.floor(Date.now() / 1000);
  }

  // ---------------------------------------------------------------------------
  // PostureLevel Enum
  // ---------------------------------------------------------------------------

  /**
   * @readonly
   * @enum {number}
   */
  const PostureLevel = Object.freeze({
    UNTRUSTED:  0,
    RESTRICTED: 1,
    STANDARD:   2,
    ELEVATED:   3,
    PRIVILEGED: 4,
    CRITICAL:   5
  });

  // ---------------------------------------------------------------------------
  // D34 -- Posture-Bound Session Attestation
  // ---------------------------------------------------------------------------

  /**
   * @readonly
   * @enum {string}
   */
  const AttestationVerdict = Object.freeze({
    VALID:                'VALID',
    EXPIRED:              'EXPIRED',
    INVALID_SIGNATURE:    'INVALID_SIGNATURE',
    INVALID_TENANT:       'INVALID_TENANT',
    POSTURE_INSUFFICIENT: 'POSTURE_INSUFFICIENT',
    REPLAY_DETECTED:      'REPLAY_DETECTED',
    SCOPE_VIOLATION:      'SCOPE_VIOLATION',
    REQUEST_MISMATCH:     'REQUEST_MISMATCH',
    REVOKED:              'REVOKED',
    MISSING:              'MISSING'
  });

  /**
   * @readonly
   * @enum {string}
   */
  const RequestClass = Object.freeze({
    READ_PUBLIC:      'READ_PUBLIC',
    READ_PHI:         'READ_PHI',
    WRITE_PHI:        'WRITE_PHI',
    SESSION_MGMT:     'SESSION_MGMT',
    CONFIG_CHANGE:    'CONFIG_CHANGE',
    DEVICE_PAIR:      'DEVICE_PAIR',
    SKILL_EXEC:       'SKILL_EXEC',
    MODEL_INFERENCE:  'MODEL_INFERENCE',
    ADMIN:            'ADMIN',
    AGENT_DISPATCH:   'AGENT_DISPATCH'
  });

  /**
   * Minimum posture required per request class.
   * @type {Object<string,number>}
   */
  const REQUEST_POSTURE_MAP = Object.freeze({
    [RequestClass.READ_PUBLIC]:     1,
    [RequestClass.READ_PHI]:        3,
    [RequestClass.WRITE_PHI]:       4,
    [RequestClass.SESSION_MGMT]:    3,
    [RequestClass.CONFIG_CHANGE]:   5,
    [RequestClass.DEVICE_PAIR]:     4,
    [RequestClass.SKILL_EXEC]:      2,
    [RequestClass.MODEL_INFERENCE]: 3,
    [RequestClass.ADMIN]:           5,
    [RequestClass.AGENT_DISPATCH]:  3
  });

  /** Maximum tokens per minute per session. */
  const D34_RATE_LIMIT = 60;

  /**
   * Represents a signed attestation token.
   * @class
   */
  class AttestationToken {
    /**
     * @param {Object} opts
     * @param {string} opts.tokenId
     * @param {string} opts.sessionId
     * @param {string} opts.tenantId
     * @param {number} opts.postureLevel
     * @param {number} opts.issuedAt
     * @param {number} opts.expiresAt
     * @param {string} opts.nonce
     * @param {string} opts.requestHash
     * @param {string} opts.requestClass
     * @param {string} opts.signature
     * @param {string[]} opts.permittedScopes
     * @param {string[]} opts.permittedEndpoints
     * @param {string} opts.sourceIp
     * @param {string} opts.userAgentHash
     * @param {string} opts.deviceFingerprint
     */
    constructor(opts) {
      this.tokenId           = opts.tokenId;
      this.sessionId         = opts.sessionId;
      this.tenantId          = opts.tenantId;
      this.postureLevel      = opts.postureLevel;
      this.issuedAt          = opts.issuedAt;
      this.expiresAt         = opts.expiresAt;
      this.nonce             = opts.nonce;
      this.requestHash       = opts.requestHash;
      this.requestClass      = opts.requestClass;
      this.signature         = opts.signature;
      this.permittedScopes   = opts.permittedScopes;
      this.permittedEndpoints = opts.permittedEndpoints;
      this.sourceIp          = opts.sourceIp;
      this.userAgentHash     = opts.userAgentHash;
      this.deviceFingerprint = opts.deviceFingerprint;
    }

    /**
     * Build the canonical payload string used for signing.
     * @returns {string}
     */
    sigPayload() {
      return [
        this.sessionId,
        this.tenantId,
        this.postureLevel,
        this.issuedAt,
        this.expiresAt,
        this.nonce,
        this.requestHash,
        this.requestClass,
        this.sourceIp,
        this.userAgentHash,
        this.deviceFingerprint
      ].join('|');
    }
  }

  /**
   * Tracks a session for attestation purposes.
   * @class
   */
  class AttestationSession {
    /**
     * @param {Object} opts
     * @param {string} opts.sessionId
     * @param {string} opts.tenantId
     * @param {number} opts.postureLevel
     * @param {string} opts.sourceIp
     * @param {string} opts.userAgentHash
     * @param {string} opts.deviceFingerprint
     */
    constructor(opts) {
      this.sessionId        = opts.sessionId;
      this.tenantId         = opts.tenantId;
      this.postureLevel     = opts.postureLevel;
      this.createdAt        = now();
      this.lastAttestedAt   = null;
      this.sourceIp         = opts.sourceIp;
      this.userAgentHash    = opts.userAgentHash;
      this.deviceFingerprint = opts.deviceFingerprint;
      this.isActive         = true;
      this.tokensIssued     = 0;
      this.tokensRejected   = 0;
      this.requestsAttested = 0;
      this.maxPermittedScopes = [];
      /** @type {{ timestamp: number, count: number }} */
      this._rateWindow      = { timestamp: now(), count: 0 };
    }

    /**
     * Check and increment the per-minute rate limiter.
     * @returns {boolean} true if within rate limit
     */
    checkRateLimit() {
      const t = now();
      if (t - this._rateWindow.timestamp >= 60) {
        this._rateWindow = { timestamp: t, count: 0 };
      }
      if (this._rateWindow.count >= D34_RATE_LIMIT) {
        return false;
      }
      this._rateWindow.count++;
      return true;
    }
  }

  /**
   * Builds and verifies attestation tokens.
   * @class
   */
  class AttestationTokenBuilder {
    /**
     * @param {string} masterKeyHex - Hex-encoded master key.
     * @param {number} [tokenTtl=30] - Token time-to-live in seconds.
     */
    constructor(masterKeyHex, tokenTtl = 30) {
      /** @type {string} */
      this._masterKeyHex = masterKeyHex;
      /** @type {number} */
      this.tokenTtl = tokenTtl;
      /** @type {CryptoKey|null} */
      this._cryptoKey = null;
    }

    /**
     * Lazily initialise the CryptoKey.
     * @returns {Promise<CryptoKey>}
     */
    async _key() {
      if (!this._cryptoKey) {
        this._cryptoKey = await importHmacKey(this._masterKeyHex);
      }
      return this._cryptoKey;
    }

    /**
     * Build an attestation token for the given session and request.
     * @param {AttestationSession} session
     * @param {string} requestHash
     * @param {string} requestClass
     * @param {string[]} scopes
     * @param {string[]} endpoints
     * @returns {Promise<AttestationToken>}
     */
    async buildToken(session, requestHash, requestClass, scopes, endpoints) {
      const t = now();
      const token = new AttestationToken({
        tokenId:           uuid(),
        sessionId:         session.sessionId,
        tenantId:          session.tenantId,
        postureLevel:      session.postureLevel,
        issuedAt:          t,
        expiresAt:         t + this.tokenTtl,
        nonce:             randomHex(16),
        requestHash:       requestHash,
        requestClass:      requestClass,
        signature:         '',
        permittedScopes:   scopes || [],
        permittedEndpoints: endpoints || [],
        sourceIp:          session.sourceIp,
        userAgentHash:     session.userAgentHash,
        deviceFingerprint: session.deviceFingerprint
      });
      token.signature = await this.signToken(token);
      return token;
    }

    /**
     * Produce the HMAC-SHA-256 signature for a token.
     * @param {AttestationToken} token
     * @returns {Promise<string>} Hex-encoded signature.
     */
    async signToken(token) {
      const key = await this._key();
      return hmacSign(key, token.sigPayload());
    }

    /**
     * Verify a token's HMAC-SHA-256 signature.
     * @param {AttestationToken} token
     * @returns {Promise<boolean>}
     */
    async verifyToken(token) {
      const key = await this._key();
      return hmacVerify(key, token.sigPayload(), token.signature);
    }
  }

  /**
   * D34 Engine -- Posture-Bound Session Attestation.
   * Manages sessions, issues per-request attestation tokens, and logs violations.
   * @class
   */
  class D34Engine {
    /**
     * @param {string} masterKeyHex - Hex-encoded master key.
     * @param {number} [tokenTtl=30]
     */
    constructor(masterKeyHex, tokenTtl = 30) {
      /** @type {Map<string, AttestationSession>} */
      this._sessions = new Map();
      /** @type {AttestationTokenBuilder} */
      this._builder = new AttestationTokenBuilder(masterKeyHex, tokenTtl);
      /** @type {Set<string>} */
      this._usedNonces = new Set();
      /** @type {Array<Object>} */
      this._violations = [];
    }

    /**
     * Create a new attestation session.
     * @param {string} tenantId
     * @param {number} postureLevel
     * @param {string} sourceIp
     * @param {string} userAgent
     * @param {string} deviceFingerprint
     * @returns {Promise<AttestationSession>}
     */
    async createSession(tenantId, postureLevel, sourceIp, userAgent, deviceFingerprint) {
      const userAgentHash = await sha256(userAgent || '');
      const session = new AttestationSession({
        sessionId:        uuid(),
        tenantId:         tenantId,
        postureLevel:     postureLevel,
        sourceIp:         sourceIp,
        userAgentHash:    userAgentHash,
        deviceFingerprint: deviceFingerprint || ''
      });
      this._sessions.set(session.sessionId, session);
      return session;
    }

    /**
     * Attest a request within an existing session.
     * @param {string} sessionId
     * @param {string} requestPath
     * @param {string} requestClass - One of RequestClass values.
     * @param {*} body - Request body (will be JSON-stringified for hashing).
     * @param {string[]} [scopes=[]]
     * @param {string[]} [endpoints=[]]
     * @returns {Promise<{verdict: string, token: AttestationToken|null}>}
     */
    async attestRequest(sessionId, requestPath, requestClass, body, scopes, endpoints) {
      const session = this._sessions.get(sessionId);
      if (!session) {
        return { verdict: AttestationVerdict.MISSING, token: null };
      }
      if (!session.isActive) {
        return { verdict: AttestationVerdict.REVOKED, token: null };
      }

      // Rate limit
      if (!session.checkRateLimit()) {
        session.tokensRejected++;
        this._logViolation(session.tenantId, sessionId, 'RATE_LIMIT_EXCEEDED', requestClass);
        return { verdict: AttestationVerdict.REPLAY_DETECTED, token: null };
      }

      // Posture check
      const required = REQUEST_POSTURE_MAP[requestClass];
      if (required === undefined || session.postureLevel < required) {
        session.tokensRejected++;
        this._logViolation(session.tenantId, sessionId, 'POSTURE_INSUFFICIENT', requestClass);
        return { verdict: AttestationVerdict.POSTURE_INSUFFICIENT, token: null };
      }

      // Scope check
      if (scopes && session.maxPermittedScopes.length > 0) {
        const disallowed = scopes.filter(s => !session.maxPermittedScopes.includes(s));
        if (disallowed.length > 0) {
          session.tokensRejected++;
          this._logViolation(session.tenantId, sessionId, 'SCOPE_VIOLATION', requestClass);
          return { verdict: AttestationVerdict.SCOPE_VIOLATION, token: null };
        }
      }

      const requestHash = await sha256(JSON.stringify({ path: requestPath, body: body || '' }));
      const token = await this._builder.buildToken(
        session, requestHash, requestClass, scopes || [], endpoints || []
      );

      // Track nonce for replay detection
      this._usedNonces.add(token.nonce);

      session.tokensIssued++;
      session.requestsAttested++;
      session.lastAttestedAt = now();

      return { verdict: AttestationVerdict.VALID, token: token };
    }

    /**
     * Verify a previously-issued token.
     * @param {AttestationToken} token
     * @returns {Promise<{verdict: string}>}
     */
    async verifyAttestation(token) {
      if (!token) {
        return { verdict: AttestationVerdict.MISSING };
      }
      const session = this._sessions.get(token.sessionId);
      if (!session) {
        return { verdict: AttestationVerdict.MISSING };
      }
      if (!session.isActive) {
        return { verdict: AttestationVerdict.REVOKED };
      }
      if (now() > token.expiresAt) {
        return { verdict: AttestationVerdict.EXPIRED };
      }
      const sigValid = await this._builder.verifyToken(token);
      if (!sigValid) {
        return { verdict: AttestationVerdict.INVALID_SIGNATURE };
      }
      if (token.tenantId !== session.tenantId) {
        return { verdict: AttestationVerdict.INVALID_TENANT };
      }
      return { verdict: AttestationVerdict.VALID };
    }

    /**
     * Revoke a session.
     * @param {string} sessionId
     * @param {string} reason
     */
    revokeSession(sessionId, reason) {
      const session = this._sessions.get(sessionId);
      if (session) {
        session.isActive = false;
        this._logViolation(session.tenantId, sessionId, 'SESSION_REVOKED', reason);
      }
    }

    /**
     * Retrieve violations for a tenant.
     * @param {string} tenantId
     * @returns {Array<Object>}
     */
    getViolations(tenantId) {
      return this._violations.filter(v => v.tenantId === tenantId);
    }

    /**
     * @private
     * @param {string} tenantId
     * @param {string} sessionId
     * @param {string} type
     * @param {string} detail
     */
    _logViolation(tenantId, sessionId, type, detail) {
      this._violations.push({
        tenantId:  tenantId,
        sessionId: sessionId,
        type:      type,
        detail:    detail,
        timestamp: now()
      });
    }
  }

  // ---------------------------------------------------------------------------
  // D37 -- Posture-Bound Token Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * TTL per posture level in seconds.
   * @type {Object<number,number>}
   */
  const D37_TTL_MAP = Object.freeze({
    [PostureLevel.UNTRUSTED]:  0,
    [PostureLevel.RESTRICTED]: 300,
    [PostureLevel.STANDARD]:   900,
    [PostureLevel.ELEVATED]:   600,
    [PostureLevel.PRIVILEGED]: 300,
    [PostureLevel.CRITICAL]:   120
  });

  /**
   * A lifecycle-managed token.
   * @class
   */
  class D37Token {
    /**
     * @param {Object} opts
     * @param {string} opts.id
     * @param {string} opts.tenantId
     * @param {number} opts.postureLevel
     * @param {string[]} opts.scopes
     * @param {string} opts.deviceFingerprint
     * @param {number} opts.issuedAt
     * @param {number} opts.expiresAt
     * @param {number} opts.refreshCount
     * @param {number} opts.maxRefreshes
     * @param {string|null} opts.parentTokenId
     */
    constructor(opts) {
      this.id                = opts.id;
      this.tenantId          = opts.tenantId;
      this.postureLevel      = opts.postureLevel;
      this.scopes            = opts.scopes;
      this.deviceFingerprint = opts.deviceFingerprint;
      this.issuedAt          = opts.issuedAt;
      this.expiresAt         = opts.expiresAt;
      this.refreshCount      = opts.refreshCount;
      this.maxRefreshes      = opts.maxRefreshes;
      this.parentTokenId     = opts.parentTokenId;
      this.revoked           = false;
      this.revokedReason     = null;
    }
  }

  /**
   * D37 Engine -- Posture-Bound Token Lifecycle.
   * Prevents privilege escalation via scope widening and enforces device binding.
   * @class
   */
  class D37Engine {
    /**
     * @param {string} masterKeyHex
     */
    constructor(masterKeyHex) {
      /** @type {string} */
      this._masterKeyHex = masterKeyHex;
      /** @type {Map<string, D37Token>} */
      this._tokens = new Map();
      /** @type {Array<Object>} */
      this._violations = [];
    }

    /**
     * Issue a new token bound to posture and device.
     * @param {string} tenantId
     * @param {number} postureLevel
     * @param {string[]} scopes
     * @param {string} deviceFingerprint
     * @param {number} [maxRefreshes=5]
     * @returns {D37Token|null} null if UNTRUSTED posture
     */
    issueToken(tenantId, postureLevel, scopes, deviceFingerprint, maxRefreshes = 5) {
      const ttl = D37_TTL_MAP[postureLevel];
      if (ttl === undefined || ttl === 0) {
        return null;
      }
      const t = now();
      const token = new D37Token({
        id:                uuid(),
        tenantId:          tenantId,
        postureLevel:      postureLevel,
        scopes:            Array.isArray(scopes) ? [...scopes] : [],
        deviceFingerprint: deviceFingerprint,
        issuedAt:          t,
        expiresAt:         t + ttl,
        refreshCount:      0,
        maxRefreshes:      maxRefreshes,
        parentTokenId:     null
      });
      this._tokens.set(token.id, token);
      return token;
    }

    /**
     * Validate an existing token against current posture and device.
     * @param {string} tokenId
     * @param {number} currentPosture
     * @param {string} currentDevice
     * @returns {{valid: boolean, reason: string}}
     */
    validateToken(tokenId, currentPosture, currentDevice) {
      const token = this._tokens.get(tokenId);
      if (!token) {
        return { valid: false, reason: 'TOKEN_NOT_FOUND' };
      }
      if (token.revoked) {
        return { valid: false, reason: 'TOKEN_REVOKED' };
      }
      if (now() > token.expiresAt) {
        return { valid: false, reason: 'TOKEN_EXPIRED' };
      }
      if (currentPosture < token.postureLevel) {
        this._logViolation(token.tenantId, tokenId, 'POSTURE_DOWNGRADE');
        return { valid: false, reason: 'POSTURE_DOWNGRADE' };
      }
      if (currentDevice !== token.deviceFingerprint) {
        this._logViolation(token.tenantId, tokenId, 'DEVICE_MISMATCH');
        return { valid: false, reason: 'DEVICE_MISMATCH' };
      }
      return { valid: true, reason: 'OK' };
    }

    /**
     * Refresh a token, revalidating posture and device. The original is revoked.
     * @param {string} tokenId
     * @param {number} currentPosture
     * @param {string} currentDevice
     * @returns {{token: D37Token|null, reason: string}}
     */
    refreshToken(tokenId, currentPosture, currentDevice) {
      const validation = this.validateToken(tokenId, currentPosture, currentDevice);
      if (!validation.valid) {
        return { token: null, reason: validation.reason };
      }
      const old = this._tokens.get(tokenId);
      if (old.refreshCount >= old.maxRefreshes) {
        return { token: null, reason: 'MAX_REFRESHES_EXCEEDED' };
      }

      // Detect scope widening: new posture must not exceed original
      const ttl = D37_TTL_MAP[currentPosture] || 0;
      if (ttl === 0) {
        return { token: null, reason: 'POSTURE_TTL_ZERO' };
      }

      const t = now();
      const newToken = new D37Token({
        id:                uuid(),
        tenantId:          old.tenantId,
        postureLevel:      currentPosture,
        scopes:            [...old.scopes],
        deviceFingerprint: currentDevice,
        issuedAt:          t,
        expiresAt:         t + ttl,
        refreshCount:      old.refreshCount + 1,
        maxRefreshes:      old.maxRefreshes,
        parentTokenId:     old.id
      });

      // Revoke old
      old.revoked = true;
      old.revokedReason = 'REFRESHED';

      this._tokens.set(newToken.id, newToken);
      return { token: newToken, reason: 'OK' };
    }

    /**
     * Revoke a token.
     * @param {string} tokenId
     * @param {string} reason
     */
    revokeToken(tokenId, reason) {
      const token = this._tokens.get(tokenId);
      if (token) {
        token.revoked = true;
        token.revokedReason = reason;
      }
    }

    /**
     * Detect whether requested scopes represent a widening beyond original scopes
     * at the given posture level.
     * @param {string[]} requestedScopes
     * @param {string[]} originalScopes
     * @param {number} postureLevel
     * @returns {boolean} true if scope widening is detected
     */
    detectScopeWidening(requestedScopes, originalScopes, postureLevel) {
      const originalSet = new Set(originalScopes);
      const widened = requestedScopes.filter(s => !originalSet.has(s));
      if (widened.length > 0) {
        this._logViolation('', '', 'SCOPE_WIDENING_ATTEMPT');
        return true;
      }
      return false;
    }

    /** @private */
    _logViolation(tenantId, tokenId, type) {
      this._violations.push({ tenantId, tokenId, type, timestamp: now() });
    }

    /**
     * Return all recorded violations.
     * @returns {Array<Object>}
     */
    getViolations() {
      return [...this._violations];
    }
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

  // ---------------------------------------------------------------------------
  // D49 -- Posture-Aware ML Model Cache
  // ---------------------------------------------------------------------------

  /**
   * @readonly
   * @enum {string}
   */
  const AIRiskLevel = Object.freeze({
    UNACCEPTABLE: 'UNACCEPTABLE',
    HIGH:         'HIGH',
    LIMITED:      'LIMITED',
    MINIMAL:      'MINIMAL'
  });

  /**
   * @readonly
   * @enum {string}
   */
  const ModelType = Object.freeze({
    CLASSIFICATION: 'CLASSIFICATION',
    GENERATION:     'GENERATION',
    EMBEDDING:      'EMBEDDING',
    AGENT:          'AGENT'
  });

  /**
   * EU AI Act article references per risk level.
   * @type {Object<string, string>}
   */
  const EU_AI_ACT_REFS = Object.freeze({
    [AIRiskLevel.UNACCEPTABLE]: 'Article 5 - Prohibited AI practices',
    [AIRiskLevel.HIGH]:         'Article 6-51 - High-risk AI systems',
    [AIRiskLevel.LIMITED]:      'Article 52 - Transparency obligations',
    [AIRiskLevel.MINIMAL]:      'Article 69 - Codes of conduct'
  });

  /**
   * A registered ML model with consent and posture binding.
   * @class
   */
  class ModelRegistration {
    /**
     * @param {Object} opts
     * @param {string} opts.modelId
     * @param {string} opts.modelHash
     * @param {string} opts.modelType
     * @param {string} opts.riskLevel
     * @param {string[]} opts.consentIds
     * @param {number} opts.postureAtCache
     */
    constructor(opts) {
      this.modelId        = opts.modelId;
      this.modelHash      = opts.modelHash;
      this.modelType      = opts.modelType;
      this.riskLevel      = opts.riskLevel;
      this.consentIds     = opts.consentIds || [];
      this.cachedAt       = now();
      this.postureAtCache = opts.postureAtCache;
      this.validated      = true;
      this.lastValidated  = now();
    }
  }

  /**
   * D49 Engine -- Posture-Aware ML Model Cache.
   * Manages model registrations with EU AI Act risk classification
   * and consent-bound caching.
   * @class
   */
  class D49Engine {
    constructor() {
      /** @type {Map<string, ModelRegistration>} */
      this._models = new Map();
      /** @type {Array<Object>} */
      this._events = [];
    }

    /**
     * Register a model in the cache.
     * @param {string} modelId
     * @param {string} modelHash
     * @param {string} modelType - One of ModelType values.
     * @param {string} riskLevel - One of AIRiskLevel values.
     * @param {string[]} consentIds
     * @param {number} [postureAtCache=2]
     * @returns {ModelRegistration}
     */
    registerModel(modelId, modelHash, modelType, riskLevel, consentIds, postureAtCache = 2) {
      if (riskLevel === AIRiskLevel.UNACCEPTABLE) {
        this._logEvent(modelId, 'REGISTRATION_BLOCKED', 'Unacceptable risk level under EU AI Act');
        throw new Error(
          'Cannot register model with UNACCEPTABLE risk level. ' +
          EU_AI_ACT_REFS[AIRiskLevel.UNACCEPTABLE]
        );
      }
      const reg = new ModelRegistration({
        modelId, modelHash, modelType, riskLevel, consentIds, postureAtCache
      });
      this._models.set(modelId, reg);
      this._logEvent(modelId, 'REGISTERED', 'Risk: ' + riskLevel);
      return reg;
    }

    /**
     * Validate a model against current posture and consent state.
     * @param {string} modelId
     * @param {number} currentPosture
     * @param {string[]} currentConsents - Currently active consent IDs.
     * @returns {{valid: boolean, reason: string, riskLevel: string|null, euRef: string|null}}
     */
    validateModel(modelId, currentPosture, currentConsents) {
      const reg = this._models.get(modelId);
      if (!reg) {
        return { valid: false, reason: 'MODEL_NOT_FOUND', riskLevel: null, euRef: null };
      }
      if (!reg.validated) {
        return {
          valid: false,
          reason: 'MODEL_INVALIDATED',
          riskLevel: reg.riskLevel,
          euRef: EU_AI_ACT_REFS[reg.riskLevel] || null
        };
      }
      if (currentPosture < reg.postureAtCache) {
        return {
          valid: false,
          reason: 'POSTURE_INSUFFICIENT',
          riskLevel: reg.riskLevel,
          euRef: EU_AI_ACT_REFS[reg.riskLevel] || null
        };
      }
      // Check consent coverage
      const currentSet = new Set(currentConsents);
      const missingConsents = reg.consentIds.filter(c => !currentSet.has(c));
      if (missingConsents.length > 0) {
        return {
          valid: false,
          reason: 'CONSENT_MISSING',
          riskLevel: reg.riskLevel,
          euRef: EU_AI_ACT_REFS[reg.riskLevel] || null
        };
      }
      reg.lastValidated = now();
      return {
        valid: true,
        reason: 'OK',
        riskLevel: reg.riskLevel,
        euRef: EU_AI_ACT_REFS[reg.riskLevel] || null
      };
    }

    /**
     * Handle consent revocation -- invalidate all models bound to that consent.
     * @param {string} consentId
     * @returns {string[]} IDs of invalidated models.
     */
    onConsentRevocation(consentId) {
      const invalidated = [];
      for (const [id, reg] of this._models) {
        if (reg.consentIds.includes(consentId)) {
          reg.validated = false;
          invalidated.push(id);
          this._logEvent(id, 'CONSENT_REVOKED', 'Consent: ' + consentId);
        }
      }
      return invalidated;
    }

    /**
     * Handle a posture transition -- revalidate all models.
     * @param {number} newPosture
     * @returns {{revalidated: number, invalidated: string[]}}
     */
    onPolicyTransition(newPosture) {
      const invalidated = [];
      let revalidated = 0;
      for (const [id, reg] of this._models) {
        revalidated++;
        if (newPosture < reg.postureAtCache) {
          reg.validated = false;
          invalidated.push(id);
          this._logEvent(id, 'POSTURE_TRANSITION_INVALIDATED', 'New posture: ' + newPosture);
        } else {
          reg.lastValidated = now();
        }
      }
      return { revalidated, invalidated };
    }

    /**
     * Return all model registrations.
     * @returns {ModelRegistration[]}
     */
    getModelInventory() {
      return Array.from(this._models.values());
    }

    /** @private */
    _logEvent(modelId, type, detail) {
      this._events.push({ modelId, type, detail, timestamp: now() });
    }

    /**
     * Return all logged events.
     * @returns {Array<Object>}
     */
    getEvents() {
      return [...this._events];
    }
  }

  // ---------------------------------------------------------------------------
  // D58 -- AI Agent Behavioral Fingerprinting
  // ---------------------------------------------------------------------------

  /** Default deviation threshold for alerting. */
  const D58_ALERT_THRESHOLD = 0.7;

  /**
   * Behavioral baseline for an agent.
   * @class
   */
  class BehavioralBaseline {
    /**
     * @param {string} agentId
     */
    constructor(agentId) {
      this.agentId            = agentId;
      /** @type {Object<string,number>} */
      this.responsePatterns   = {};
      /** @type {Object<string,number>} */
      this.toolUsageFrequency = {};
      this.outputLengthMean   = 0;
      this.outputLengthStddev = 0;
      /** @type {Object<string,number>} */
      this.topicDistribution  = {};
      this.createdAt          = now();
      this.sampleCount        = 0;
    }
  }

  /**
   * A single behavioral observation for an agent.
   * @class
   */
  class BehavioralObservation {
    /**
     * @param {Object} opts
     * @param {string} opts.agentId
     * @param {number} opts.responseLength
     * @param {string[]} opts.toolsUsed
     * @param {string[]} opts.topics
     * @param {string} opts.outputHash
     */
    constructor(opts) {
      this.agentId        = opts.agentId;
      this.timestamp      = now();
      this.responseLength = opts.responseLength;
      this.toolsUsed      = opts.toolsUsed || [];
      this.topics         = opts.topics || [];
      this.outputHash     = opts.outputHash || '';
    }
  }

  /**
   * D58 Engine -- AI Agent Behavioral Fingerprinting.
   * Detects prompt injection via behavioral deviation scoring.
   * @class
   */
  class D58Engine {
    /**
     * @param {number} [alertThreshold=0.7]
     */
    constructor(alertThreshold = D58_ALERT_THRESHOLD) {
      /** @type {number} */
      this._alertThreshold = alertThreshold;
      /** @type {Map<string, BehavioralBaseline>} */
      this._baselines = new Map();
      /** @type {Map<string, BehavioralObservation[]>} */
      this._observations = new Map();
      /** @type {Array<Object>} */
      this._alerts = [];
    }

    /**
     * Register an agent and initialize its baseline.
     * @param {string} agentId
     * @returns {BehavioralBaseline}
     */
    registerAgent(agentId) {
      const baseline = new BehavioralBaseline(agentId);
      this._baselines.set(agentId, baseline);
      this._observations.set(agentId, []);
      return baseline;
    }

    /**
     * Record an observation and update the agent's baseline.
     * @param {string} agentId
     * @param {BehavioralObservation} observation
     */
    recordObservation(agentId, observation) {
      const baseline = this._baselines.get(agentId);
      if (!baseline) {
        throw new Error('Agent not registered: ' + agentId);
      }

      const obs = this._observations.get(agentId);
      obs.push(observation);

      // Update running statistics
      const n = baseline.sampleCount;
      const newCount = n + 1;

      // Update output length mean and stddev (Welford's online algorithm)
      const delta = observation.responseLength - baseline.outputLengthMean;
      baseline.outputLengthMean += delta / newCount;
      const delta2 = observation.responseLength - baseline.outputLengthMean;
      const m2 = (baseline.outputLengthStddev * baseline.outputLengthStddev) * n + delta * delta2;
      baseline.outputLengthStddev = newCount > 1 ? Math.sqrt(m2 / newCount) : 0;

      // Update tool usage frequency
      for (const tool of observation.toolsUsed) {
        baseline.toolUsageFrequency[tool] = (baseline.toolUsageFrequency[tool] || 0) + 1;
      }

      // Update topic distribution
      for (const topic of observation.topics) {
        baseline.topicDistribution[topic] = (baseline.topicDistribution[topic] || 0) + 1;
      }

      // Update response length pattern bucket
      const bucket = this._lengthBucket(observation.responseLength);
      baseline.responsePatterns[bucket] = (baseline.responsePatterns[bucket] || 0) + 1;

      baseline.sampleCount = newCount;
    }

    /**
     * Compute a deviation score for an observation against the agent's baseline.
     * @param {string} agentId
     * @param {BehavioralObservation} observation
     * @returns {{score: number, components: Object, alert: boolean}}
     */
    computeDeviation(agentId, observation) {
      const baseline = this._baselines.get(agentId);
      if (!baseline || baseline.sampleCount < 2) {
        return { score: 0, components: {}, alert: false };
      }

      const components = {};

      // Length deviation (z-score, clamped to [0,1])
      if (baseline.outputLengthStddev > 0) {
        const z = Math.abs(observation.responseLength - baseline.outputLengthMean) /
                  baseline.outputLengthStddev;
        components.lengthDeviation = Math.min(z / 4, 1);
      } else {
        components.lengthDeviation = observation.responseLength !== baseline.outputLengthMean ? 1 : 0;
      }

      // Tool usage deviation
      components.toolDeviation = this._toolDeviation(baseline, observation.toolsUsed);

      // Topic deviation
      components.topicDeviation = this._topicDeviation(baseline, observation.topics);

      // Weighted aggregate
      const score = Math.min(1, Math.max(0,
        components.lengthDeviation * 0.3 +
        components.toolDeviation * 0.4 +
        components.topicDeviation * 0.3
      ));

      const alert = score >= this._alertThreshold;
      if (alert) {
        this._alerts.push({
          agentId:   agentId,
          score:     score,
          components: { ...components },
          timestamp: now()
        });
      }

      return { score, components, alert };
    }

    /**
     * Detect possible prompt injection based on behavioral analysis.
     * @param {string} agentId
     * @param {BehavioralObservation} observation
     * @returns {{detected: boolean, confidence: number, indicators: string[]}}
     */
    detectPromptInjection(agentId, observation) {
      const deviation = this.computeDeviation(agentId, observation);
      const indicators = [];

      if (deviation.components.lengthDeviation > 0.8) {
        indicators.push('ABNORMAL_OUTPUT_LENGTH');
      }
      if (deviation.components.toolDeviation > 0.8) {
        indicators.push('UNUSUAL_TOOL_USAGE');
      }
      if (deviation.components.topicDeviation > 0.8) {
        indicators.push('TOPIC_DRIFT');
      }
      if (observation.outputHash && this._detectMemoryTampering(agentId, observation)) {
        indicators.push('MEMORY_TAMPERING');
      }

      const confidence = deviation.score;
      const detected = indicators.length >= 2 || confidence >= this._alertThreshold;

      return { detected, confidence, indicators };
    }

    /**
     * Get the baseline for an agent.
     * @param {string} agentId
     * @returns {BehavioralBaseline|null}
     */
    getAgentBaseline(agentId) {
      return this._baselines.get(agentId) || null;
    }

    /**
     * Get alert history for an agent.
     * @param {string} agentId
     * @returns {Array<Object>}
     */
    getAlertHistory(agentId) {
      return this._alerts.filter(a => a.agentId === agentId);
    }

    /**
     * Detect potential memory tampering (SOUL.md/MEMORY.md modifications).
     * Checks if the output hash has changed drastically from previous observations.
     * @private
     * @param {string} agentId
     * @param {BehavioralObservation} observation
     * @returns {boolean}
     */
    _detectMemoryTampering(agentId, observation) {
      const obs = this._observations.get(agentId);
      if (!obs || obs.length < 3) {
        return false;
      }
      // Check if output hash is entirely new in last window of observations
      const recentHashes = new Set(obs.slice(-10).map(o => o.outputHash).filter(Boolean));
      return recentHashes.size > 0 && !recentHashes.has(observation.outputHash);
    }

    /**
     * Compute tool usage deviation between observation and baseline.
     * @private
     * @param {BehavioralBaseline} baseline
     * @param {string[]} toolsUsed
     * @returns {number} 0.0-1.0
     */
    _toolDeviation(baseline, toolsUsed) {
      const knownTools = Object.keys(baseline.toolUsageFrequency);
      if (knownTools.length === 0) {
        return toolsUsed.length > 0 ? 1 : 0;
      }
      const knownSet = new Set(knownTools);
      const novelTools = toolsUsed.filter(t => !knownSet.has(t));
      return toolsUsed.length > 0 ? novelTools.length / toolsUsed.length : 0;
    }

    /**
     * Compute topic deviation between observation and baseline.
     * @private
     * @param {BehavioralBaseline} baseline
     * @param {string[]} topics
     * @returns {number} 0.0-1.0
     */
    _topicDeviation(baseline, topics) {
      const knownTopics = Object.keys(baseline.topicDistribution);
      if (knownTopics.length === 0) {
        return topics.length > 0 ? 1 : 0;
      }
      const knownSet = new Set(knownTopics);
      const novelTopics = topics.filter(t => !knownSet.has(t));
      return topics.length > 0 ? novelTopics.length / topics.length : 0;
    }

    /**
     * Bucket a response length for pattern tracking.
     * @private
     * @param {number} len
     * @returns {string}
     */
    _lengthBucket(len) {
      if (len < 100)  return 'short';
      if (len < 500)  return 'medium';
      if (len < 2000) return 'long';
      return 'very_long';
    }
  }

  // ---------------------------------------------------------------------------
  // Module -- StaamlLayer2
  // ---------------------------------------------------------------------------

  /**
   * @namespace StaamlLayer2
   */
  const StaamlLayer2 = {
    VERSION: '1.0.0',

    PostureLevel:        PostureLevel,
    AttestationVerdict:  AttestationVerdict,
    RequestClass:        RequestClass,
    AIRiskLevel:         AIRiskLevel,
    ModelType:           ModelType,

    // Engine classes (for direct instantiation)
    D34Engine:           D34Engine,
    D37Engine:           D37Engine,
    D48Engine:           D48Engine,
    D49Engine:           D49Engine,
    D58Engine:           D58Engine,

    // Data classes
    AttestationToken:        AttestationToken,
    AttestationSession:      AttestationSession,
    AttestationTokenBuilder: AttestationTokenBuilder,
    D37Token:                D37Token,
    TenantBoundary:          TenantBoundary,
    ModelRegistration:       ModelRegistration,
    BehavioralBaseline:      BehavioralBaseline,
    BehavioralObservation:   BehavioralObservation,

    /** @type {D34Engine|null} */
    D34: null,
    /** @type {D37Engine|null} */
    D37: null,
    /** @type {D48Engine|null} */
    D48: null,
    /** @type {D49Engine|null} */
    D49: null,
    /** @type {D58Engine|null} */
    D58: null,

    /**
     * Initialize all Layer 2 governance engines with a shared master key.
     * @param {string} masterKey - Hex-encoded master key (minimum 32 hex chars / 128 bits).
     * @returns {StaamlLayer2}
     */
    init: function (masterKey) {
      if (!masterKey || typeof masterKey !== 'string' || masterKey.length < 32) {
        throw new Error('Master key must be a hex string of at least 32 characters (128 bits).');
      }
      this.D34 = new D34Engine(masterKey);
      this.D37 = new D37Engine(masterKey);
      this.D48 = new D48Engine(masterKey);
      this.D49 = new D49Engine();
      this.D58 = new D58Engine();
      return this;
    },

    /**
     * Return combined status of all Layer 2 engines.
     * @returns {Object}
     */
    getStatus: function () {
      return {
        version: this.VERSION,
        engines: {
          D34: { initialized: this.D34 !== null, type: 'Posture-Bound Session Attestation' },
          D37: { initialized: this.D37 !== null, type: 'Posture-Bound Token Lifecycle' },
          D48: { initialized: this.D48 !== null, type: 'Multi-Tenant Posture Isolation' },
          D49: { initialized: this.D49 !== null, type: 'Posture-Aware ML Model Cache' },
          D58: { initialized: this.D58 !== null, type: 'AI Agent Behavioral Fingerprinting' }
        },
        timestamp: now()
      };
    }
  };

  // Expose on window
  globalThis.StaamlLayer2 = StaamlLayer2;

})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
