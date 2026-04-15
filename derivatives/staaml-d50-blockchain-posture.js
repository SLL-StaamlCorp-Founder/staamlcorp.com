'use strict';

/**
 * StaamlCorp Temporal Security Derivative D50
 * Blockchain Smart Contract Posture Binding
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

  globalThis.StaamlD50 = { PostureLevel, generateId, now, sha256 };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
