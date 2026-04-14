'use strict';

/**
 * StaamlCorp TSB Orchestrator
 * Master coordinator for ALL StaamlCorp layers and derivatives.
 *
 * @fileoverview Coordinates Layer 2 (D34/D37), Layer 3 (D43/D48/D49/D58),
 * Layer 4 (RIT/CBQE), QeratheonCore, and the TSB cache engine.
 * Implements Policy-Aware Cache Registry (PACR) and cascading policy transitions.
 * Uses Web Crypto API exclusively. No external dependencies.
 *
 * @version 1.0.0
 * @license Proprietary - StaamlCorp
 */

// ============================================================================
// Enums
// ============================================================================

/**
 * Policy domains governed by the orchestrator.
 * @enum {string}
 */
const PolicyDomain = Object.freeze({
  HIPAA:       'HIPAA',
  AI_ACT:      'AI_ACT',
  CFR_42_PART2: 'CFR_42_PART2',
  NETWORK:     'NETWORK',
  TENANT:      'TENANT',
  SKILL:       'SKILL',
  MODEL:       'MODEL',
  IDENTITY:    'IDENTITY',
  ENCRYPTION:  'ENCRYPTION',
});

/**
 * Types of policy transitions the orchestrator can process.
 * @enum {string}
 */
const TransitionType = Object.freeze({
  CONSENT_CHANGE:             'CONSENT_CHANGE',
  POSTURE_CHANGE:             'POSTURE_CHANGE',
  RISK_RECLASSIFICATION:      'RISK_RECLASSIFICATION',
  NETWORK_POLICY_UPDATE:      'NETWORK_POLICY_UPDATE',
  SKILL_ATTESTATION_CHANGE:   'SKILL_ATTESTATION_CHANGE',
  TENANT_BOUNDARY_CHANGE:     'TENANT_BOUNDARY_CHANGE',
  AGENT_RESTART:              'AGENT_RESTART',
  BLUEPRINT_TRANSITION:       'BLUEPRINT_TRANSITION',
  REGULATORY_UPDATE:          'REGULATORY_UPDATE',
  EMERGENCY_LOCKDOWN:         'EMERGENCY_LOCKDOWN',
  KEY_ROTATION:               'KEY_ROTATION',
});

/**
 * Actions to mitigate policy violations on cache entries.
 * @enum {string}
 */
const MitigationAction = Object.freeze({
  BLOCK:       'BLOCK',
  PURGE:       'PURGE',
  REGENERATE:  'REGENERATE',
  REVALIDATE:  'REVALIDATE',
  QUARANTINE:  'QUARANTINE',
  ALLOW:       'ALLOW',
});

/**
 * Posture change direction.
 * @enum {string}
 */
const PostureDirection = Object.freeze({
  TIGHTENED: 'TIGHTENED',
  LOOSENED:  'LOOSENED',
  UNCHANGED: 'UNCHANGED',
});

// ============================================================================
// Utility Helpers
// ============================================================================

/**
 * Generate a UUID v4.
 * @returns {string}
 */
function _generateId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Get current ISO timestamp.
 * @returns {string}
 */
function _nowISO() {
  return new Date().toISOString();
}

/**
 * Deep clone a plain object.
 * @param {Object} obj
 * @returns {Object}
 */
function _deepClone(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(_deepClone);
  const out = {};
  for (const key of Object.keys(obj)) {
    out[key] = _deepClone(obj[key]);
  }
  return out;
}

/**
 * Compute SHA-256 hash (hex).
 * @param {string} data
 * @returns {Promise<string>}
 */
async function _sha256Hex(data) {
  const subtle = crypto.subtle;
  const buf = new TextEncoder().encode(data);
  const hash = await subtle.digest('SHA-256', buf);
  const bytes = new Uint8Array(hash);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

// ============================================================================
// Core Data Structures
// ============================================================================

/**
 * An entry in the Policy-Aware Cache Registry (PACR).
 */
class CacheEntry {
  /**
   * @param {Object} params
   * @param {string} params.entryId
   * @param {string} params.contentType
   * @param {string} params.contentHash
   * @param {string} params.contentName
   * @param {string} params.origin
   * @param {string} params.cachedAt
   * @param {string} params.lastValidatedAt
   * @param {string} params.priorPolicyId
   * @param {string} params.currentPolicyId
   * @param {string} params.validationState - 'VALID' | 'INVALID' | 'PENDING' | 'QUARANTINED'
   * @param {string} params.tenantId
   * @param {number} params.postureAtCache
   * @param {string} [params.contractId]
   * @param {string} [params.modelRegistrationId]
   * @param {string[]} [params.d43EndpointIds]
   * @param {string} [params.behavioralBaselineId]
   * @param {string} [params.mitigationAction]
   * @param {string} [params.mitigationTimestamp]
   * @param {string} [params.mitigationReason]
   * @param {Object[]} [params.validationHistory]
   * @param {number} [params.executionCount]
   */
  constructor(params) {
    this.entryId = params.entryId || _generateId();
    this.contentType = params.contentType;
    this.contentHash = params.contentHash;
    this.contentName = params.contentName;
    this.origin = params.origin;
    this.cachedAt = params.cachedAt || _nowISO();
    this.lastValidatedAt = params.lastValidatedAt || _nowISO();
    this.priorPolicyId = params.priorPolicyId || null;
    this.currentPolicyId = params.currentPolicyId || null;
    this.validationState = params.validationState || 'PENDING';
    this.tenantId = params.tenantId;
    this.postureAtCache = params.postureAtCache;
    this.contractId = params.contractId || null;
    this.modelRegistrationId = params.modelRegistrationId || null;
    this.d43EndpointIds = params.d43EndpointIds || [];
    this.behavioralBaselineId = params.behavioralBaselineId || null;
    this.mitigationAction = params.mitigationAction || null;
    this.mitigationTimestamp = params.mitigationTimestamp || null;
    this.mitigationReason = params.mitigationReason || null;
    this.validationHistory = params.validationHistory || [];
    this.executionCount = params.executionCount || 0;
  }

  /**
   * @returns {Object}
   */
  toJSON() {
    return _deepClone(this);
  }
}

/**
 * A snapshot of the complete policy state at a point in time.
 */
class PolicyState {
  /**
   * @param {Object} params
   * @param {string} params.policyId
   * @param {string} params.timestamp
   * @param {number} params.postureLevel - 1 (lowest) to 5 (CRITICAL)
   * @param {string[]} params.activeConsents
   * @param {string} params.networkPolicyVersion
   * @param {string} params.skillContractsVersion
   * @param {string} params.tenantConfigVersion
   * @param {string} params.identityFingerprint
   * @param {number} params.encryptionKeyGeneration
   * @param {Object} params.regulatoryFlags
   */
  constructor(params) {
    this.policyId = params.policyId || _generateId();
    this.timestamp = params.timestamp || _nowISO();
    this.postureLevel = params.postureLevel;
    this.activeConsents = params.activeConsents || [];
    this.networkPolicyVersion = params.networkPolicyVersion || '1.0.0';
    this.skillContractsVersion = params.skillContractsVersion || '1.0.0';
    this.tenantConfigVersion = params.tenantConfigVersion || '1.0.0';
    this.identityFingerprint = params.identityFingerprint || null;
    this.encryptionKeyGeneration = params.encryptionKeyGeneration || 1;
    this.regulatoryFlags = params.regulatoryFlags || {};
  }

  /**
   * @returns {Object}
   */
  toJSON() {
    return _deepClone(this);
  }
}

/**
 * The computed difference between two policy states, including affected entries
 * and the mitigation plan.
 */
class PolicyDelta {
  /**
   * @param {Object} params
   * @param {string} params.deltaId
   * @param {PolicyState} params.priorPolicy
   * @param {PolicyState} params.currentPolicy
   * @param {string} params.computedAt
   * @param {boolean} params.postureChanged
   * @param {string} params.postureDirection - PostureDirection value
   * @param {string[]} params.consentsRevoked
   * @param {string[]} params.consentsAdded
   * @param {string[]} params.networkEndpointsAdded
   * @param {string[]} params.networkEndpointsRemoved
   * @param {string[]} params.skillsRevoked
   * @param {string[]} params.skillsAdded
   * @param {Object[]} params.tenantChanges
   * @param {boolean} params.identityChanged
   * @param {boolean} params.encryptionRotated
   * @param {Object[]} params.regulatoryChanges
   * @param {CacheEntry[]} params.affectedEntries
   * @param {Object[]} params.mitigationPlan
   */
  constructor(params) {
    this.deltaId = params.deltaId || _generateId();
    this.priorPolicy = params.priorPolicy;
    this.currentPolicy = params.currentPolicy;
    this.computedAt = params.computedAt || _nowISO();
    this.postureChanged = params.postureChanged || false;
    this.postureDirection = params.postureDirection || PostureDirection.UNCHANGED;
    this.consentsRevoked = params.consentsRevoked || [];
    this.consentsAdded = params.consentsAdded || [];
    this.networkEndpointsAdded = params.networkEndpointsAdded || [];
    this.networkEndpointsRemoved = params.networkEndpointsRemoved || [];
    this.skillsRevoked = params.skillsRevoked || [];
    this.skillsAdded = params.skillsAdded || [];
    this.tenantChanges = params.tenantChanges || [];
    this.identityChanged = params.identityChanged || false;
    this.encryptionRotated = params.encryptionRotated || false;
    this.regulatoryChanges = params.regulatoryChanges || [];
    this.affectedEntries = params.affectedEntries || [];
    this.mitigationPlan = params.mitigationPlan || [];
  }

  /**
   * @returns {Object}
   */
  toJSON() {
    return {
      deltaId: this.deltaId,
      priorPolicy: this.priorPolicy ? this.priorPolicy.toJSON() : null,
      currentPolicy: this.currentPolicy ? this.currentPolicy.toJSON() : null,
      computedAt: this.computedAt,
      postureChanged: this.postureChanged,
      postureDirection: this.postureDirection,
      consentsRevoked: this.consentsRevoked.slice(),
      consentsAdded: this.consentsAdded.slice(),
      networkEndpointsAdded: this.networkEndpointsAdded.slice(),
      networkEndpointsRemoved: this.networkEndpointsRemoved.slice(),
      skillsRevoked: this.skillsRevoked.slice(),
      skillsAdded: this.skillsAdded.slice(),
      tenantChanges: _deepClone(this.tenantChanges),
      identityChanged: this.identityChanged,
      encryptionRotated: this.encryptionRotated,
      regulatoryChanges: _deepClone(this.regulatoryChanges),
      affectedEntries: this.affectedEntries.map(function (e) { return e.toJSON ? e.toJSON() : e; }),
      mitigationPlan: _deepClone(this.mitigationPlan),
    };
  }
}

// ============================================================================
// Audit Entry
// ============================================================================

/**
 * An audit trail entry produced by the orchestrator.
 */
class AuditEntry {
  /**
   * @param {Object} params
   * @param {string} params.entryId
   * @param {string} params.timestamp
   * @param {string} params.transitionType - TransitionType value
   * @param {string} params.reason
   * @param {string} [params.deltaId]
   * @param {string[]} [params.affectedEntryIds]
   * @param {Object[]} [params.mitigationsExecuted]
   * @param {string} [params.outcome]
   * @param {Object} [params.details]
   */
  constructor(params) {
    this.entryId = params.entryId || _generateId();
    this.timestamp = params.timestamp || _nowISO();
    this.transitionType = params.transitionType;
    this.reason = params.reason;
    this.deltaId = params.deltaId || null;
    this.affectedEntryIds = params.affectedEntryIds || [];
    this.mitigationsExecuted = params.mitigationsExecuted || [];
    this.outcome = params.outcome || 'SUCCESS';
    this.details = params.details || {};
  }

  /**
   * @returns {Object}
   */
  toJSON() {
    return _deepClone(this);
  }
}

// ============================================================================
// StaamlTSBOrchestrator
// ============================================================================

/**
 * Master TSB Orchestrator.
 *
 * Coordinates all StaamlCorp layers and derivatives:
 *  - Layer 2: D34 (session management), D37 (token management)
 *  - Layer 3: D43 (network policy), D48 (tenant boundaries), D49 (model registry), D58 (behavioral baselines)
 *  - Layer 4: RIT (identity verification), CBQE (encryption)
 *  - QeratheonCore: quantum-resistant core
 *  - TSB: cache validation engine
 *
 * Implements the Policy-Aware Cache Registry (PACR) — tracks all cached
 * content with the policy state under which it was cached, and re-evaluates
 * entries whenever policy transitions occur.
 */
class StaamlTSBOrchestrator {
  /**
   * @param {string} masterKey - Hex-encoded master key (at least 64 hex chars)
   * @param {string} agentId - Unique agent identifier
   */
  constructor(masterKey, agentId) {
    if (!masterKey || masterKey.length < 64) {
      throw new Error('masterKey must be at least 256 bits (64 hex characters).');
    }
    if (!agentId) {
      throw new Error('agentId is required.');
    }

    /** @private */
    this._masterKey = masterKey;
    /** @private */
    this._agentId = agentId;

    // Connected engines (set via connect* methods)
    /** @private */
    this._layer2 = null;
    /** @private */
    this._layer3 = null;
    /** @private */
    this._layer4 = null;
    /** @private */
    this._qeratheon = null;
    /** @private */
    this._tsb = null;

    // Policy-Aware Cache Registry
    /** @private @type {Map<string, CacheEntry>} */
    this._cacheRegistry = new Map();

    // Policy history
    /** @private @type {PolicyState|null} */
    this._currentPolicy = null;
    /** @private @type {PolicyState[]} */
    this._policyHistory = [];
    /** @private @type {PolicyDelta[]} */
    this._deltaHistory = [];

    // Audit trail
    /** @private @type {AuditEntry[]} */
    this._auditTrail = [];

    // Lockdown state
    /** @private */
    this._isLockedDown = false;
    /** @private */
    this._lockdownReason = null;
    /** @private */
    this._lockdownTimestamp = null;
  }

  // --------------------------------------------------------------------------
  // Engine Connection
  // --------------------------------------------------------------------------

  /**
   * Connect Layer 2 engines (D34 session management, D37 token management).
   * @param {Object} layer2 - Object with d34 and/or d37 properties
   */
  connectLayer2(layer2) {
    this._layer2 = layer2;
    this._addAudit(TransitionType.AGENT_RESTART, 'Layer 2 engines connected', {
      engines: Object.keys(layer2),
    });
  }

  /**
   * Connect Layer 3 engines (D43, D48, D49, D58).
   * @param {Object} layer3 - Object with d43, d48, d49, d58 properties
   */
  connectLayer3(layer3) {
    this._layer3 = layer3;
    this._addAudit(TransitionType.AGENT_RESTART, 'Layer 3 engines connected', {
      engines: Object.keys(layer3),
    });
  }

  /**
   * Connect Layer 4 engines (RIT, CBQE).
   * @param {Object} layer4 - Object with rit and/or cbqe properties
   */
  connectLayer4(layer4) {
    this._layer4 = layer4;
    this._addAudit(TransitionType.AGENT_RESTART, 'Layer 4 engines connected', {
      engines: Object.keys(layer4),
    });
  }

  /**
   * Connect QeratheonCore engine.
   * @param {Object} qeratheon
   */
  connectQeratheon(qeratheon) {
    this._qeratheon = qeratheon;
    this._addAudit(TransitionType.AGENT_RESTART, 'QeratheonCore connected', {});
  }

  /**
   * Connect the TSB cache validation engine.
   * @param {Object} tsb
   */
  connectTSB(tsb) {
    this._tsb = tsb;
    this._addAudit(TransitionType.AGENT_RESTART, 'TSB engine connected', {});
  }

  // --------------------------------------------------------------------------
  // Cache Registry (PACR)
  // --------------------------------------------------------------------------

  /**
   * Register cached content in the Policy-Aware Cache Registry.
   *
   * @param {string} contentType - Type of content (e.g., 'session', 'token', 'model_output')
   * @param {string} contentHash - SHA-256 hash of the content
   * @param {string} contentName - Human-readable name
   * @param {string} origin - Where the content came from
   * @param {string} tenantId - Tenant that owns this content
   * @param {number} postureLevel - Posture level at time of caching
   * @returns {CacheEntry}
   */
  registerCachedContent(contentType, contentHash, contentName, origin, tenantId, postureLevel) {
    const entry = new CacheEntry({
      entryId: _generateId(),
      contentType: contentType,
      contentHash: contentHash,
      contentName: contentName,
      origin: origin,
      cachedAt: _nowISO(),
      lastValidatedAt: _nowISO(),
      priorPolicyId: this._currentPolicy ? this._currentPolicy.policyId : null,
      currentPolicyId: this._currentPolicy ? this._currentPolicy.policyId : null,
      validationState: 'VALID',
      tenantId: tenantId,
      postureAtCache: postureLevel,
      validationHistory: [{
        timestamp: _nowISO(),
        state: 'VALID',
        policyId: this._currentPolicy ? this._currentPolicy.policyId : null,
        reason: 'Initial registration',
      }],
      executionCount: 0,
    });

    this._cacheRegistry.set(entry.entryId, entry);
    return entry;
  }

  // --------------------------------------------------------------------------
  // Policy Management
  // --------------------------------------------------------------------------

  /**
   * Set the initial policy state. Must be called before processing transitions.
   *
   * @param {PolicyState|Object} policy
   */
  setInitialPolicy(policy) {
    if (!(policy instanceof PolicyState)) {
      policy = new PolicyState(policy);
    }

    this._currentPolicy = policy;
    this._policyHistory.push(policy);

    this._addAudit(TransitionType.AGENT_RESTART, 'Initial policy set', {
      policyId: policy.policyId,
      postureLevel: policy.postureLevel,
    });
  }

  /**
   * Process a policy transition. This is the CORE orchestration method.
   *
   * Steps:
   *  1. Compute delta between current and new policy
   *  2. Identify affected cache entries
   *  3. Generate mitigation plan
   *  4. Execute mitigations via connected engines
   *  5. Log comprehensive audit trail
   *
   * @param {PolicyState|Object} newPolicy
   * @param {string} transitionType - TransitionType value
   * @param {string} reason - Human-readable reason for the transition
   * @returns {Promise<PolicyDelta>}
   */
  async processPolicyTransition(newPolicy, transitionType, reason) {
    if (!this._currentPolicy) {
      throw new Error('No current policy set. Call setInitialPolicy() first.');
    }

    if (this._isLockedDown && transitionType !== TransitionType.EMERGENCY_LOCKDOWN) {
      throw new Error('System is in emergency lockdown. Only EMERGENCY_LOCKDOWN transitions are permitted.');
    }

    if (!(newPolicy instanceof PolicyState)) {
      newPolicy = new PolicyState(newPolicy);
    }

    const priorPolicy = this._currentPolicy;

    // 1. Compute delta
    const delta = this._computeDelta(priorPolicy, newPolicy);

    // 2. Identify affected cache entries
    const affectedEntries = this._identifyAffectedEntries(delta, transitionType);
    delta.affectedEntries = affectedEntries;

    // 3. Generate mitigation plan
    const mitigationPlan = this._generateMitigationPlan(delta, transitionType, affectedEntries);
    delta.mitigationPlan = mitigationPlan;

    // 4. Execute mitigations
    const executedMitigations = await this._executeMitigations(mitigationPlan, delta);

    // 5. Update state
    this._currentPolicy = newPolicy;
    this._policyHistory.push(newPolicy);
    this._deltaHistory.push(delta);

    // Update affected cache entries
    for (const entry of affectedEntries) {
      entry.priorPolicyId = priorPolicy.policyId;
      entry.currentPolicyId = newPolicy.policyId;
      entry.lastValidatedAt = _nowISO();
    }

    // 6. Audit
    this._addAudit(transitionType, reason, {
      deltaId: delta.deltaId,
      affectedEntryCount: affectedEntries.length,
      mitigationCount: mitigationPlan.length,
      postureDirection: delta.postureDirection,
      executedMitigations: executedMitigations,
    });

    return delta;
  }

  /**
   * Compute the policy delta between two states.
   *
   * @private
   * @param {PolicyState} prior
   * @param {PolicyState} current
   * @returns {PolicyDelta}
   */
  _computeDelta(prior, current) {
    // Posture
    const postureChanged = prior.postureLevel !== current.postureLevel;
    let postureDirection = PostureDirection.UNCHANGED;
    if (current.postureLevel > prior.postureLevel) {
      postureDirection = PostureDirection.TIGHTENED;
    } else if (current.postureLevel < prior.postureLevel) {
      postureDirection = PostureDirection.LOOSENED;
    }

    // Consents
    const priorConsents = new Set(prior.activeConsents);
    const currentConsents = new Set(current.activeConsents);
    const consentsRevoked = prior.activeConsents.filter(function (c) { return !currentConsents.has(c); });
    const consentsAdded = current.activeConsents.filter(function (c) { return !priorConsents.has(c); });

    // Identity
    const identityChanged = prior.identityFingerprint !== current.identityFingerprint;

    // Encryption
    const encryptionRotated = prior.encryptionKeyGeneration !== current.encryptionKeyGeneration;

    // Regulatory flags
    const regulatoryChanges = [];
    const allFlags = new Set([
      ...Object.keys(prior.regulatoryFlags || {}),
      ...Object.keys(current.regulatoryFlags || {}),
    ]);
    for (const flag of allFlags) {
      const priorVal = (prior.regulatoryFlags || {})[flag];
      const currentVal = (current.regulatoryFlags || {})[flag];
      if (priorVal !== currentVal) {
        regulatoryChanges.push({
          flag: flag,
          prior: priorVal !== undefined ? priorVal : null,
          current: currentVal !== undefined ? currentVal : null,
        });
      }
    }

    // Version-based changes (network, skill, tenant)
    const networkEndpointsAdded = prior.networkPolicyVersion !== current.networkPolicyVersion
      ? ['network_policy_updated']
      : [];
    const networkEndpointsRemoved = [];

    const skillsRevoked = [];
    const skillsAdded = [];
    if (prior.skillContractsVersion !== current.skillContractsVersion) {
      skillsAdded.push('skill_contracts_updated');
    }

    const tenantChanges = [];
    if (prior.tenantConfigVersion !== current.tenantConfigVersion) {
      tenantChanges.push({
        type: 'CONFIG_VERSION_CHANGE',
        prior: prior.tenantConfigVersion,
        current: current.tenantConfigVersion,
      });
    }

    return new PolicyDelta({
      deltaId: _generateId(),
      priorPolicy: prior,
      currentPolicy: current,
      computedAt: _nowISO(),
      postureChanged: postureChanged,
      postureDirection: postureDirection,
      consentsRevoked: consentsRevoked,
      consentsAdded: consentsAdded,
      networkEndpointsAdded: networkEndpointsAdded,
      networkEndpointsRemoved: networkEndpointsRemoved,
      skillsRevoked: skillsRevoked,
      skillsAdded: skillsAdded,
      tenantChanges: tenantChanges,
      identityChanged: identityChanged,
      encryptionRotated: encryptionRotated,
      regulatoryChanges: regulatoryChanges,
      affectedEntries: [],
      mitigationPlan: [],
    });
  }

  /**
   * Identify cache entries affected by a policy delta.
   *
   * @private
   * @param {PolicyDelta} delta
   * @param {string} transitionType
   * @returns {CacheEntry[]}
   */
  _identifyAffectedEntries(delta, transitionType) {
    const affected = [];

    for (const [, entry] of this._cacheRegistry) {
      let isAffected = false;

      // Posture tightening affects all entries cached at a lower posture
      if (delta.postureChanged && delta.postureDirection === PostureDirection.TIGHTENED) {
        if (entry.postureAtCache < delta.currentPolicy.postureLevel) {
          isAffected = true;
        }
      }

      // Consent revocations affect entries from tenants with revoked consents
      if (delta.consentsRevoked.length > 0) {
        isAffected = true;
      }

      // Network policy changes affect entries with D43 endpoint associations
      if (delta.networkEndpointsAdded.length > 0 || delta.networkEndpointsRemoved.length > 0) {
        if (entry.d43EndpointIds && entry.d43EndpointIds.length > 0) {
          isAffected = true;
        }
      }

      // Tenant changes affect entries belonging to changed tenants
      if (delta.tenantChanges.length > 0) {
        isAffected = true;
      }

      // Identity changes affect all entries
      if (delta.identityChanged) {
        isAffected = true;
      }

      // Encryption rotation affects all entries
      if (delta.encryptionRotated) {
        isAffected = true;
      }

      // Emergency lockdown affects everything
      if (transitionType === TransitionType.EMERGENCY_LOCKDOWN) {
        isAffected = true;
      }

      // Regulatory changes affect all entries
      if (delta.regulatoryChanges.length > 0) {
        isAffected = true;
      }

      if (isAffected) {
        affected.push(entry);
      }
    }

    return affected;
  }

  /**
   * Generate a mitigation plan for affected entries.
   *
   * @private
   * @param {PolicyDelta} delta
   * @param {string} transitionType
   * @param {CacheEntry[]} affectedEntries
   * @returns {Object[]}
   */
  _generateMitigationPlan(delta, transitionType, affectedEntries) {
    const plan = [];

    for (const entry of affectedEntries) {
      let action = MitigationAction.REVALIDATE;
      let reason = 'Policy transition requires revalidation.';

      // Emergency lockdown => BLOCK all
      if (transitionType === TransitionType.EMERGENCY_LOCKDOWN) {
        action = MitigationAction.BLOCK;
        reason = 'Emergency lockdown: all cache entries blocked.';
      }
      // Consent revocation => PURGE
      else if (delta.consentsRevoked.length > 0) {
        action = MitigationAction.PURGE;
        reason = 'Consent revoked: cached content must be purged.';
      }
      // Posture tightening by 2+ levels => QUARANTINE
      else if (delta.postureChanged && delta.postureDirection === PostureDirection.TIGHTENED) {
        const postureDiff = delta.currentPolicy.postureLevel - delta.priorPolicy.postureLevel;
        if (postureDiff >= 2) {
          action = MitigationAction.QUARANTINE;
          reason = 'Posture tightened by ' + postureDiff + ' levels: quarantining until manual review.';
        }
      }
      // Identity change => QUARANTINE
      else if (delta.identityChanged) {
        action = MitigationAction.QUARANTINE;
        reason = 'Identity fingerprint changed: quarantining cached content.';
      }
      // Encryption rotation => REGENERATE
      else if (delta.encryptionRotated) {
        action = MitigationAction.REGENERATE;
        reason = 'Encryption key rotated: cached content must be re-encrypted.';
      }

      plan.push({
        entryId: entry.entryId,
        contentName: entry.contentName,
        action: action,
        reason: reason,
        delegateTo: this._determineDelegation(entry, transitionType),
      });
    }

    return plan;
  }

  /**
   * Determine which engine should handle a mitigation.
   *
   * @private
   * @param {CacheEntry} entry
   * @param {string} transitionType
   * @returns {string[]} Engine identifiers to delegate to
   */
  _determineDelegation(entry, transitionType) {
    const delegates = [];

    switch (entry.contentType) {
      case 'session':
        delegates.push('D34');
        break;
      case 'token':
        delegates.push('D37');
        break;
      case 'network_endpoint':
        delegates.push('D43');
        break;
      case 'tenant_config':
        delegates.push('D48');
        break;
      case 'model_output':
      case 'model_registration':
        delegates.push('D49');
        break;
      case 'behavioral_baseline':
        delegates.push('D58');
        break;
      default:
        delegates.push('TSB');
        break;
    }

    // Identity transitions always involve RIT
    if (transitionType === TransitionType.BLUEPRINT_TRANSITION ||
        transitionType === TransitionType.AGENT_RESTART) {
      delegates.push('RIT');
    }

    // Key rotation always involves CBQE
    if (transitionType === TransitionType.KEY_ROTATION) {
      delegates.push('CBQE');
    }

    // Emergency lockdown involves everything
    if (transitionType === TransitionType.EMERGENCY_LOCKDOWN) {
      if (!delegates.includes('RIT')) delegates.push('RIT');
      if (!delegates.includes('CBQE')) delegates.push('CBQE');
      if (!delegates.includes('TSB')) delegates.push('TSB');
    }

    return delegates;
  }

  /**
   * Execute the mitigation plan by delegating to connected engines.
   *
   * @private
   * @param {Object[]} plan
   * @param {PolicyDelta} delta
   * @returns {Promise<Object[]>} Executed mitigations with outcomes
   */
  async _executeMitigations(plan, delta) {
    const results = [];

    for (const mitigation of plan) {
      const entry = this._cacheRegistry.get(mitigation.entryId);
      if (!entry) continue;

      const result = {
        entryId: mitigation.entryId,
        action: mitigation.action,
        delegates: mitigation.delegateTo,
        executedAt: _nowISO(),
        outcomes: [],
      };

      // Execute mitigation action on the cache entry
      switch (mitigation.action) {
        case MitigationAction.BLOCK:
          entry.validationState = 'INVALID';
          entry.mitigationAction = MitigationAction.BLOCK;
          entry.mitigationTimestamp = _nowISO();
          entry.mitigationReason = mitigation.reason;
          result.outcomes.push('BLOCKED');
          break;

        case MitigationAction.PURGE:
          entry.validationState = 'INVALID';
          entry.mitigationAction = MitigationAction.PURGE;
          entry.mitigationTimestamp = _nowISO();
          entry.mitigationReason = mitigation.reason;
          // Mark for deletion but keep for audit
          result.outcomes.push('PURGED');
          break;

        case MitigationAction.QUARANTINE:
          entry.validationState = 'QUARANTINED';
          entry.mitigationAction = MitigationAction.QUARANTINE;
          entry.mitigationTimestamp = _nowISO();
          entry.mitigationReason = mitigation.reason;
          result.outcomes.push('QUARANTINED');
          break;

        case MitigationAction.REGENERATE:
          entry.validationState = 'PENDING';
          entry.mitigationAction = MitigationAction.REGENERATE;
          entry.mitigationTimestamp = _nowISO();
          entry.mitigationReason = mitigation.reason;
          result.outcomes.push('REGENERATION_PENDING');
          break;

        case MitigationAction.REVALIDATE:
          entry.validationState = 'PENDING';
          entry.mitigationAction = MitigationAction.REVALIDATE;
          entry.mitigationTimestamp = _nowISO();
          entry.mitigationReason = mitigation.reason;
          result.outcomes.push('REVALIDATION_PENDING');
          break;

        case MitigationAction.ALLOW:
          result.outcomes.push('ALLOWED');
          break;
      }

      // Delegate to connected engines
      for (const delegate of mitigation.delegateTo) {
        try {
          const delegateResult = await this._delegateToEngine(delegate, mitigation, entry, delta);
          result.outcomes.push(delegate + ':' + delegateResult);
        } catch (err) {
          result.outcomes.push(delegate + ':ERROR:' + err.message);
        }
      }

      // Update validation history
      entry.validationHistory.push({
        timestamp: _nowISO(),
        state: entry.validationState,
        policyId: delta.currentPolicy.policyId,
        reason: mitigation.reason,
        action: mitigation.action,
      });

      results.push(result);
    }

    return results;
  }

  /**
   * Delegate a mitigation action to a specific engine.
   *
   * @private
   * @param {string} engineId
   * @param {Object} mitigation
   * @param {CacheEntry} entry
   * @param {PolicyDelta} delta
   * @returns {Promise<string>} Outcome description
   */
  async _delegateToEngine(engineId, mitigation, entry, delta) {
    switch (engineId) {
      case 'D34':
        if (this._layer2 && this._layer2.d34) {
          if (typeof this._layer2.d34.invalidateSession === 'function') {
            await this._layer2.d34.invalidateSession(entry.entryId, mitigation.reason);
            return 'SESSION_INVALIDATED';
          }
        }
        return 'D34_NOT_CONNECTED';

      case 'D37':
        if (this._layer2 && this._layer2.d37) {
          if (typeof this._layer2.d37.revokeToken === 'function') {
            await this._layer2.d37.revokeToken(entry.entryId, mitigation.reason);
            return 'TOKEN_REVOKED';
          }
        }
        return 'D37_NOT_CONNECTED';

      case 'D43':
        if (this._layer3 && this._layer3.d43) {
          if (typeof this._layer3.d43.updateEndpointPolicy === 'function') {
            await this._layer3.d43.updateEndpointPolicy(entry.d43EndpointIds, mitigation.action);
            return 'ENDPOINTS_UPDATED';
          }
        }
        return 'D43_NOT_CONNECTED';

      case 'D48':
        if (this._layer3 && this._layer3.d48) {
          if (typeof this._layer3.d48.enforceBoundary === 'function') {
            await this._layer3.d48.enforceBoundary(entry.tenantId, mitigation.action);
            return 'BOUNDARY_ENFORCED';
          }
        }
        return 'D48_NOT_CONNECTED';

      case 'D49':
        if (this._layer3 && this._layer3.d49) {
          if (typeof this._layer3.d49.updateRegistration === 'function') {
            await this._layer3.d49.updateRegistration(entry.modelRegistrationId, mitigation.action);
            return 'MODEL_UPDATED';
          }
        }
        return 'D49_NOT_CONNECTED';

      case 'D58':
        if (this._layer3 && this._layer3.d58) {
          if (typeof this._layer3.d58.updateBaseline === 'function') {
            await this._layer3.d58.updateBaseline(entry.behavioralBaselineId, mitigation.action);
            return 'BASELINE_UPDATED';
          }
        }
        return 'D58_NOT_CONNECTED';

      case 'RIT':
        if (this._layer4 && this._layer4.rit) {
          if (typeof this._layer4.rit.gateAccess === 'function') {
            const gateResult = await this._layer4.rit.gateAccess(entry.entryId);
            return gateResult.allowed ? 'IDENTITY_VERIFIED' : 'IDENTITY_BLOCKED';
          }
        }
        return 'RIT_NOT_CONNECTED';

      case 'CBQE':
        if (this._layer4 && this._layer4.cbqe) {
          if (typeof this._layer4.cbqe.rotateField === 'function') {
            await this._layer4.cbqe.rotateField(mitigation.reason);
            return 'FIELD_ROTATED';
          }
        }
        return 'CBQE_NOT_CONNECTED';

      case 'TSB':
        if (this._tsb) {
          if (typeof this._tsb.validateEntry === 'function') {
            await this._tsb.validateEntry(entry.entryId, entry.contentHash);
            return 'CACHE_VALIDATED';
          }
        }
        return 'TSB_NOT_CONNECTED';

      default:
        return 'UNKNOWN_ENGINE';
    }
  }

  // --------------------------------------------------------------------------
  // Validation
  // --------------------------------------------------------------------------

  /**
   * Validate all cache entries against the current policy.
   *
   * @returns {Promise<Object>} Validation report
   */
  async validateAllCaches() {
    const report = {
      reportId: _generateId(),
      timestamp: _nowISO(),
      policyId: this._currentPolicy ? this._currentPolicy.policyId : null,
      totalEntries: this._cacheRegistry.size,
      valid: 0,
      invalid: 0,
      pending: 0,
      quarantined: 0,
      entries: [],
    };

    for (const [, entry] of this._cacheRegistry) {
      let currentState = entry.validationState;

      // Re-check posture compliance
      if (this._currentPolicy && entry.postureAtCache < this._currentPolicy.postureLevel) {
        if (currentState === 'VALID') {
          currentState = 'PENDING';
          entry.validationState = 'PENDING';
          entry.lastValidatedAt = _nowISO();
          entry.validationHistory.push({
            timestamp: _nowISO(),
            state: 'PENDING',
            policyId: this._currentPolicy.policyId,
            reason: 'Posture level at cache (' + entry.postureAtCache + ') is below current policy (' + this._currentPolicy.postureLevel + ').',
          });
        }
      }

      switch (currentState) {
        case 'VALID':
          report.valid++;
          break;
        case 'INVALID':
          report.invalid++;
          break;
        case 'PENDING':
          report.pending++;
          break;
        case 'QUARANTINED':
          report.quarantined++;
          break;
      }

      report.entries.push({
        entryId: entry.entryId,
        contentName: entry.contentName,
        contentType: entry.contentType,
        validationState: entry.validationState,
        postureAtCache: entry.postureAtCache,
        lastValidatedAt: entry.lastValidatedAt,
      });
    }

    this._addAudit(TransitionType.POSTURE_CHANGE, 'Cache validation sweep completed', {
      reportId: report.reportId,
      valid: report.valid,
      invalid: report.invalid,
      pending: report.pending,
      quarantined: report.quarantined,
    });

    return report;
  }

  // --------------------------------------------------------------------------
  // Emergency Lockdown
  // --------------------------------------------------------------------------

  /**
   * Trigger emergency lockdown across ALL connected engines.
   * Sets posture to CRITICAL (5), blocks all cache entries, and notifies all engines.
   *
   * @param {string} reason - Reason for the lockdown
   * @returns {Promise<Object>} Lockdown report
   */
  async emergencyLockdown(reason) {
    this._isLockedDown = true;
    this._lockdownReason = reason;
    this._lockdownTimestamp = _nowISO();

    const lockdownPolicy = new PolicyState({
      policyId: _generateId(),
      timestamp: _nowISO(),
      postureLevel: 5, // CRITICAL
      activeConsents: this._currentPolicy ? this._currentPolicy.activeConsents : [],
      networkPolicyVersion: this._currentPolicy ? this._currentPolicy.networkPolicyVersion : '1.0.0',
      skillContractsVersion: this._currentPolicy ? this._currentPolicy.skillContractsVersion : '1.0.0',
      tenantConfigVersion: this._currentPolicy ? this._currentPolicy.tenantConfigVersion : '1.0.0',
      identityFingerprint: this._currentPolicy ? this._currentPolicy.identityFingerprint : null,
      encryptionKeyGeneration: this._currentPolicy ? this._currentPolicy.encryptionKeyGeneration : 1,
      regulatoryFlags: Object.assign({}, this._currentPolicy ? this._currentPolicy.regulatoryFlags : {}, {
        EMERGENCY_LOCKDOWN: true,
      }),
    });

    let delta = null;
    if (this._currentPolicy) {
      delta = await this.processPolicyTransition(
        lockdownPolicy,
        TransitionType.EMERGENCY_LOCKDOWN,
        'EMERGENCY LOCKDOWN: ' + reason
      );
    } else {
      this.setInitialPolicy(lockdownPolicy);
    }

    // Block all remaining valid entries
    for (const [, entry] of this._cacheRegistry) {
      if (entry.validationState === 'VALID' || entry.validationState === 'PENDING') {
        entry.validationState = 'INVALID';
        entry.mitigationAction = MitigationAction.BLOCK;
        entry.mitigationTimestamp = _nowISO();
        entry.mitigationReason = 'Emergency lockdown: ' + reason;
        entry.validationHistory.push({
          timestamp: _nowISO(),
          state: 'INVALID',
          policyId: lockdownPolicy.policyId,
          reason: 'Emergency lockdown',
          action: MitigationAction.BLOCK,
        });
      }
    }

    // Cascade lockdown to connected engines
    const cascadeResults = [];

    if (this._layer2) {
      if (this._layer2.d34 && typeof this._layer2.d34.emergencyLockdown === 'function') {
        try {
          await this._layer2.d34.emergencyLockdown(reason);
          cascadeResults.push({ engine: 'D34', status: 'LOCKED' });
        } catch (err) {
          cascadeResults.push({ engine: 'D34', status: 'ERROR', error: err.message });
        }
      }
      if (this._layer2.d37 && typeof this._layer2.d37.emergencyLockdown === 'function') {
        try {
          await this._layer2.d37.emergencyLockdown(reason);
          cascadeResults.push({ engine: 'D37', status: 'LOCKED' });
        } catch (err) {
          cascadeResults.push({ engine: 'D37', status: 'ERROR', error: err.message });
        }
      }
    }

    if (this._layer3) {
      for (const key of ['d43', 'd48', 'd49', 'd58']) {
        const engine = this._layer3[key];
        if (engine && typeof engine.emergencyLockdown === 'function') {
          try {
            await engine.emergencyLockdown(reason);
            cascadeResults.push({ engine: key.toUpperCase(), status: 'LOCKED' });
          } catch (err) {
            cascadeResults.push({ engine: key.toUpperCase(), status: 'ERROR', error: err.message });
          }
        }
      }
    }

    if (this._layer4) {
      if (this._layer4.cbqe && typeof this._layer4.cbqe.rotateField === 'function') {
        try {
          await this._layer4.cbqe.rotateField('Emergency lockdown: ' + reason);
          cascadeResults.push({ engine: 'CBQE', status: 'FIELD_ROTATED' });
        } catch (err) {
          cascadeResults.push({ engine: 'CBQE', status: 'ERROR', error: err.message });
        }
      }
    }

    if (this._qeratheon && typeof this._qeratheon.emergencyLockdown === 'function') {
      try {
        await this._qeratheon.emergencyLockdown(reason);
        cascadeResults.push({ engine: 'QERATHEON', status: 'LOCKED' });
      } catch (err) {
        cascadeResults.push({ engine: 'QERATHEON', status: 'ERROR', error: err.message });
      }
    }

    if (this._tsb && typeof this._tsb.emergencyLockdown === 'function') {
      try {
        await this._tsb.emergencyLockdown(reason);
        cascadeResults.push({ engine: 'TSB', status: 'LOCKED' });
      } catch (err) {
        cascadeResults.push({ engine: 'TSB', status: 'ERROR', error: err.message });
      }
    }

    const report = {
      lockdownId: _generateId(),
      timestamp: this._lockdownTimestamp,
      reason: reason,
      policyId: lockdownPolicy.policyId,
      postureLevel: 5,
      blockedEntries: this._cacheRegistry.size,
      cascadeResults: cascadeResults,
      deltaId: delta ? delta.deltaId : null,
    };

    this._addAudit(TransitionType.EMERGENCY_LOCKDOWN, reason, report);

    return report;
  }

  // --------------------------------------------------------------------------
  // Status and Reporting
  // --------------------------------------------------------------------------

  /**
   * Get comprehensive system status from all layers.
   *
   * @returns {Object}
   */
  getSystemStatus() {
    const status = {
      orchestratorVersion: '1.0.0',
      timestamp: _nowISO(),
      agentId: this._agentId,
      isLockedDown: this._isLockedDown,
      lockdownReason: this._lockdownReason,
      lockdownTimestamp: this._lockdownTimestamp,
      currentPolicy: this._currentPolicy ? this._currentPolicy.toJSON() : null,
      policyTransitionCount: this._deltaHistory.length,
      cacheEntryCount: this._cacheRegistry.size,
      auditEntryCount: this._auditTrail.length,
      connectedEngines: {
        layer2: this._layer2 ? Object.keys(this._layer2) : [],
        layer3: this._layer3 ? Object.keys(this._layer3) : [],
        layer4: this._layer4 ? Object.keys(this._layer4) : [],
        qeratheon: !!this._qeratheon,
        tsb: !!this._tsb,
      },
    };

    // Cache state summary
    let valid = 0, invalid = 0, pending = 0, quarantined = 0;
    for (const [, entry] of this._cacheRegistry) {
      switch (entry.validationState) {
        case 'VALID': valid++; break;
        case 'INVALID': invalid++; break;
        case 'PENDING': pending++; break;
        case 'QUARANTINED': quarantined++; break;
      }
    }
    status.cacheStateSummary = {
      valid: valid,
      invalid: invalid,
      pending: pending,
      quarantined: quarantined,
    };

    // Layer-specific statuses
    if (this._layer4) {
      if (this._layer4.rit && typeof this._layer4.rit.getVerificationHistory === 'function') {
        status.ritVerificationCount = this._layer4.rit.getVerificationHistory().length;
      }
      if (this._layer4.cbqe && typeof this._layer4.cbqe.getSecurityLevel === 'function') {
        status.cbqeSecurityLevel = this._layer4.cbqe.getSecurityLevel();
      }
    }

    return status;
  }

  /**
   * Get the combined audit trail from the orchestrator.
   *
   * @returns {Object[]}
   */
  getAuditTrail() {
    return this._auditTrail.map(function (e) { return e.toJSON(); });
  }

  /**
   * Get all policy states and transitions.
   *
   * @returns {Object}
   */
  getPolicyHistory() {
    return {
      policies: this._policyHistory.map(function (p) { return p.toJSON(); }),
      deltas: this._deltaHistory.map(function (d) { return d.toJSON(); }),
      totalPolicies: this._policyHistory.length,
      totalTransitions: this._deltaHistory.length,
    };
  }

  /**
   * Get all tracked cache entries.
   *
   * @returns {CacheEntry[]}
   */
  getCacheRegistry() {
    const entries = [];
    for (const [, entry] of this._cacheRegistry) {
      entries.push(entry.toJSON());
    }
    return entries;
  }

  // --------------------------------------------------------------------------
  // Internal Helpers
  // --------------------------------------------------------------------------

  /**
   * Add an audit entry.
   *
   * @private
   * @param {string} transitionType
   * @param {string} reason
   * @param {Object} details
   */
  _addAudit(transitionType, reason, details) {
    this._auditTrail.push(new AuditEntry({
      entryId: _generateId(),
      timestamp: _nowISO(),
      transitionType: transitionType,
      reason: reason,
      details: details || {},
    }));
  }
}

// ============================================================================
// Public API: window.StaamlOrchestrator
// ============================================================================

/**
 * StaamlOrchestrator public interface.
 */
const StaamlOrchestrator = Object.freeze({
  /** @type {string} */
  VERSION: '1.0.0',

  /** Enums */
  PolicyDomain: PolicyDomain,
  TransitionType: TransitionType,
  MitigationAction: MitigationAction,
  PostureDirection: PostureDirection,

  /** Data classes */
  CacheEntry: CacheEntry,
  PolicyState: PolicyState,
  PolicyDelta: PolicyDelta,
  AuditEntry: AuditEntry,

  /** Orchestrator class */
  StaamlTSBOrchestrator: StaamlTSBOrchestrator,

  /** @private */
  _instance: null,

  /**
   * Initialize the orchestrator and optionally connect all layer engines.
   *
   * @param {string} masterKey - Hex-encoded master key (at least 64 hex chars)
   * @param {string} agentId - Unique agent identifier
   * @param {Object} [engines] - Optional pre-created engine instances to connect
   * @param {Object} [engines.layer2] - Layer 2 engines (d34, d37)
   * @param {Object} [engines.layer3] - Layer 3 engines (d43, d48, d49, d58)
   * @param {Object} [engines.layer4] - Layer 4 engines (rit, cbqe)
   * @param {Object} [engines.qeratheon] - QeratheonCore instance
   * @param {Object} [engines.tsb] - TSB cache engine instance
   * @returns {StaamlTSBOrchestrator}
   */
  init(masterKey, agentId, engines) {
    const orchestrator = new StaamlTSBOrchestrator(masterKey, agentId);

    if (engines) {
      if (engines.layer2) orchestrator.connectLayer2(engines.layer2);
      if (engines.layer3) orchestrator.connectLayer3(engines.layer3);
      if (engines.layer4) orchestrator.connectLayer4(engines.layer4);
      if (engines.qeratheon) orchestrator.connectQeratheon(engines.qeratheon);
      if (engines.tsb) orchestrator.connectTSB(engines.tsb);
    }

    // Store as singleton for convenience methods
    StaamlOrchestrator._instance = orchestrator;
    return orchestrator;
  },

  /**
   * Process a policy transition on the singleton instance.
   *
   * @param {Object} newPolicy
   * @param {string} type - TransitionType value
   * @param {string} reason
   * @returns {Promise<PolicyDelta>}
   */
  async processPolicyTransition(newPolicy, type, reason) {
    if (!StaamlOrchestrator._instance) {
      throw new Error('Orchestrator not initialized. Call StaamlOrchestrator.init() first.');
    }
    return StaamlOrchestrator._instance.processPolicyTransition(newPolicy, type, reason);
  },

  /**
   * Trigger emergency lockdown on the singleton instance.
   *
   * @param {string} reason
   * @returns {Promise<Object>}
   */
  async emergencyLockdown(reason) {
    if (!StaamlOrchestrator._instance) {
      throw new Error('Orchestrator not initialized. Call StaamlOrchestrator.init() first.');
    }
    return StaamlOrchestrator._instance.emergencyLockdown(reason);
  },

  /**
   * Get system status from the singleton instance.
   *
   * @returns {Object}
   */
  getSystemStatus() {
    if (!StaamlOrchestrator._instance) {
      return {
        orchestratorVersion: '1.0.0',
        initialized: false,
        timestamp: _nowISO(),
      };
    }
    return StaamlOrchestrator._instance.getSystemStatus();
  },

  /**
   * Get audit trail from the singleton instance.
   *
   * @returns {Object[]}
   */
  getAuditTrail() {
    if (!StaamlOrchestrator._instance) {
      return [];
    }
    return StaamlOrchestrator._instance.getAuditTrail();
  },

  /**
   * Get policy history from the singleton instance.
   *
   * @returns {Object}
   */
  getPolicyHistory() {
    if (!StaamlOrchestrator._instance) {
      return { policies: [], deltas: [], totalPolicies: 0, totalTransitions: 0 };
    }
    return StaamlOrchestrator._instance.getPolicyHistory();
  },

  /**
   * Validate all caches on the singleton instance.
   *
   * @returns {Promise<Object>}
   */
  async validateAllCaches() {
    if (!StaamlOrchestrator._instance) {
      throw new Error('Orchestrator not initialized. Call StaamlOrchestrator.init() first.');
    }
    return StaamlOrchestrator._instance.validateAllCaches();
  },
});

// Attach to window if available (browser), otherwise export for Node/testing
if (typeof window !== 'undefined') {
  window.StaamlOrchestrator = StaamlOrchestrator;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = StaamlOrchestrator;
}
