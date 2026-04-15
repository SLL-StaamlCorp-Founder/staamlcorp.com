'use strict';

/**
 * StaamlCorp Temporal Security Derivative D49
 * Posture-Aware Machine Learning Model Cache
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

  globalThis.StaamlD49 = { PostureLevel, generateId, now, sha256 };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
