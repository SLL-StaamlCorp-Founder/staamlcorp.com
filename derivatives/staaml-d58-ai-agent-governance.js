'use strict';

/**
 * StaamlCorp Temporal Security Derivative D58
 * AI Agent Behavioral Fingerprinting
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

  globalThis.StaamlD58 = { PostureLevel, generateId, now, sha256 };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
