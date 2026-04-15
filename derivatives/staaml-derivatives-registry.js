'use strict';

/**
 * StaamlCorp Derivative Registry — All 71 Temporal Security Derivatives
 * Master coordination layer connecting all derivative tiers.
 *
 * Integrates:
 *   - StaamlDerivativesCore     (D1-D12)   staaml-derivatives-core.js
 *   - StaamlDerivativesNetwork  (D13-D28)  staaml-derivatives-network.js
 *   - StaamlDerivativesInfra    (D29-D42)  staaml-derivatives-infra.js
 *   - StaamlLayer2              (D34,D37,D48,D49,D58) staaml-layer2-governance.js [existing]
 *   - StaamlLayer3              (D33,D35,D36,D38,D43,D50) staaml-layer3-infrastructure.js [existing]
 *   - StaamlDerivativesRuntime  (D44-D57)  staaml-derivatives-runtime.js
 *   - StaamlDerivativesExtended (D59-D71)  staaml-derivatives-extended.js
 *
 * Cross-module event bus, dependency graph, and conflict resolution.
 *
 * U.S. Patent Application No. 19/640,793
 * (c) 2024-2026 StaamlCorp. All rights reserved.
 *
 * @version 1.0.0
 * @license Proprietary - StaamlCorp
 */
(function (globalThis) {

  // ===========================================================================
  // Constants
  // ===========================================================================

  const REGISTRY_VERSION = '1.0.0';

  /** @enum {string} */
  const DerivativeTier = Object.freeze({
    HARDWARE_OS:     'hardware_os',
    NETWORK:         'network',
    CACHE_STORAGE:   'cache_storage',
    CRYPTO:          'crypto',
    VALIDATION:      'validation',
    COMPLIANCE:      'compliance',
    INFRASTRUCTURE:  'infrastructure',
  });

  /** @enum {string} */
  const EventType = Object.freeze({
    EPOCH_ADVANCE:           'epoch_advance',
    POSTURE_TRANSITION:      'posture_transition',
    POLICY_CHANGE:           'policy_change',
    KEY_ROTATION:            'key_rotation',
    BIOMETRIC_TRIGGER:       'biometric_trigger',
    GEO_FENCE_CHANGE:        'geo_fence_change',
    FIRMWARE_UPDATE:          'firmware_update',
    CONTAINER_DEPLOY:        'container_deploy',
    REGULATORY_CHANGE:       'regulatory_change',
    AI_AGENT_ACTION:         'ai_agent_action',
    PACKAGE_UPDATE:          'package_update',
    BROWSER_EXTENSION_UPDATE:'browser_extension_update',
  });

  /** @enum {string} */
  const ConflictStrategy = Object.freeze({
    MOST_RESTRICTIVE: 'most_restrictive',
    LEAST_RESTRICTIVE: 'least_restrictive',
    MAJORITY_VOTE:     'majority_vote',
  });

  // ===========================================================================
  // Derivative Catalog — All 71 Derivatives
  // ===========================================================================

  const DERIVATIVE_CATALOG = Object.freeze({
    1:  { name: 'Container Cache Coherency',            tier: DerivativeTier.HARDWARE_OS,    source: 'core' },
    2:  { name: 'BPF LSM Policy Monitoring',            tier: DerivativeTier.HARDWARE_OS,    source: 'core' },
    3:  { name: 'MDM Integration',                      tier: DerivativeTier.COMPLIANCE,     source: 'core' },
    4:  { name: 'Parallel Validation Pipeline',         tier: DerivativeTier.VALIDATION,     source: 'core' },
    5:  { name: 'Legacy Wrapper Framework',             tier: DerivativeTier.INFRASTRUCTURE, source: 'core' },
    6:  { name: 'Compliance Documentation Generator',   tier: DerivativeTier.COMPLIANCE,     source: 'core' },
    7:  { name: 'Development Toolkit',                  tier: DerivativeTier.INFRASTRUCTURE, source: 'core' },
    8:  { name: 'Distributed Posture Sync',             tier: DerivativeTier.NETWORK,        source: 'core' },
    9:  { name: 'Hardware-Accelerated Validation',      tier: DerivativeTier.HARDWARE_OS,    source: 'core' },
    10: { name: 'Adaptive Load Balancer',               tier: DerivativeTier.VALIDATION,     source: 'core' },
    11: { name: 'Cache Partitioning',                   tier: DerivativeTier.CACHE_STORAGE,  source: 'core' },
    12: { name: 'Speculative Validation',               tier: DerivativeTier.VALIDATION,     source: 'core' },
    13: { name: 'TLS Session Posture Binding',          tier: DerivativeTier.NETWORK,        source: 'network' },
    14: { name: 'File System Posture Tagging',          tier: DerivativeTier.CACHE_STORAGE,  source: 'network' },
    15: { name: 'Browser Storage Posture Controller',   tier: DerivativeTier.CACHE_STORAGE,  source: 'network' },
    16: { name: 'Firmware Update Posture Validator',    tier: DerivativeTier.HARDWARE_OS,    source: 'network' },
    17: { name: 'API Gateway Posture Enforcer',         tier: DerivativeTier.NETWORK,        source: 'network' },
    18: { name: 'Message Queue Posture Bridge',         tier: DerivativeTier.NETWORK,        source: 'network' },
    19: { name: 'Service Mesh Posture Sidecar',         tier: DerivativeTier.NETWORK,        source: 'network' },
    20: { name: 'Secrets Manager Posture Rotation',     tier: DerivativeTier.CRYPTO,         source: 'network' },
    21: { name: 'CI/CD Pipeline Posture Gate',          tier: DerivativeTier.INFRASTRUCTURE, source: 'network' },
    22: { name: 'Eventually Consistent Synchronizer',   tier: DerivativeTier.VALIDATION,     source: 'network' },
    23: { name: 'Epidemic Policy Distribution',         tier: DerivativeTier.NETWORK,        source: 'network' },
    24: { name: 'Dependency-Aware Scheduler',           tier: DerivativeTier.VALIDATION,     source: 'network' },
    25: { name: 'Differential Privacy Logging',         tier: DerivativeTier.COMPLIANCE,     source: 'network' },
    26: { name: 'Geo-Aware Validation',                 tier: DerivativeTier.COMPLIANCE,     source: 'network' },
    27: { name: 'Regulatory Impact Analyzer',           tier: DerivativeTier.COMPLIANCE,     source: 'network' },
    28: { name: 'Cryptographic Audit Trail',            tier: DerivativeTier.COMPLIANCE,     source: 'network' },
    29: { name: 'Legacy Posture Proxy',                 tier: DerivativeTier.INFRASTRUCTURE, source: 'infra' },
    30: { name: 'Posture Metadata Inference',           tier: DerivativeTier.VALIDATION,     source: 'infra' },
    31: { name: 'Universal Posture Translation',        tier: DerivativeTier.INFRASTRUCTURE, source: 'infra' },
    32: { name: 'Cross-Org Federation',                 tier: DerivativeTier.INFRASTRUCTURE, source: 'infra' },
    33: { name: 'P-MESI Cache Coherency',               tier: DerivativeTier.HARDWARE_OS,    source: 'infra+layer3' },
    34: { name: 'P-MPU Memory Protection',              tier: DerivativeTier.HARDWARE_OS,    source: 'infra+layer2' },
    35: { name: 'Hardware Posture Barriers',            tier: DerivativeTier.HARDWARE_OS,    source: 'infra+layer3' },
    36: { name: 'Process Creation Validation',          tier: DerivativeTier.HARDWARE_OS,    source: 'infra+layer3' },
    37: { name: 'Kernel-Space Validation',              tier: DerivativeTier.HARDWARE_OS,    source: 'infra+layer2' },
    38: { name: 'IPC Content Validation',               tier: DerivativeTier.HARDWARE_OS,    source: 'infra+layer3' },
    39: { name: 'Posture-Tagged VM Manager',            tier: DerivativeTier.INFRASTRUCTURE, source: 'infra' },
    40: { name: 'Container Image Scanner',              tier: DerivativeTier.INFRASTRUCTURE, source: 'infra' },
    41: { name: 'Kubernetes Controller',                tier: DerivativeTier.INFRASTRUCTURE, source: 'infra' },
    42: { name: 'Hypervisor Isolation',                 tier: DerivativeTier.HARDWARE_OS,    source: 'infra' },
    43: { name: 'HTTP Posture Cache Protocol',          tier: DerivativeTier.NETWORK,        source: 'layer3' },
    44: { name: 'DNS Posture Policy Records',           tier: DerivativeTier.NETWORK,        source: 'runtime' },
    45: { name: 'JIT Compiler Invalidation',            tier: DerivativeTier.CACHE_STORAGE,  source: 'runtime' },
    46: { name: 'WASM Runtime Lifecycle',               tier: DerivativeTier.CACHE_STORAGE,  source: 'runtime' },
    47: { name: 'Database Query Plan Cache',            tier: DerivativeTier.CACHE_STORAGE,  source: 'runtime' },
    48: { name: 'Multi-Tenant Isolation',               tier: DerivativeTier.CACHE_STORAGE,  source: 'layer2' },
    49: { name: 'ML Model Cache',                       tier: DerivativeTier.CACHE_STORAGE,  source: 'layer2' },
    50: { name: 'Blockchain Posture Binding',           tier: DerivativeTier.CRYPTO,         source: 'layer3' },
    51: { name: 'Biometric Posture Triggers',           tier: DerivativeTier.CRYPTO,         source: 'runtime' },
    52: { name: 'Quantum-Resistant Binding',            tier: DerivativeTier.CRYPTO,         source: 'runtime' },
    53: { name: 'Energy-Harvesting Device Posture',     tier: DerivativeTier.INFRASTRUCTURE, source: 'runtime' },
    54: { name: 'GPU Kernel Cache',                     tier: DerivativeTier.CACHE_STORAGE,  source: 'runtime' },
    55: { name: '5G Slice Posture Binding',             tier: DerivativeTier.NETWORK,        source: 'runtime' },
    56: { name: 'Inferred Posture Fingerprinting',      tier: DerivativeTier.VALIDATION,     source: 'runtime' },
    57: { name: 'Zero-Latency Enforcer',                tier: DerivativeTier.VALIDATION,     source: 'runtime' },
    58: { name: 'AI Agent Behavioral Fingerprinting',   tier: DerivativeTier.COMPLIANCE,     source: 'layer2' },
    59: { name: 'Physics-Aware Deferral Scheduler',     tier: DerivativeTier.INFRASTRUCTURE, source: 'extended' },
    60: { name: 'Multi-Perspective Rendering',          tier: DerivativeTier.INFRASTRUCTURE, source: 'extended' },
    61: { name: 'Enhancement Program Integration',      tier: DerivativeTier.COMPLIANCE,     source: 'extended' },
    62: { name: 'WebView Cache Posture',                tier: DerivativeTier.CACHE_STORAGE,  source: 'extended' },
    63: { name: 'UEFI Boot Cache Binding',              tier: DerivativeTier.HARDWARE_OS,    source: 'extended' },
    64: { name: 'AI Agent Tool Cache',                  tier: DerivativeTier.COMPLIANCE,     source: 'extended' },
    65: { name: 'CI/CD Artifact Cache Gate',            tier: DerivativeTier.INFRASTRUCTURE, source: 'extended' },
    66: { name: 'Serverless Warm Cache',                tier: DerivativeTier.INFRASTRUCTURE, source: 'extended' },
    67: { name: 'Browser Extension Cache',              tier: DerivativeTier.CACHE_STORAGE,  source: 'extended' },
    68: { name: 'Shared Memory Posture Binding',        tier: DerivativeTier.CACHE_STORAGE,  source: 'extended' },
    69: { name: 'Extended Network Session Cache',       tier: DerivativeTier.NETWORK,        source: 'extended' },
    70: { name: 'Package Manager Cache Gate',           tier: DerivativeTier.CACHE_STORAGE,  source: 'extended' },
    71: { name: 'PWA Installation Cache',               tier: DerivativeTier.CACHE_STORAGE,  source: 'extended' },
  });

  // ===========================================================================
  // Tier Classification
  // ===========================================================================

  const TIER_MEMBERS = Object.freeze({
    [DerivativeTier.HARDWARE_OS]:    [1, 2, 9, 16, 33, 34, 35, 36, 37, 38, 42, 63],
    [DerivativeTier.NETWORK]:        [8, 13, 17, 18, 19, 23, 43, 44, 55, 69],
    [DerivativeTier.CACHE_STORAGE]:  [11, 14, 15, 45, 46, 47, 48, 49, 54, 62, 67, 68, 70, 71],
    [DerivativeTier.CRYPTO]:         [20, 50, 51, 52],
    [DerivativeTier.VALIDATION]:     [4, 10, 12, 22, 24, 30, 56, 57],
    [DerivativeTier.COMPLIANCE]:     [3, 6, 25, 26, 27, 28, 58, 61, 64],
    [DerivativeTier.INFRASTRUCTURE]: [5, 7, 21, 29, 31, 32, 39, 40, 41, 53, 59, 60, 65, 66],
  });

  // ===========================================================================
  // Event Subscriptions
  // ===========================================================================

  const EVENT_SUBSCRIPTIONS = Object.freeze({
    [EventType.EPOCH_ADVANCE]:            Array.from({ length: 71 }, (_, i) => i + 1),
    [EventType.POSTURE_TRANSITION]:       [1,4,5,10,11,12,13,14,15,16,17,18,19,20,33,34,35,36,37,38,39,42,43,45,46,47,48,49,54,57,62,63,66,67,68,69,70,71],
    [EventType.POLICY_CHANGE]:            [6,17,21,25,26,27,28,31,32,41,58,61,64,65,67],
    [EventType.KEY_ROTATION]:             [9,13,16,20,50,52,69],
    [EventType.BIOMETRIC_TRIGGER]:        [48,51,57],
    [EventType.GEO_FENCE_CHANGE]:         [26,27,32],
    [EventType.FIRMWARE_UPDATE]:           [9,16,33,34,35,37,53,63],
    [EventType.CONTAINER_DEPLOY]:         [1,2,40,41,46,65,66],
    [EventType.REGULATORY_CHANGE]:        [6,25,26,27,28,31,32,58,61,64],
    [EventType.AI_AGENT_ACTION]:          [49,58,64],
    [EventType.PACKAGE_UPDATE]:           [21,65,70],
    [EventType.BROWSER_EXTENSION_UPDATE]: [15,62,67,71],
  });

  // ===========================================================================
  // Dependency Graph
  // ===========================================================================

  const DEPENDENCY_GRAPH = Object.freeze({
    17: [13],       // Gateway depends on TLS session
    18: [17],       // MQ bridge depends on gateway
    28: [17,18,26], // Audit depends on gateway + geo
    21: [20],       // CI/CD depends on secrets rotation
    32: [26,27],    // Federation depends on geo + regulatory
    25: [26],       // DP logging depends on geo
    57: [35],       // Zero-latency depends on barriers
    41: [40],       // K8s depends on container scanner
    31: [30],       // Translation depends on inference
    23: [22],       // Epidemic depends on EC sync
    62: [15],       // WebView depends on browser storage
    63: [16],       // UEFI depends on firmware posture
    64: [58],       // Agent cache depends on agent fingerprinting
    65: [20,21],    // CI/CD artifact depends on secrets + pipeline gate
    66: [41],       // Serverless depends on K8s
    67: [15],       // Extension depends on browser storage
    68: [5],        // Shared memory depends on process validation
    69: [13],       // Extended network depends on TLS session
    70: [65],       // Package cache depends on CI/CD artifact
    71: [15,46],    // PWA depends on browser storage + WASM runtime
  });

  // ===========================================================================
  // PostureEventBus — Cross-Module Event Routing
  // ===========================================================================

  class PostureEventBus {
    constructor() {
      /** @type {Map<string, Function[]>} */
      this._subscribers = new Map();
      this._eventLog = [];
    }

    /**
     * Subscribe a derivative engine to an event type.
     * @param {string} eventType
     * @param {number} derivativeNum
     * @param {Function} handler
     */
    subscribe(eventType, derivativeNum, handler) {
      const key = eventType;
      if (!this._subscribers.has(key)) this._subscribers.set(key, []);
      this._subscribers.get(key).push({ derivativeNum, handler });
    }

    /**
     * Publish an event, executing handlers in dependency order.
     * @param {string} eventType
     * @param {Object} payload
     * @returns {Promise<Object[]>} Results from each handler
     */
    async publish(eventType, payload) {
      const handlers = this._subscribers.get(eventType) || [];
      const sorted = this._topologicalSort(handlers.map(h => h.derivativeNum));
      const results = [];

      for (const num of sorted) {
        const handler = handlers.find(h => h.derivativeNum === num);
        if (handler) {
          try {
            const result = await handler.handler(payload);
            results.push({ derivative: num, result, status: 'success' });
          } catch (err) {
            results.push({ derivative: num, error: err.message, status: 'error' });
          }
        }
      }

      this._eventLog.push({
        eventType,
        timestamp: new Date().toISOString(),
        handlersInvoked: sorted.length,
        results: results.length,
      });

      return results;
    }

    /**
     * Topologically sort derivative numbers by dependency graph.
     * @private
     * @param {number[]} nums
     * @returns {number[]}
     */
    _topologicalSort(nums) {
      const numSet = new Set(nums);
      const visited = new Set();
      const order = [];

      const visit = (n) => {
        if (visited.has(n)) return;
        visited.add(n);
        const deps = DEPENDENCY_GRAPH[n] || [];
        for (const dep of deps) {
          if (numSet.has(dep)) visit(dep);
        }
        order.push(n);
      };

      for (const n of nums) visit(n);
      return order;
    }

    getStats() {
      return {
        subscriberCount: Array.from(this._subscribers.values()).reduce((a, b) => a + b.length, 0),
        eventTypes: this._subscribers.size,
        eventsPublished: this._eventLog.length,
      };
    }
  }

  // ===========================================================================
  // ConflictResolver — When Derivatives Disagree
  // ===========================================================================

  class ConflictResolver {
    constructor(strategy) {
      this._strategy = strategy || ConflictStrategy.MOST_RESTRICTIVE;
      this._resolutions = [];
    }

    /**
     * Resolve conflicting posture decisions from multiple derivatives.
     * @param {Object[]} decisions - Array of { derivative, action, postureLevel }
     * @returns {Object} Resolved decision
     */
    resolve(decisions) {
      let resolved;

      switch (this._strategy) {
        case ConflictStrategy.MOST_RESTRICTIVE:
          resolved = decisions.reduce((a, b) =>
            (b.postureLevel > a.postureLevel) ? b : a, decisions[0]);
          break;

        case ConflictStrategy.LEAST_RESTRICTIVE:
          resolved = decisions.reduce((a, b) =>
            (b.postureLevel < a.postureLevel) ? b : a, decisions[0]);
          break;

        case ConflictStrategy.MAJORITY_VOTE: {
          const counts = {};
          for (const d of decisions) {
            counts[d.action] = (counts[d.action] || 0) + 1;
          }
          const winner = Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
          resolved = decisions.find(d => d.action === winner);
          break;
        }

        default:
          resolved = decisions[0];
      }

      this._resolutions.push({
        timestamp: new Date().toISOString(),
        inputCount: decisions.length,
        strategy: this._strategy,
        resolved: resolved,
      });

      return resolved;
    }

    getStats() {
      return {
        strategy: this._strategy,
        totalResolutions: this._resolutions.length,
      };
    }
  }

  // ===========================================================================
  // DerivativeRegistry — Master Registry for All 71
  // ===========================================================================

  class DerivativeRegistry {
    constructor() {
      /** @type {Map<number, Object>} */
      this._engines = new Map();
      this._eventBus = new PostureEventBus();
      this._conflictResolver = new ConflictResolver(ConflictStrategy.MOST_RESTRICTIVE);
      this._initialized = false;
    }

    /**
     * Register a derivative engine instance.
     * @param {number} derivativeNum
     * @param {Object} engine - Must implement onPostureTransition() and getStats()
     */
    register(derivativeNum, engine) {
      if (!DERIVATIVE_CATALOG[derivativeNum]) {
        throw new Error('Unknown derivative: D' + derivativeNum);
      }
      this._engines.set(derivativeNum, engine);

      // Auto-subscribe to relevant events
      for (const [eventType, subscribers] of Object.entries(EVENT_SUBSCRIPTIONS)) {
        if (subscribers.includes(derivativeNum) && typeof engine.onPostureTransition === 'function') {
          this._eventBus.subscribe(eventType, derivativeNum, (payload) => {
            return engine.onPostureTransition(
              payload.priorLevel, payload.currentLevel, payload.delta
            );
          });
        }
      }
    }

    /**
     * Auto-discover and register engines from loaded modules.
     */
    autoDiscover() {
      const sources = [
        { obj: globalThis.StaamlDerivativesCore,     range: [1,12] },
        { obj: globalThis.StaamlDerivativesNetwork,  range: [13,28] },
        { obj: globalThis.StaamlDerivativesInfra,    range: [29,42] },
        { obj: globalThis.StaamlDerivativesRuntime,  range: [44,57] },
        { obj: globalThis.StaamlDerivativesExtended, range: [59,71] },
      ];

      for (const src of sources) {
        if (!src.obj) continue;
        for (let d = src.range[0]; d <= src.range[1]; d++) {
          const engineClass = src.obj['D' + d + 'Engine'];
          if (engineClass) {
            this.register(d, new engineClass());
          }
        }
      }

      this._initialized = true;
    }

    /**
     * Broadcast a posture transition to all registered derivatives.
     * @param {number} priorLevel
     * @param {number} currentLevel
     * @param {Object} delta
     * @param {string} eventType
     * @returns {Promise<Object[]>}
     */
    async broadcastTransition(priorLevel, currentLevel, delta, eventType) {
      return this._eventBus.publish(eventType || EventType.POSTURE_TRANSITION, {
        priorLevel,
        currentLevel,
        delta,
        timestamp: new Date().toISOString(),
      });
    }

    /**
     * Get aggregate statistics from all registered derivatives.
     * @returns {Object}
     */
    getStats() {
      const stats = {
        version: REGISTRY_VERSION,
        totalCataloged: Object.keys(DERIVATIVE_CATALOG).length,
        totalRegistered: this._engines.size,
        registeredDerivatives: Array.from(this._engines.keys()).sort((a, b) => a - b),
        missingDerivatives: [],
        tierBreakdown: {},
        eventBus: this._eventBus.getStats(),
        conflictResolver: this._conflictResolver.getStats(),
        engineStats: {},
      };

      // Find missing
      for (let d = 1; d <= 71; d++) {
        if (DERIVATIVE_CATALOG[d] && !this._engines.has(d)) {
          stats.missingDerivatives.push(d);
        }
      }

      // Tier breakdown
      for (const [tier, members] of Object.entries(TIER_MEMBERS)) {
        const registered = members.filter(m => this._engines.has(m));
        stats.tierBreakdown[tier] = {
          total: members.length,
          registered: registered.length,
          coverage: Math.round((registered.length / members.length) * 100) + '%',
        };
      }

      // Individual engine stats
      for (const [num, engine] of this._engines) {
        if (typeof engine.getStats === 'function') {
          stats.engineStats['D' + num] = engine.getStats();
        }
      }

      return stats;
    }

    /** @returns {PostureEventBus} */
    getEventBus() { return this._eventBus; }

    /** @returns {ConflictResolver} */
    getConflictResolver() { return this._conflictResolver; }

    /** @returns {Object} */
    getCatalog() { return DERIVATIVE_CATALOG; }

    /** @returns {Object} */
    getDependencyGraph() { return DEPENDENCY_GRAPH; }
  }

  // ===========================================================================
  // Export
  // ===========================================================================

  globalThis.StaamlDerivativeRegistry = {
    VERSION: REGISTRY_VERSION,
    DerivativeTier,
    EventType,
    ConflictStrategy,
    DERIVATIVE_CATALOG,
    TIER_MEMBERS,
    EVENT_SUBSCRIPTIONS,
    DEPENDENCY_GRAPH,
    PostureEventBus,
    ConflictResolver,
    DerivativeRegistry,
  };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
