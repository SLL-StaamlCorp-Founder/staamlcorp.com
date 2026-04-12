/**
 * StaamlCorp Temporal Security Binding (TSB) Engine
 * Core implementation of patent-pending technology
 * U.S. Patent Application No. 19/640,793
 *
 * Method for mitigating security bypasses caused by execution of
 * persistently cached executable content following security policy
 * transitions.
 *
 * Patent Method Claims Implemented:
 *   Claim 1 — Detecting a security policy transition
 *   Claim 2 — Computing a policy delta
 *   Claim 3 — Identifying cached executable content
 *   Claim 4 — Extracting temporal attributes (when cached, under what policy)
 *   Claim 5 — Validating against current policy
 *   Claim 6 — Preventing execution of non-compliant content
 *   Claim 7 — Generating tamper-evident audit trails
 *
 * (c) 2024-2026 StaamlCorp. All rights reserved.
 */

(function(global) {
  'use strict';

  // ---------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------

  const TSB_VERSION = '1.0.0';
  const LEDGER_STORAGE_KEY = 'staaml_tsb_ledger';
  const AUDIT_STORAGE_KEY = 'staaml_tsb_audit';
  const POLICY_STORAGE_KEY = 'staaml_tsb_policy';
  const QUARANTINE_CACHE_PREFIX = 'staaml-quarantine-';
  const MAX_AUDIT_ENTRIES = 10000;
  const MONITOR_INTERVAL_MS = 2000;

  /**
   * @enum {string}
   * Security policy levels, ordered from least to most restrictive.
   */
  const PolicyLevel = Object.freeze({
    STANDARD: 'standard',
    ELEVATED: 'elevated',
    LOCKDOWN: 'lockdown',
    MAXIMUM:  'maximum'
  });

  /** Numeric severity for comparison. Higher is more restrictive. */
  const POLICY_SEVERITY = Object.freeze({
    [PolicyLevel.STANDARD]: 0,
    [PolicyLevel.ELEVATED]: 1,
    [PolicyLevel.LOCKDOWN]: 2,
    [PolicyLevel.MAXIMUM]:  3
  });

  /**
   * @enum {string}
   * Content type classifications for cached executable content.
   */
  const ContentType = Object.freeze({
    JAVASCRIPT:      'javascript',
    WEBASSEMBLY:     'webassembly',
    SERVICE_WORKER:  'service-worker',
    JSON_DATA:       'json-data',
    COMPILED_SHADER: 'compiled-shader',
    ML_MODEL:        'ml-model',
    UNKNOWN:         'unknown'
  });

  /**
   * @enum {string}
   * Cache source classifications.
   */
  const CacheSource = Object.freeze({
    CACHE_API:       'cache-api',
    LOCAL_STORAGE:   'local-storage',
    SESSION_STORAGE: 'session-storage',
    INDEXED_DB:      'indexed-db'
  });

  /**
   * @enum {string}
   * Validation result codes (Claim 5).
   */
  const ValidationResult = Object.freeze({
    VALID:            'VALID',
    INVALID_TYPE:     'INVALID_TYPE',
    INVALID_SOURCE:   'INVALID_SOURCE',
    EXPIRED:          'EXPIRED',
    INTEGRITY_FAILED: 'INTEGRITY_FAILED',
    POLICY_VIOLATION: 'POLICY_VIOLATION'
  });

  /**
   * @enum {string}
   * Mitigation actions (Claim 6).
   */
  const MitigationAction = Object.freeze({
    QUARANTINE:  'quarantine',
    INVALIDATE:  'invalidate',
    REGENERATE:  'regenerate',
    BLOCK:       'block',
    NONE:        'none'
  });

  // ---------------------------------------------------------------------------
  // SecurityPolicy — Claim 1 & 2: Policy definition, transition detection
  // ---------------------------------------------------------------------------

  /**
   * Defines the security constraints for a given policy level.
   * Each level specifies what cached content is permissible,
   * from which sources, and under what temporal constraints.
   *
   * @class
   * @param {string} level - One of PolicyLevel values
   */
  class SecurityPolicy {
    constructor(level) {
      if (!POLICY_SEVERITY.hasOwnProperty(level)) {
        throw new Error(`Invalid policy level: ${level}`);
      }
      this.level = level;
      this.severity = POLICY_SEVERITY[level];
      this.createdAt = Date.now();
      Object.assign(this, SecurityPolicy.DEFINITIONS[level]);
    }

    /**
     * Policy definitions per level. Each defines the allowed content types,
     * cache sources, maximum cache age, required integrity checks, and
     * Content-Security-Policy directives.
     */
    static DEFINITIONS = Object.freeze({
      [PolicyLevel.STANDARD]: {
        allowedContentTypes: [
          ContentType.JAVASCRIPT,
          ContentType.WEBASSEMBLY,
          ContentType.SERVICE_WORKER,
          ContentType.JSON_DATA,
          ContentType.COMPILED_SHADER,
          ContentType.ML_MODEL
        ],
        allowedCacheSources: [
          CacheSource.CACHE_API,
          CacheSource.LOCAL_STORAGE,
          CacheSource.SESSION_STORAGE,
          CacheSource.INDEXED_DB
        ],
        maxCacheAgeMs: 7 * 24 * 60 * 60 * 1000, // 7 days
        requiredIntegrityChecks: false,
        cspDirectives: {
          'default-src': "'self'",
          'script-src':  "'self' 'unsafe-inline'",
          'style-src':   "'self' 'unsafe-inline'",
          'connect-src': "'self' https:"
        }
      },

      [PolicyLevel.ELEVATED]: {
        allowedContentTypes: [
          ContentType.JAVASCRIPT,
          ContentType.WEBASSEMBLY,
          ContentType.JSON_DATA,
          ContentType.ML_MODEL
        ],
        allowedCacheSources: [
          CacheSource.CACHE_API,
          CacheSource.LOCAL_STORAGE,
          CacheSource.SESSION_STORAGE
        ],
        maxCacheAgeMs: 24 * 60 * 60 * 1000, // 1 day
        requiredIntegrityChecks: true,
        cspDirectives: {
          'default-src': "'self'",
          'script-src':  "'self'",
          'style-src':   "'self'",
          'connect-src': "'self'"
        }
      },

      [PolicyLevel.LOCKDOWN]: {
        allowedContentTypes: [
          ContentType.JAVASCRIPT,
          ContentType.JSON_DATA
        ],
        allowedCacheSources: [
          CacheSource.CACHE_API
        ],
        maxCacheAgeMs: 4 * 60 * 60 * 1000, // 4 hours
        requiredIntegrityChecks: true,
        cspDirectives: {
          'default-src': "'none'",
          'script-src':  "'self'",
          'style-src':   "'self'",
          'connect-src': "'self'"
        }
      },

      [PolicyLevel.MAXIMUM]: {
        allowedContentTypes: [
          ContentType.JSON_DATA
        ],
        allowedCacheSources: [],
        maxCacheAgeMs: 0, // No cached content allowed
        requiredIntegrityChecks: true,
        cspDirectives: {
          'default-src': "'none'",
          'script-src':  "'none'",
          'style-src':   "'none'",
          'connect-src': "'none'"
        }
      }
    });

    /**
     * Serialize policy for storage / comparison.
     * @returns {Object}
     */
    toJSON() {
      return {
        level: this.level,
        severity: this.severity,
        allowedContentTypes: this.allowedContentTypes,
        allowedCacheSources: this.allowedCacheSources,
        maxCacheAgeMs: this.maxCacheAgeMs,
        requiredIntegrityChecks: this.requiredIntegrityChecks,
        cspDirectives: this.cspDirectives,
        createdAt: this.createdAt
      };
    }
  }

  // ---------------------------------------------------------------------------
  // PolicyDelta — Claim 2: Compute the difference between two policies
  // ---------------------------------------------------------------------------

  /**
   * Computes a structured delta between two SecurityPolicy instances.
   * Identifies which constraints tightened, loosened, or changed.
   *
   * Per Claim 2 of U.S. App. No. 19/640,793: "computing a policy delta
   * that represents the difference between a previous security policy
   * and a current security policy."
   *
   * @param {SecurityPolicy} oldPolicy
   * @param {SecurityPolicy} newPolicy
   * @returns {Object} delta
   */
  function computePolicyDelta(oldPolicy, newPolicy) {
    const removedContentTypes = oldPolicy.allowedContentTypes.filter(
      t => !newPolicy.allowedContentTypes.includes(t)
    );
    const addedContentTypes = newPolicy.allowedContentTypes.filter(
      t => !oldPolicy.allowedContentTypes.includes(t)
    );
    const removedCacheSources = oldPolicy.allowedCacheSources.filter(
      s => !newPolicy.allowedCacheSources.includes(s)
    );
    const addedCacheSources = newPolicy.allowedCacheSources.filter(
      s => !oldPolicy.allowedCacheSources.includes(s)
    );

    const direction = newPolicy.severity > oldPolicy.severity ? 'tightened'
                    : newPolicy.severity < oldPolicy.severity ? 'loosened'
                    : 'lateral';

    return {
      oldLevel: oldPolicy.level,
      newLevel: newPolicy.level,
      direction,
      severityChange: newPolicy.severity - oldPolicy.severity,
      removedContentTypes,
      addedContentTypes,
      removedCacheSources,
      addedCacheSources,
      maxCacheAgeChanged: oldPolicy.maxCacheAgeMs !== newPolicy.maxCacheAgeMs,
      oldMaxCacheAgeMs: oldPolicy.maxCacheAgeMs,
      newMaxCacheAgeMs: newPolicy.maxCacheAgeMs,
      integrityCheckChanged: oldPolicy.requiredIntegrityChecks !== newPolicy.requiredIntegrityChecks,
      newRequiresIntegrity: newPolicy.requiredIntegrityChecks,
      cspChanged: JSON.stringify(oldPolicy.cspDirectives) !== JSON.stringify(newPolicy.cspDirectives),
      timestamp: Date.now()
    };
  }

  // ---------------------------------------------------------------------------
  // SecurityPolicyMonitor — Claim 1: Detect policy transitions
  // ---------------------------------------------------------------------------

  /**
   * Watches for security policy transitions from three sources:
   *   1. Content-Security-Policy header changes (via meta tag observation)
   *   2. <meta http-equiv="Content-Security-Policy"> changes (MutationObserver)
   *   3. Programmatic policy updates via StaamlTSB.setPolicy()
   *
   * Per Claim 1: "detecting a security policy transition in a computing
   * environment."
   *
   * @class
   */
  class SecurityPolicyMonitor {
    constructor() {
      this._observer = null;
      this._intervalId = null;
      this._lastCSPSnapshot = null;
      this._onTransitionCallbacks = [];
    }

    /**
     * Start monitoring for policy transitions.
     * @param {Function} onTransition - callback(oldPolicy, newPolicy, delta)
     */
    start(onTransition) {
      if (typeof onTransition === 'function') {
        this._onTransitionCallbacks.push(onTransition);
      }
      this._lastCSPSnapshot = this._readCSPMetaTags();
      this._startMutationObserver();
      this._startPolling();
    }

    /** Stop monitoring. */
    stop() {
      if (this._observer) {
        this._observer.disconnect();
        this._observer = null;
      }
      if (this._intervalId) {
        clearInterval(this._intervalId);
        this._intervalId = null;
      }
    }

    /**
     * Register an additional transition callback.
     * @param {Function} cb
     */
    onTransition(cb) {
      if (typeof cb === 'function') {
        this._onTransitionCallbacks.push(cb);
      }
    }

    /**
     * Notify all listeners of a policy transition.
     * @param {SecurityPolicy} oldPolicy
     * @param {SecurityPolicy} newPolicy
     * @param {Object} delta
     */
    _notifyTransition(oldPolicy, newPolicy, delta) {
      for (const cb of this._onTransitionCallbacks) {
        try {
          cb(oldPolicy, newPolicy, delta);
        } catch (err) {
          console.error('[TSB] Transition callback error:', err);
        }
      }
    }

    /**
     * Read CSP meta tags from the DOM.
     * @returns {string|null}
     */
    _readCSPMetaTags() {
      const tags = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
      if (tags.length === 0) return null;
      return Array.from(tags).map(t => t.getAttribute('content') || '').join('; ');
    }

    /**
     * MutationObserver on <head> to detect CSP meta tag changes.
     */
    _startMutationObserver() {
      if (typeof MutationObserver === 'undefined') return;

      this._observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          const isCSPRelated =
            (mutation.type === 'childList' && Array.from(mutation.addedNodes).some(
              n => n.nodeName === 'META' && n.getAttribute && n.getAttribute('http-equiv') === 'Content-Security-Policy'
            )) ||
            (mutation.type === 'attributes' && mutation.target.nodeName === 'META' &&
             mutation.target.getAttribute('http-equiv') === 'Content-Security-Policy');

          if (isCSPRelated) {
            const newCSP = this._readCSPMetaTags();
            if (newCSP !== this._lastCSPSnapshot) {
              this._lastCSPSnapshot = newCSP;
              this._onCSPChange(newCSP);
            }
          }
        }
      });

      const head = document.head || document.documentElement;
      this._observer.observe(head, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['content']
      });
    }

    /**
     * Periodic poll as a fallback for detecting programmatic CSP changes.
     */
    _startPolling() {
      this._intervalId = setInterval(() => {
        const current = this._readCSPMetaTags();
        if (current !== this._lastCSPSnapshot) {
          this._lastCSPSnapshot = current;
          this._onCSPChange(current);
        }
      }, MONITOR_INTERVAL_MS);
    }

    /**
     * Handle a detected CSP change by inferring a policy level.
     * @param {string|null} cspContent
     */
    _onCSPChange(cspContent) {
      // Attempt to infer policy level from CSP directives
      const level = this._inferPolicyFromCSP(cspContent);
      if (level && engine) {
        engine._handleExternalPolicySignal(level);
      }
    }

    /**
     * Heuristic: infer policy level from CSP content string.
     * @param {string|null} csp
     * @returns {string|null}
     */
    _inferPolicyFromCSP(csp) {
      if (!csp) return null;
      const lower = csp.toLowerCase();
      if (lower.includes("script-src 'none'")) return PolicyLevel.MAXIMUM;
      if (lower.includes("default-src 'none'") && !lower.includes('unsafe')) return PolicyLevel.LOCKDOWN;
      if (!lower.includes('unsafe-inline') && !lower.includes('unsafe-eval')) return PolicyLevel.ELEVATED;
      return PolicyLevel.STANDARD;
    }
  }

  // ---------------------------------------------------------------------------
  // CacheIdentifier — Claim 3: Identify cached executable content
  // ---------------------------------------------------------------------------

  /**
   * Enumerates and classifies cached content across browser storage APIs.
   *
   * Per Claim 3: "identifying cached executable content that is stored
   * in persistent cache storage of the computing environment."
   *
   * @class
   */
  class CacheIdentifier {

    /**
     * Classify a MIME type or URL into a ContentType.
     * @param {string} mimeOrUrl
     * @returns {string} ContentType value
     */
    static classifyContent(mimeOrUrl) {
      const s = (mimeOrUrl || '').toLowerCase();
      if (s.includes('javascript') || s.endsWith('.js') || s.endsWith('.mjs')) return ContentType.JAVASCRIPT;
      if (s.includes('wasm') || s.endsWith('.wasm')) return ContentType.WEBASSEMBLY;
      if (s.includes('service-worker') || s.includes('sw.js')) return ContentType.SERVICE_WORKER;
      if (s.includes('json') || s.endsWith('.json')) return ContentType.JSON_DATA;
      if (s.includes('shader') || s.endsWith('.glsl') || s.endsWith('.frag') || s.endsWith('.vert')) return ContentType.COMPILED_SHADER;
      if (s.includes('model') || s.endsWith('.onnx') || s.endsWith('.tflite') || s.endsWith('.bin')) return ContentType.ML_MODEL;
      return ContentType.UNKNOWN;
    }

    /**
     * Scan the Cache API (Service Worker caches).
     * @returns {Promise<Array>} Array of cache item descriptors
     */
    static async scanCacheAPI() {
      const items = [];
      if (typeof caches === 'undefined') return items;

      try {
        const cacheNames = await caches.keys();
        for (const name of cacheNames) {
          // Skip our own quarantine caches
          if (name.startsWith(QUARANTINE_CACHE_PREFIX)) continue;

          const cache = await caches.open(name);
          const requests = await cache.keys();
          for (const request of requests) {
            try {
              const response = await cache.match(request);
              if (!response) continue;

              const contentType = CacheIdentifier.classifyContent(
                response.headers.get('content-type') || request.url
              );
              const blob = await response.clone().blob();

              items.push({
                url: request.url,
                source: CacheSource.CACHE_API,
                cacheName: name,
                contentType,
                size: blob.size,
                responseHeaders: Object.fromEntries(response.headers.entries()),
                dateHeader: response.headers.get('date'),
                lastModified: response.headers.get('last-modified')
              });
            } catch (err) {
              // Individual entry errors are non-fatal
              console.warn('[TSB] Cache API entry scan error:', err);
            }
          }
        }
      } catch (err) {
        console.warn('[TSB] Cache API scan error:', err);
      }

      return items;
    }

    /**
     * Scan localStorage for executable content.
     * @returns {Array} Array of cache item descriptors
     */
    static scanLocalStorage() {
      const items = [];
      if (typeof localStorage === 'undefined') return items;

      try {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (!key) continue;
          // Skip TSB internal keys
          if (key.startsWith('staaml_tsb_')) continue;

          const value = localStorage.getItem(key);
          if (!value) continue;

          const contentType = CacheIdentifier._inferContentTypeFromValue(key, value);
          items.push({
            url: 'localStorage://' + key,
            source: CacheSource.LOCAL_STORAGE,
            cacheName: null,
            contentType,
            size: new Blob([value]).size,
            storageKey: key
          });
        }
      } catch (err) {
        console.warn('[TSB] localStorage scan error:', err);
      }

      return items;
    }

    /**
     * Scan sessionStorage for executable content.
     * @returns {Array} Array of cache item descriptors
     */
    static scanSessionStorage() {
      const items = [];
      if (typeof sessionStorage === 'undefined') return items;

      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          if (!key) continue;

          const value = sessionStorage.getItem(key);
          if (!value) continue;

          const contentType = CacheIdentifier._inferContentTypeFromValue(key, value);
          items.push({
            url: 'sessionStorage://' + key,
            source: CacheSource.SESSION_STORAGE,
            cacheName: null,
            contentType,
            size: new Blob([value]).size,
            storageKey: key
          });
        }
      } catch (err) {
        console.warn('[TSB] sessionStorage scan error:', err);
      }

      return items;
    }

    /**
     * Scan IndexedDB for references to executable content.
     * Enumerates databases and their object stores.
     * @returns {Promise<Array>} Array of cache item descriptors
     */
    static async scanIndexedDB() {
      const items = [];
      if (typeof indexedDB === 'undefined' || typeof indexedDB.databases !== 'function') {
        return items;
      }

      try {
        const databases = await indexedDB.databases();
        for (const dbInfo of databases) {
          if (!dbInfo.name) continue;

          try {
            const db = await new Promise((resolve, reject) => {
              const req = indexedDB.open(dbInfo.name, dbInfo.version);
              req.onsuccess = () => resolve(req.result);
              req.onerror = () => reject(req.error);
              // If an upgrade is needed, just close — we only read
              req.onupgradeneeded = (e) => {
                e.target.transaction.abort();
                reject(new Error('upgrade needed'));
              };
            });

            const storeNames = Array.from(db.objectStoreNames);
            for (const storeName of storeNames) {
              try {
                const tx = db.transaction(storeName, 'readonly');
                const store = tx.objectStore(storeName);
                const count = await new Promise((resolve, reject) => {
                  const req = store.count();
                  req.onsuccess = () => resolve(req.result);
                  req.onerror = () => reject(req.error);
                });

                items.push({
                  url: 'indexeddb://' + dbInfo.name + '/' + storeName,
                  source: CacheSource.INDEXED_DB,
                  cacheName: dbInfo.name,
                  contentType: ContentType.UNKNOWN,
                  size: 0, // Cannot determine size without iterating all records
                  storeName,
                  recordCount: count
                });
              } catch (storeErr) {
                // Non-fatal
              }
            }

            db.close();
          } catch (dbErr) {
            // Non-fatal — some DBs may require version upgrades
          }
        }
      } catch (err) {
        console.warn('[TSB] IndexedDB scan error:', err);
      }

      return items;
    }

    /**
     * Heuristic to infer content type from a storage key/value pair.
     * @param {string} key
     * @param {string} value
     * @returns {string} ContentType
     */
    static _inferContentTypeFromValue(key, value) {
      const k = key.toLowerCase();
      if (k.includes('script') || k.includes('.js')) return ContentType.JAVASCRIPT;
      if (k.includes('wasm')) return ContentType.WEBASSEMBLY;
      if (k.includes('shader') || k.includes('glsl')) return ContentType.COMPILED_SHADER;
      if (k.includes('model') || k.includes('onnx')) return ContentType.ML_MODEL;

      // Try to detect by value shape
      const trimmed = (value || '').trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) return ContentType.JSON_DATA;
      if (trimmed.startsWith('function') || trimmed.includes('=>')) return ContentType.JAVASCRIPT;

      return ContentType.UNKNOWN;
    }

    /**
     * Full scan across all cache sources.
     * @returns {Promise<Array>}
     */
    static async scanAll() {
      const [cacheAPI, local, session, idb] = await Promise.all([
        CacheIdentifier.scanCacheAPI(),
        Promise.resolve(CacheIdentifier.scanLocalStorage()),
        Promise.resolve(CacheIdentifier.scanSessionStorage()),
        CacheIdentifier.scanIndexedDB()
      ]);
      return [...cacheAPI, ...local, ...session, ...idb];
    }
  }

  // ---------------------------------------------------------------------------
  // Crypto utilities — SHA-256 hashing via SubtleCrypto
  // ---------------------------------------------------------------------------

  /**
   * Compute a SHA-256 hash of arbitrary data.
   * @param {string|ArrayBuffer|Blob} data
   * @returns {Promise<string>} Hex-encoded hash
   */
  async function sha256(data) {
    let buffer;
    if (typeof data === 'string') {
      buffer = new TextEncoder().encode(data);
    } else if (data instanceof Blob) {
      buffer = await data.arrayBuffer();
    } else if (data instanceof ArrayBuffer) {
      buffer = data;
    } else {
      buffer = new TextEncoder().encode(String(data));
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Generate a unique content ID from a URL and source.
   * @param {string} url
   * @param {string} source
   * @returns {Promise<string>}
   */
  async function generateContentId(url, source) {
    return sha256(url + '|' + source + '|' + location.origin);
  }

  // ---------------------------------------------------------------------------
  // TemporalSecurityLedger — Claim 4: Temporal attribute extraction & binding
  // ---------------------------------------------------------------------------

  /**
   * The Temporal Security Ledger binds each cached item to its security
   * context at the time of caching. This is the core data structure of
   * the TSB patent.
   *
   * Per Claim 4: "extracting temporal attributes including when the
   * content was cached and under what security policy the content was
   * cached."
   *
   * Each binding record contains:
   *   - contentId:          Unique identifier derived from URL + source
   *   - contentHash:        SHA-256 of content (via SubtleCrypto)
   *   - cacheTimestamp:     When the content was cached or first observed
   *   - policyLevelAtCache: The policy level in effect when cached
   *   - source:             CacheSource enum value
   *   - contentType:        ContentType enum value
   *   - size:               Content size in bytes
   *   - integrityTag:       SHA-256 integrity hash
   *   - url:                Original URL / storage key
   *   - lastValidated:      Timestamp of last validation
   *   - validationResult:   Most recent validation outcome
   *
   * @class
   */
  class TemporalSecurityLedger {
    constructor() {
      /** @type {Map<string, Object>} contentId -> binding record */
      this._bindings = new Map();
      this._load();
    }

    /**
     * Load ledger from localStorage.
     */
    _load() {
      try {
        const raw = localStorage.getItem(LEDGER_STORAGE_KEY);
        if (raw) {
          const entries = JSON.parse(raw);
          for (const entry of entries) {
            this._bindings.set(entry.contentId, entry);
          }
        }
      } catch (err) {
        console.warn('[TSB] Ledger load error:', err);
      }
    }

    /**
     * Persist ledger to localStorage.
     */
    _save() {
      try {
        const entries = Array.from(this._bindings.values());
        localStorage.setItem(LEDGER_STORAGE_KEY, JSON.stringify(entries));
      } catch (err) {
        console.warn('[TSB] Ledger save error:', err);
      }
    }

    /**
     * Create or update a temporal binding for a cached item.
     *
     * @param {Object} item - Cache item descriptor from CacheIdentifier
     * @param {string} policyLevel - Current policy level
     * @param {string} contentHash - SHA-256 hash of content
     * @returns {Object} The binding record
     */
    bind(item, policyLevel, contentHash) {
      const contentId = item._contentId; // Pre-computed
      const existing = this._bindings.get(contentId);

      const binding = {
        contentId,
        contentHash,
        cacheTimestamp: existing ? existing.cacheTimestamp : Date.now(),
        policyLevelAtCache: existing ? existing.policyLevelAtCache : policyLevel,
        source: item.source,
        contentType: item.contentType,
        size: item.size || 0,
        integrityTag: contentHash,
        url: item.url,
        lastValidated: null,
        validationResult: null
      };

      this._bindings.set(contentId, binding);
      this._save();
      return binding;
    }

    /**
     * Get a binding by content ID.
     * @param {string} contentId
     * @returns {Object|null}
     */
    get(contentId) {
      return this._bindings.get(contentId) || null;
    }

    /**
     * Update validation result on a binding.
     * @param {string} contentId
     * @param {string} result - ValidationResult value
     */
    updateValidation(contentId, result) {
      const binding = this._bindings.get(contentId);
      if (binding) {
        binding.lastValidated = Date.now();
        binding.validationResult = result;
        this._save();
      }
    }

    /**
     * Remove a binding.
     * @param {string} contentId
     */
    remove(contentId) {
      this._bindings.delete(contentId);
      this._save();
    }

    /**
     * Get all bindings.
     * @returns {Array<Object>}
     */
    getAll() {
      return Array.from(this._bindings.values());
    }

    /** @returns {number} */
    get size() {
      return this._bindings.size;
    }

    /** Clear all bindings. */
    clear() {
      this._bindings.clear();
      this._save();
    }
  }

  // ---------------------------------------------------------------------------
  // ValidationEngine — Claim 5: Validate cached content against current policy
  // ---------------------------------------------------------------------------

  /**
   * Validates each cached content binding against the current security policy.
   *
   * Per Claim 5: "validating cached executable content against the current
   * security policy using the policy delta and the temporal attributes."
   *
   * Validation checks:
   *   - Is the content type still allowed under the new policy?
   *   - Is the cache source still permitted?
   *   - Does the cache age exceed the new policy maximum?
   *   - Does the content need a re-integrity-check?
   *
   * @class
   */
  class ValidationEngine {

    /**
     * Validate a single binding record against a policy.
     *
     * @param {Object} binding - From TemporalSecurityLedger
     * @param {SecurityPolicy} policy - Current policy
     * @param {Object|null} delta - Policy delta (if transition occurred)
     * @returns {Object} { result: ValidationResult, details: string }
     */
    static validate(binding, policy, delta) {
      // Check 1: Content type allowed?
      if (!policy.allowedContentTypes.includes(binding.contentType)) {
        return {
          result: ValidationResult.INVALID_TYPE,
          details: `Content type "${binding.contentType}" not allowed under "${policy.level}" policy`
        };
      }

      // Check 2: Cache source allowed?
      if (!policy.allowedCacheSources.includes(binding.source)) {
        return {
          result: ValidationResult.INVALID_SOURCE,
          details: `Cache source "${binding.source}" not permitted under "${policy.level}" policy`
        };
      }

      // Check 3: Cache age within limits?
      const age = Date.now() - binding.cacheTimestamp;
      if (policy.maxCacheAgeMs > 0 && age > policy.maxCacheAgeMs) {
        return {
          result: ValidationResult.EXPIRED,
          details: `Cache age ${Math.round(age / 1000)}s exceeds maximum ${Math.round(policy.maxCacheAgeMs / 1000)}s`
        };
      }
      if (policy.maxCacheAgeMs === 0 && binding.source !== CacheSource.SESSION_STORAGE) {
        // Maximum policy: no cached content allowed at all
        return {
          result: ValidationResult.EXPIRED,
          details: 'No cached content allowed under maximum policy'
        };
      }

      // Check 4: Integrity check required but binding pre-dates requirement?
      if (policy.requiredIntegrityChecks && delta && delta.integrityCheckChanged) {
        // If the policy just started requiring integrity and the binding was
        // created under a policy that did not, it needs re-verification
        const cachedPolicySeverity = POLICY_SEVERITY[binding.policyLevelAtCache] || 0;
        if (cachedPolicySeverity < policy.severity && !binding.integrityTag) {
          return {
            result: ValidationResult.INTEGRITY_FAILED,
            details: 'Content cached under less restrictive policy lacks required integrity tag'
          };
        }
      }

      // Check 5: General policy violation — content cached under a less
      // restrictive policy when a tightening transition occurred
      if (delta && delta.direction === 'tightened') {
        const cachedSeverity = POLICY_SEVERITY[binding.policyLevelAtCache];
        if (cachedSeverity !== undefined && cachedSeverity < policy.severity) {
          // Content was cached under a weaker policy — flag if the delta
          // removed its content type or source
          if (delta.removedContentTypes.includes(binding.contentType)) {
            return {
              result: ValidationResult.POLICY_VIOLATION,
              details: `Content type "${binding.contentType}" was removed in policy transition from "${delta.oldLevel}" to "${delta.newLevel}"`
            };
          }
          if (delta.removedCacheSources.includes(binding.source)) {
            return {
              result: ValidationResult.POLICY_VIOLATION,
              details: `Cache source "${binding.source}" was removed in policy transition`
            };
          }
        }
      }

      return {
        result: ValidationResult.VALID,
        details: 'Content passes all validation checks'
      };
    }

    /**
     * Validate all bindings in the ledger.
     * @param {TemporalSecurityLedger} ledger
     * @param {SecurityPolicy} policy
     * @param {Object|null} delta
     * @returns {Array<Object>} Array of { binding, result, details }
     */
    static validateAll(ledger, policy, delta) {
      const results = [];
      for (const binding of ledger.getAll()) {
        const { result, details } = ValidationEngine.validate(binding, policy, delta);
        ledger.updateValidation(binding.contentId, result);
        results.push({ binding, result, details });
      }
      return results;
    }
  }

  // ---------------------------------------------------------------------------
  // MitigationController — Claim 6: Prevent execution of non-compliant content
  // ---------------------------------------------------------------------------

  /**
   * Executes mitigation strategies for non-compliant cached content.
   *
   * Per Claim 6: "preventing execution of cached executable content
   * that does not comply with the current security policy."
   *
   * Strategies:
   *   - quarantine: Move to an isolated quarantine cache namespace
   *   - invalidate: Remove from cache entirely
   *   - regenerate: Re-fetch from origin under new policy
   *   - block: Mark for execution blocking
   *
   * @class
   */
  class MitigationController {

    /**
     * Default mitigation strategy mapping.
     * Maps ValidationResult -> MitigationAction by content type.
     */
    static DEFAULT_STRATEGIES = {
      [ValidationResult.INVALID_TYPE]: {
        default: MitigationAction.INVALIDATE,
        [ContentType.JAVASCRIPT]: MitigationAction.BLOCK,
        [ContentType.WEBASSEMBLY]: MitigationAction.BLOCK,
        [ContentType.SERVICE_WORKER]: MitigationAction.INVALIDATE
      },
      [ValidationResult.INVALID_SOURCE]: {
        default: MitigationAction.QUARANTINE,
        [ContentType.JAVASCRIPT]: MitigationAction.BLOCK,
        [ContentType.WEBASSEMBLY]: MitigationAction.BLOCK
      },
      [ValidationResult.EXPIRED]: {
        default: MitigationAction.REGENERATE,
        [ContentType.SERVICE_WORKER]: MitigationAction.INVALIDATE
      },
      [ValidationResult.INTEGRITY_FAILED]: {
        default: MitigationAction.BLOCK,
        [ContentType.JSON_DATA]: MitigationAction.REGENERATE
      },
      [ValidationResult.POLICY_VIOLATION]: {
        default: MitigationAction.BLOCK,
        [ContentType.JSON_DATA]: MitigationAction.QUARANTINE
      }
    };

    /**
     * Determine the mitigation action for a validation failure.
     * @param {string} validationResult
     * @param {string} contentType
     * @param {Object} [customStrategies]
     * @returns {string} MitigationAction
     */
    static determineAction(validationResult, contentType, customStrategies) {
      if (validationResult === ValidationResult.VALID) return MitigationAction.NONE;

      const strategies = customStrategies || MitigationController.DEFAULT_STRATEGIES;
      const mapping = strategies[validationResult];
      if (!mapping) return MitigationAction.BLOCK;

      return mapping[contentType] || mapping.default || MitigationAction.BLOCK;
    }

    /**
     * Execute a mitigation action on a cached item.
     *
     * @param {Object} binding - Ledger binding record
     * @param {string} action - MitigationAction
     * @param {TemporalSecurityLedger} ledger
     * @returns {Promise<Object>} { success: boolean, action, details }
     */
    static async execute(binding, action, ledger) {
      switch (action) {
        case MitigationAction.QUARANTINE:
          return MitigationController._quarantine(binding, ledger);
        case MitigationAction.INVALIDATE:
          return MitigationController._invalidate(binding, ledger);
        case MitigationAction.REGENERATE:
          return MitigationController._regenerate(binding, ledger);
        case MitigationAction.BLOCK:
          return MitigationController._block(binding, ledger);
        case MitigationAction.NONE:
          return { success: true, action, details: 'No action required' };
        default:
          return { success: false, action, details: 'Unknown mitigation action' };
      }
    }

    /**
     * Quarantine: move content to an isolated cache namespace.
     */
    static async _quarantine(binding, ledger) {
      try {
        if (binding.source === CacheSource.CACHE_API && typeof caches !== 'undefined') {
          const srcCache = await caches.open(binding.cacheName || 'default');
          const quarantineCache = await caches.open(QUARANTINE_CACHE_PREFIX + Date.now());
          const response = await srcCache.match(binding.url);
          if (response) {
            await quarantineCache.put(binding.url, response.clone());
            await srcCache.delete(binding.url);
          }
        } else if (binding.source === CacheSource.LOCAL_STORAGE && binding.storageKey) {
          const value = localStorage.getItem(binding.storageKey);
          if (value !== null) {
            localStorage.setItem(QUARANTINE_CACHE_PREFIX + binding.storageKey, value);
            localStorage.removeItem(binding.storageKey);
          }
        } else if (binding.source === CacheSource.SESSION_STORAGE && binding.storageKey) {
          const value = sessionStorage.getItem(binding.storageKey);
          if (value !== null) {
            sessionStorage.setItem(QUARANTINE_CACHE_PREFIX + binding.storageKey, value);
            sessionStorage.removeItem(binding.storageKey);
          }
        }

        ledger.remove(binding.contentId);
        return { success: true, action: MitigationAction.QUARANTINE, details: 'Content quarantined' };
      } catch (err) {
        return { success: false, action: MitigationAction.QUARANTINE, details: err.message };
      }
    }

    /**
     * Invalidate: remove content from its cache entirely.
     */
    static async _invalidate(binding, ledger) {
      try {
        if (binding.source === CacheSource.CACHE_API && typeof caches !== 'undefined') {
          const cache = await caches.open(binding.cacheName || 'default');
          await cache.delete(binding.url);
        } else if (binding.source === CacheSource.LOCAL_STORAGE && binding.storageKey) {
          localStorage.removeItem(binding.storageKey);
        } else if (binding.source === CacheSource.SESSION_STORAGE && binding.storageKey) {
          sessionStorage.removeItem(binding.storageKey);
        }

        ledger.remove(binding.contentId);
        return { success: true, action: MitigationAction.INVALIDATE, details: 'Content invalidated' };
      } catch (err) {
        return { success: false, action: MitigationAction.INVALIDATE, details: err.message };
      }
    }

    /**
     * Regenerate: re-fetch content from origin under the new policy.
     * Only applicable to Cache API entries with a fetchable URL.
     */
    static async _regenerate(binding, ledger) {
      try {
        if (binding.source === CacheSource.CACHE_API && typeof caches !== 'undefined') {
          const url = binding.url;
          // Validate it is a fetchable URL
          if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return { success: false, action: MitigationAction.REGENERATE, details: 'Non-fetchable URL' };
          }

          const cache = await caches.open(binding.cacheName || 'default');
          await cache.delete(url);
          const response = await fetch(url, { cache: 'reload', credentials: 'same-origin' });
          if (response.ok) {
            await cache.put(url, response.clone());
          }
          ledger.remove(binding.contentId);
          return { success: true, action: MitigationAction.REGENERATE, details: 'Content re-fetched from origin' };
        }

        // For non-Cache-API sources, fall back to invalidation
        return MitigationController._invalidate(binding, ledger);
      } catch (err) {
        return { success: false, action: MitigationAction.REGENERATE, details: err.message };
      }
    }

    /**
     * Block: mark the content as blocked to prevent execution.
     * The binding remains in the ledger with a BLOCKED flag so the
     * execution interceptor can check it.
     */
    static async _block(binding, ledger) {
      try {
        const record = ledger.get(binding.contentId);
        if (record) {
          record.blocked = true;
          record.blockedAt = Date.now();
          ledger._save();
        }
        return { success: true, action: MitigationAction.BLOCK, details: 'Content marked as blocked' };
      } catch (err) {
        return { success: false, action: MitigationAction.BLOCK, details: err.message };
      }
    }
  }

  // ---------------------------------------------------------------------------
  // AuditSubsystem — Claim 7: Tamper-evident audit trails
  // ---------------------------------------------------------------------------

  /**
   * Generates and maintains a tamper-evident audit trail of all TSB
   * operations, policy transitions, and mitigation actions.
   *
   * Per Claim 7: "generating a tamper-evident audit trail that records
   * the security policy transition, the validation results, and the
   * mitigation actions."
   *
   * Each entry is chained to the previous via SHA-256 hash, forming
   * a hash chain (blockchain-like) for tamper evidence.
   *
   * @class
   */
  class AuditSubsystem {
    constructor() {
      /** @type {Array<Object>} */
      this._entries = [];
      /** @type {string} Previous entry hash for chaining */
      this._previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
      this._maxEntries = MAX_AUDIT_ENTRIES;
      this._load();
    }

    /**
     * Load audit log from localStorage.
     */
    _load() {
      try {
        const raw = localStorage.getItem(AUDIT_STORAGE_KEY);
        if (raw) {
          const data = JSON.parse(raw);
          this._entries = data.entries || [];
          this._previousHash = data.lastHash || this._previousHash;
        }
      } catch (err) {
        console.warn('[TSB] Audit log load error:', err);
      }
    }

    /**
     * Persist audit log to localStorage.
     */
    _save() {
      try {
        // Rotate if over limit
        if (this._entries.length > this._maxEntries) {
          this._entries = this._entries.slice(-this._maxEntries);
        }
        localStorage.setItem(AUDIT_STORAGE_KEY, JSON.stringify({
          entries: this._entries,
          lastHash: this._previousHash,
          savedAt: Date.now()
        }));
      } catch (err) {
        console.warn('[TSB] Audit log save error:', err);
      }
    }

    /**
     * Append a tamper-evident audit entry.
     *
     * @param {Object} params
     * @param {string} params.action - What happened (e.g., 'policy_transition', 'validation', 'mitigation')
     * @param {string} [params.contentId] - Related content ID
     * @param {string} [params.previousPolicy] - Previous policy level
     * @param {string} [params.newPolicy] - New policy level
     * @param {string} [params.validationResult] - ValidationResult value
     * @param {string} [params.mitigationAction] - MitigationAction value
     * @param {string} [params.contentHash] - Content hash
     * @param {string} [params.details] - Human-readable details
     * @returns {Promise<Object>} The created entry
     */
    async append(params) {
      const entry = {
        entryId: this._generateEntryId(),
        timestamp: Date.now(),
        action: params.action,
        contentId: params.contentId || null,
        previousPolicy: params.previousPolicy || null,
        newPolicy: params.newPolicy || null,
        validationResult: params.validationResult || null,
        mitigationAction: params.mitigationAction || null,
        contentHash: params.contentHash || null,
        details: params.details || null,
        previousEntryHash: this._previousHash
      };

      // Compute this entry's hash (chained to previous)
      const entryData = JSON.stringify(entry);
      entry.entryHash = await sha256(entryData);
      this._previousHash = entry.entryHash;

      this._entries.push(entry);
      this._save();
      return entry;
    }

    /**
     * Generate a unique entry ID.
     * @returns {string}
     */
    _generateEntryId() {
      const timestamp = Date.now().toString(36);
      const random = Math.random().toString(36).substring(2, 10);
      return `tsb-${timestamp}-${random}`;
    }

    /**
     * Get the full audit log.
     * @returns {Array<Object>}
     */
    getAll() {
      return [...this._entries];
    }

    /**
     * Get entries filtered by action type.
     * @param {string} action
     * @returns {Array<Object>}
     */
    getByAction(action) {
      return this._entries.filter(e => e.action === action);
    }

    /**
     * Verify the integrity of the audit chain.
     * Checks that each entry's previousEntryHash matches the prior entry's hash.
     * @returns {Promise<Object>} { valid: boolean, brokenAt: number|null }
     */
    async verifyChain() {
      if (this._entries.length === 0) return { valid: true, brokenAt: null };

      for (let i = 1; i < this._entries.length; i++) {
        const prev = this._entries[i - 1];
        const curr = this._entries[i];
        if (curr.previousEntryHash !== prev.entryHash) {
          return { valid: false, brokenAt: i };
        }
      }
      return { valid: true, brokenAt: null };
    }

    /**
     * Export the audit log as a JSON string for compliance reporting.
     * @returns {string}
     */
    exportJSON() {
      return JSON.stringify({
        version: TSB_VERSION,
        exportedAt: new Date().toISOString(),
        origin: location.origin,
        entryCount: this._entries.length,
        entries: this._entries
      }, null, 2);
    }

    /**
     * Set maximum number of entries before rotation.
     * @param {number} max
     */
    setMaxEntries(max) {
      this._maxEntries = Math.max(100, Math.floor(max));
    }

    /** Clear all entries. */
    clear() {
      this._entries = [];
      this._previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
      this._save();
    }

    /** @returns {number} */
    get size() {
      return this._entries.length;
    }
  }

  // ---------------------------------------------------------------------------
  // TSBEngine — Main orchestrator
  // ---------------------------------------------------------------------------

  /**
   * The core Temporal Security Binding engine. Orchestrates all subsystems
   * and exposes the public API.
   *
   * @class
   */
  class TSBEngine {
    constructor() {
      /** @type {SecurityPolicy|null} */
      this._currentPolicy = null;
      /** @type {SecurityPolicy|null} */
      this._previousPolicy = null;
      /** @type {Object|null} */
      this._lastDelta = null;
      /** @type {TemporalSecurityLedger} */
      this._ledger = null;
      /** @type {AuditSubsystem} */
      this._audit = null;
      /** @type {SecurityPolicyMonitor} */
      this._monitor = null;
      /** @type {boolean} */
      this._initialized = false;
      /** @type {boolean} */
      this._running = false;
      /** @type {Array<Function>} */
      this._violationCallbacks = [];
      /** @type {Array<Function>} */
      this._transitionCallbacks = [];
      /** @type {Object} */
      this._config = {};
      /** @type {number} */
      this._violationCount = 0;
      /** @type {Object|null} */
      this._mitigationStrategies = null;
    }

    /**
     * Initialize the TSB engine.
     *
     * @param {Object} [config]
     * @param {string} [config.defaultPolicy='standard'] - Initial policy level
     * @param {boolean} [config.autoScan=true] - Auto-scan caches on init
     * @param {boolean} [config.autoMonitor=true] - Auto-start policy monitoring
     * @param {number} [config.maxAuditEntries=10000] - Max audit log entries
     * @param {Object} [config.mitigationStrategies] - Custom mitigation strategies
     * @returns {Promise<Object>} Initialization status
     */
    async init(config = {}) {
      if (this._initialized) {
        console.warn('[TSB] Engine already initialized');
        return this.getStatus();
      }

      this._config = {
        defaultPolicy: config.defaultPolicy || PolicyLevel.STANDARD,
        autoScan: config.autoScan !== false,
        autoMonitor: config.autoMonitor !== false,
        maxAuditEntries: config.maxAuditEntries || MAX_AUDIT_ENTRIES,
        mitigationStrategies: config.mitigationStrategies || null
      };

      this._mitigationStrategies = this._config.mitigationStrategies;

      // Initialize subsystems
      this._ledger = new TemporalSecurityLedger();
      this._audit = new AuditSubsystem();
      this._audit.setMaxEntries(this._config.maxAuditEntries);
      this._monitor = new SecurityPolicyMonitor();

      // Restore or set initial policy
      const savedPolicy = this._loadSavedPolicy();
      this._currentPolicy = new SecurityPolicy(savedPolicy || this._config.defaultPolicy);
      this._savePolicy();

      // Log initialization
      await this._audit.append({
        action: 'engine_init',
        newPolicy: this._currentPolicy.level,
        details: `TSB engine v${TSB_VERSION} initialized with policy "${this._currentPolicy.level}"`
      });

      this._initialized = true;
      this._running = true;

      // Start monitoring (Claim 1)
      if (this._config.autoMonitor) {
        this._monitor.start((oldPolicy, newPolicy, delta) => {
          this._onPolicyTransition(oldPolicy, newPolicy, delta);
        });
      }

      // Initial cache scan (Claim 3)
      if (this._config.autoScan) {
        // Defer to avoid blocking page load
        setTimeout(() => this.scanCaches(), 100);
      }

      console.log(`[TSB] Temporal Security Binding engine v${TSB_VERSION} initialized — policy: ${this._currentPolicy.level}`);
      return this.getStatus();
    }

    /**
     * Handle an external policy signal (from CSP meta tag change).
     * @param {string} level
     */
    async _handleExternalPolicySignal(level) {
      if (!this._initialized) return;
      if (this._currentPolicy && this._currentPolicy.level === level) return;
      await this.setPolicy(level);
    }

    /**
     * Get the current security policy.
     * @returns {Object|null} Serialized policy
     */
    getCurrentPolicy() {
      return this._currentPolicy ? this._currentPolicy.toJSON() : null;
    }

    /**
     * Manually transition to a new security policy level.
     * Implements Claims 1, 2, 5, 6, and 7 in sequence.
     *
     * @param {string} level - PolicyLevel value
     * @returns {Promise<Object>} Transition result with validation summary
     */
    async setPolicy(level) {
      if (!this._initialized) {
        throw new Error('[TSB] Engine not initialized. Call StaamlTSB.init() first.');
      }

      if (!POLICY_SEVERITY.hasOwnProperty(level)) {
        throw new Error(`[TSB] Invalid policy level: ${level}`);
      }

      if (this._currentPolicy && this._currentPolicy.level === level) {
        return { transitioned: false, reason: 'Already at requested policy level' };
      }

      // Claim 1: Detect transition
      this._previousPolicy = this._currentPolicy;
      const newPolicy = new SecurityPolicy(level);

      // Claim 2: Compute delta
      const delta = computePolicyDelta(this._previousPolicy, newPolicy);
      this._lastDelta = delta;

      // Claim 7: Audit the transition
      await this._audit.append({
        action: 'policy_transition',
        previousPolicy: this._previousPolicy.level,
        newPolicy: newPolicy.level,
        details: `Policy transitioned from "${this._previousPolicy.level}" to "${newPolicy.level}" (${delta.direction})`
      });

      // Apply new policy
      this._currentPolicy = newPolicy;
      this._savePolicy();

      // Notify transition callbacks
      for (const cb of this._transitionCallbacks) {
        try {
          cb(this._previousPolicy.toJSON(), newPolicy.toJSON(), delta);
        } catch (err) {
          console.error('[TSB] Transition callback error:', err);
        }
      }

      // Claim 5 & 6: Validate and mitigate
      const validationResults = await this._validateAndMitigate(delta);

      return {
        transitioned: true,
        previousLevel: this._previousPolicy.level,
        newLevel: newPolicy.level,
        delta,
        validationSummary: {
          total: validationResults.length,
          valid: validationResults.filter(r => r.result === ValidationResult.VALID).length,
          violations: validationResults.filter(r => r.result !== ValidationResult.VALID).length
        }
      };
    }

    /**
     * Scan all caches, identify content, extract temporal attributes,
     * and create bindings in the ledger.
     * Implements Claims 3 and 4.
     *
     * @returns {Promise<Object>} Scan results
     */
    async scanCaches() {
      if (!this._initialized) {
        throw new Error('[TSB] Engine not initialized.');
      }

      const items = await CacheIdentifier.scanAll();
      let bound = 0;
      let errors = 0;

      for (const item of items) {
        try {
          // Generate content ID
          item._contentId = await generateContentId(item.url, item.source);

          // Compute content hash (Claim 4: temporal attribute extraction)
          let contentHash;
          if (item.source === CacheSource.CACHE_API && typeof caches !== 'undefined') {
            try {
              const cache = await caches.open(item.cacheName || 'default');
              const response = await cache.match(item.url);
              if (response) {
                const blob = await response.clone().blob();
                contentHash = await sha256(blob);
              }
            } catch (e) {
              contentHash = await sha256(item.url + '|' + item.size);
            }
          } else if (item.storageKey) {
            const storage = item.source === CacheSource.LOCAL_STORAGE ? localStorage : sessionStorage;
            const value = storage.getItem(item.storageKey);
            contentHash = value ? await sha256(value) : await sha256(item.url);
          } else {
            contentHash = await sha256(item.url + '|' + item.source);
          }

          // Claim 4: Bind to temporal security context
          this._ledger.bind(item, this._currentPolicy.level, contentHash);
          bound++;
        } catch (err) {
          errors++;
          console.warn('[TSB] Binding error for', item.url, err);
        }
      }

      await this._audit.append({
        action: 'cache_scan',
        newPolicy: this._currentPolicy.level,
        details: `Scanned ${items.length} cached items, bound ${bound}, errors ${errors}`
      });

      return {
        scanned: items.length,
        bound,
        errors,
        sources: {
          cacheAPI: items.filter(i => i.source === CacheSource.CACHE_API).length,
          localStorage: items.filter(i => i.source === CacheSource.LOCAL_STORAGE).length,
          sessionStorage: items.filter(i => i.source === CacheSource.SESSION_STORAGE).length,
          indexedDB: items.filter(i => i.source === CacheSource.INDEXED_DB).length
        }
      };
    }

    /**
     * Validate all cached content against the current policy.
     * Implements Claim 5.
     *
     * @returns {Promise<Object>} Validation summary and details
     */
    async validateAll() {
      if (!this._initialized) {
        throw new Error('[TSB] Engine not initialized.');
      }

      const results = ValidationEngine.validateAll(
        this._ledger,
        this._currentPolicy,
        this._lastDelta
      );

      // Audit each violation
      for (const { binding, result, details } of results) {
        if (result !== ValidationResult.VALID) {
          await this._audit.append({
            action: 'validation_failure',
            contentId: binding.contentId,
            newPolicy: this._currentPolicy.level,
            validationResult: result,
            contentHash: binding.contentHash,
            details
          });
        }
      }

      const valid = results.filter(r => r.result === ValidationResult.VALID);
      const violations = results.filter(r => r.result !== ValidationResult.VALID);

      return {
        total: results.length,
        valid: valid.length,
        violations: violations.length,
        results: results.map(r => ({
          contentId: r.binding.contentId,
          url: r.binding.url,
          contentType: r.binding.contentType,
          source: r.binding.source,
          result: r.result,
          details: r.details
        }))
      };
    }

    /**
     * Internal: validate all bindings and execute mitigations.
     * Implements Claims 5, 6, and 7 together.
     *
     * @param {Object} delta
     * @returns {Promise<Array>}
     */
    async _validateAndMitigate(delta) {
      const results = ValidationEngine.validateAll(
        this._ledger,
        this._currentPolicy,
        delta
      );

      for (const { binding, result, details } of results) {
        if (result === ValidationResult.VALID) continue;

        this._violationCount++;

        // Claim 6: Determine and execute mitigation
        const action = MitigationController.determineAction(
          result,
          binding.contentType,
          this._mitigationStrategies
        );

        const mitigationResult = await MitigationController.execute(
          binding, action, this._ledger
        );

        // Claim 7: Audit the violation and mitigation
        await this._audit.append({
          action: 'mitigation',
          contentId: binding.contentId,
          previousPolicy: this._previousPolicy ? this._previousPolicy.level : null,
          newPolicy: this._currentPolicy.level,
          validationResult: result,
          mitigationAction: action,
          contentHash: binding.contentHash,
          details: `${details} | Mitigation: ${action} (${mitigationResult.success ? 'success' : 'failed: ' + mitigationResult.details})`
        });

        // Notify violation callbacks
        for (const cb of this._violationCallbacks) {
          try {
            cb({
              binding,
              validationResult: result,
              mitigationAction: action,
              mitigationSuccess: mitigationResult.success,
              details,
              policy: this._currentPolicy.level
            });
          } catch (err) {
            console.error('[TSB] Violation callback error:', err);
          }
        }
      }

      return results;
    }

    /**
     * Handle an internally-triggered policy transition (from the monitor).
     * @param {SecurityPolicy} oldPolicy
     * @param {SecurityPolicy} newPolicy
     * @param {Object} delta
     */
    async _onPolicyTransition(oldPolicy, newPolicy, delta) {
      // The monitor detected a transition — delegate to setPolicy
      if (newPolicy && newPolicy.level !== this._currentPolicy.level) {
        await this.setPolicy(newPolicy.level);
      }
    }

    /**
     * Get the tamper-evident audit trail.
     * @returns {Array<Object>}
     */
    getAuditLog() {
      return this._audit ? this._audit.getAll() : [];
    }

    /**
     * Export audit log as JSON for compliance reporting.
     * @returns {string}
     */
    exportAuditLog() {
      return this._audit ? this._audit.exportJSON() : '{}';
    }

    /**
     * Verify audit chain integrity.
     * @returns {Promise<Object>}
     */
    async verifyAuditChain() {
      return this._audit ? this._audit.verifyChain() : { valid: false, brokenAt: null };
    }

    /**
     * Get the temporal security ledger.
     * @returns {Array<Object>}
     */
    getLedger() {
      return this._ledger ? this._ledger.getAll() : [];
    }

    /**
     * Get engine status.
     * @returns {Object}
     */
    getStatus() {
      return {
        version: TSB_VERSION,
        initialized: this._initialized,
        running: this._running,
        policyLevel: this._currentPolicy ? this._currentPolicy.level : null,
        cacheBindings: this._ledger ? this._ledger.size : 0,
        auditEntries: this._audit ? this._audit.size : 0,
        violations: this._violationCount,
        lastDelta: this._lastDelta,
        config: this._config
      };
    }

    /**
     * Register a callback for policy transitions.
     * @param {Function} cb - callback(oldPolicy, newPolicy, delta)
     */
    onPolicyTransition(cb) {
      if (typeof cb === 'function') {
        this._transitionCallbacks.push(cb);
      }
      if (this._monitor) {
        this._monitor.onTransition(cb);
      }
    }

    /**
     * Register a callback for violations.
     * @param {Function} cb - callback({ binding, validationResult, mitigationAction, ... })
     */
    onViolation(cb) {
      if (typeof cb === 'function') {
        this._violationCallbacks.push(cb);
      }
    }

    /**
     * Save current policy level to localStorage.
     */
    _savePolicy() {
      try {
        localStorage.setItem(POLICY_STORAGE_KEY, this._currentPolicy.level);
      } catch (err) {
        // Non-fatal
      }
    }

    /**
     * Load saved policy level from localStorage.
     * @returns {string|null}
     */
    _loadSavedPolicy() {
      try {
        const level = localStorage.getItem(POLICY_STORAGE_KEY);
        if (level && POLICY_SEVERITY.hasOwnProperty(level)) {
          return level;
        }
      } catch (err) {
        // Non-fatal
      }
      return null;
    }

    /**
     * Shut down the engine.
     */
    shutdown() {
      if (this._monitor) {
        this._monitor.stop();
      }
      this._running = false;
      console.log('[TSB] Engine shut down');
    }
  }

  // ---------------------------------------------------------------------------
  // Singleton instance & public API
  // ---------------------------------------------------------------------------

  /** @type {TSBEngine} */
  let engine = new TSBEngine();

  /**
   * Public API surface exposed as window.StaamlTSB.
   *
   * @namespace StaamlTSB
   */
  const StaamlTSB = Object.freeze({
    /** Engine version */
    VERSION: TSB_VERSION,

    /** Enum constants for external use */
    PolicyLevel,
    ContentType,
    CacheSource,
    ValidationResult,
    MitigationAction,

    /**
     * Initialize the TSB engine.
     * @param {Object} [config] - See TSBEngine.init()
     * @returns {Promise<Object>}
     */
    init: (config) => engine.init(config),

    /**
     * Get the current security policy.
     * @returns {Object|null}
     */
    getCurrentPolicy: () => engine.getCurrentPolicy(),

    /**
     * Manually transition to a new policy level.
     * @param {string} level - PolicyLevel value
     * @returns {Promise<Object>}
     */
    setPolicy: (level) => engine.setPolicy(level),

    /**
     * Scan all caches and bind content to temporal security context.
     * @returns {Promise<Object>}
     */
    scanCaches: () => engine.scanCaches(),

    /**
     * Validate all cached content against the current policy.
     * @returns {Promise<Object>}
     */
    validateAll: () => engine.validateAll(),

    /**
     * Get the tamper-evident audit trail.
     * @returns {Array<Object>}
     */
    getAuditLog: () => engine.getAuditLog(),

    /**
     * Export audit log as JSON for compliance reporting.
     * @returns {string}
     */
    exportAuditLog: () => engine.exportAuditLog(),

    /**
     * Verify integrity of the audit chain.
     * @returns {Promise<Object>}
     */
    verifyAuditChain: () => engine.verifyAuditChain(),

    /**
     * Get the temporal security ledger (all bindings).
     * @returns {Array<Object>}
     */
    getLedger: () => engine.getLedger(),

    /**
     * Get engine status.
     * @returns {Object}
     */
    getStatus: () => engine.getStatus(),

    /**
     * Register a callback for policy transitions.
     * @param {Function} cb
     */
    onPolicyTransition: (cb) => engine.onPolicyTransition(cb),

    /**
     * Register a callback for violations.
     * @param {Function} cb
     */
    onViolation: (cb) => engine.onViolation(cb),

    /**
     * Shut down the engine.
     */
    shutdown: () => engine.shutdown()
  });

  // Expose on global
  global.StaamlTSB = StaamlTSB;

  // ---------------------------------------------------------------------------
  // Auto-initialize on load
  // ---------------------------------------------------------------------------

  /**
   * Auto-initialize with default configuration when the script loads.
   * Deferred to avoid blocking the critical rendering path.
   */
  if (typeof document !== 'undefined') {
    const autoInit = () => {
      engine.init().catch(err => {
        console.error('[TSB] Auto-initialization failed:', err);
      });
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', autoInit, { once: true });
    } else {
      // DOM already ready — defer slightly
      setTimeout(autoInit, 0);
    }
  }

})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
