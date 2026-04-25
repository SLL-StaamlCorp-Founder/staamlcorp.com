/**
 * StaamlCorp Temporal Security Binding -- Service Worker Derivative
 * U.S. Patent Application No. 19/640,793
 *
 * Implements cache interception and policy-aware validation at the network
 * layer via Service Worker, as described in Patent Claims 1-21.
 *
 * Cache namespaces:
 *   tsb-static-v1      -- pre-cached site assets (HTML, CSS, JS)
 *   tsb-dynamic-v1     -- runtime-fetched resources
 *   tsb-quarantine-v1  -- non-compliant items pending review
 *   tsb-metadata        -- companion metadata for every cached item
 *
 * @file staaml-sw.js
 * @version 1.0.0
 * @license Proprietary -- StaamlCorp
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const CACHE_STATIC = 'tsb-static-v1';
const CACHE_DYNAMIC = 'tsb-dynamic-v1';
const CACHE_QUARANTINE = 'tsb-quarantine-v1';
const CACHE_METADATA = 'tsb-metadata';

const ALL_CACHES = [CACHE_STATIC, CACHE_DYNAMIC, CACHE_QUARANTINE, CACHE_METADATA];

/** Site assets to pre-cache during install. */
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/about.html',
  '/services.html',
  '/team.html',
  '/blog.html',
  '/blog-ai-governance.html',
  '/blog-ldb01-three-years.html',
  '/blog-temporal-discontinuity.html',
  '/contact.html',
  '/assessment.html',
  '/styles.css',
];

const AUDIT_DB_NAME = 'tsb-audit';
const AUDIT_DB_VERSION = 1;
const AUDIT_STORE = 'entries';

/* ------------------------------------------------------------------ */
/*  Policy state (Patent Claims 1-2, 12)                               */
/* ------------------------------------------------------------------ */

/**
 * Default policy. The main thread can upgrade this via POLICY_UPDATE.
 *
 * policyLevel: numeric severity (higher = more restrictive).
 * maxCacheAge: maximum cache age in milliseconds.
 * allowedContentTypes: MIME prefixes that are permitted.
 * allowedOrigins: origin strings that are permitted (empty = allow all).
 *
 * @type {Object}
 */
let currentPolicy = {
  policyLevel: 1,
  maxCacheAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  allowedContentTypes: [
    'text/html',
    'text/css',
    'application/javascript',
    'application/json',
    'image/',
    'font/',
  ],
  allowedOrigins: [], // empty = no origin restriction
  timestamp: Date.now(),
};

/* ------------------------------------------------------------------ */
/*  Utility: SHA-256 content hash                                      */
/* ------------------------------------------------------------------ */

/**
 * Compute a hex-encoded SHA-256 hash of an ArrayBuffer.
 * @param {ArrayBuffer} buffer
 * @returns {Promise<string>}
 */
async function sha256(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/* ------------------------------------------------------------------ */
/*  IndexedDB audit trail (Patent Claims 9-11, 19-21)                  */
/* ------------------------------------------------------------------ */

/**
 * Open (or create) the audit IndexedDB.
 * @returns {Promise<IDBDatabase>}
 */
function openAuditDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(AUDIT_DB_NAME, AUDIT_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(AUDIT_STORE)) {
        const store = db.createObjectStore(AUDIT_STORE, {
          keyPath: 'id',
          autoIncrement: true,
        });
        store.createIndex('timestamp', 'timestamp', { unique: false });
        store.createIndex('action', 'action', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Hash of the most recent audit entry, used for chaining. */
let lastAuditHash = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Append a tamper-evident audit entry.
 *
 * Each entry includes the hash of the previous entry so that the
 * sequence cannot be reordered or truncated without detection.
 * (Patent Claims 9-11, 19-21)
 *
 * @param {string} action  - e.g. 'INTERCEPT', 'VALIDATE', 'QUARANTINE'
 * @param {Object} detail  - arbitrary detail payload
 * @returns {Promise<void>}
 */
async function audit(action, detail) {
  try {
    const entry = {
      timestamp: Date.now(),
      action,
      detail,
      previousHash: lastAuditHash,
    };

    // Compute chain hash
    const raw = JSON.stringify(entry);
    const buf = new TextEncoder().encode(raw);
    entry.hash = await sha256(buf);
    lastAuditHash = entry.hash;

    const db = await openAuditDb();
    const tx = db.transaction(AUDIT_STORE, 'readwrite');
    tx.objectStore(AUDIT_STORE).add(entry);
    await new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch (_) {
    // Audit failures must never break the site.
  }
}

/**
 * Retrieve the full audit log.
 * @returns {Promise<Array>}
 */
async function getAuditLog() {
  try {
    const db = await openAuditDb();
    const tx = db.transaction(AUDIT_STORE, 'readonly');
    const store = tx.objectStore(AUDIT_STORE);
    return await new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => { db.close(); resolve(req.result); };
      req.onerror = () => { db.close(); reject(req.error); };
    });
  } catch (_) {
    return [];
  }
}

/* ------------------------------------------------------------------ */
/*  Metadata helpers                                                   */
/* ------------------------------------------------------------------ */

/**
 * Build a metadata key for a given request URL.
 * We store metadata as a Response in the tsb-metadata cache keyed by
 * a synthetic URL to avoid collisions.
 *
 * @param {string} url
 * @returns {string}
 */
function metaKey(url) {
  return `https://tsb-meta.staamlcorp.internal/${encodeURIComponent(url)}`;
}

/**
 * Store temporal metadata for a cached response.
 * (Patent Claims 3-5, 13-15)
 *
 * @param {string} url
 * @param {Object} meta - { cacheTime, policyLevel, contentHash, contentType, origin }
 * @returns {Promise<void>}
 */
async function storeMetadata(url, meta) {
  try {
    const cache = await caches.open(CACHE_METADATA);
    const body = JSON.stringify(meta);
    const res = new Response(body, {
      headers: { 'Content-Type': 'application/json' },
    });
    await cache.put(new Request(metaKey(url)), res);
  } catch (_) {
    // Non-fatal.
  }
}

/**
 * Retrieve temporal metadata for a cached URL.
 * @param {string} url
 * @returns {Promise<Object|null>}
 */
async function getMetadata(url) {
  try {
    const cache = await caches.open(CACHE_METADATA);
    const res = await cache.match(new Request(metaKey(url)));
    if (!res) return null;
    return await res.json();
  } catch (_) {
    return null;
  }
}

/**
 * Delete metadata for a cached URL.
 * @param {string} url
 * @returns {Promise<void>}
 */
async function deleteMetadata(url) {
  try {
    const cache = await caches.open(CACHE_METADATA);
    await cache.delete(new Request(metaKey(url)));
  } catch (_) {
    // Non-fatal.
  }
}

/* ------------------------------------------------------------------ */
/*  Content validation (Patent Claims 6-8, 16-18)                      */
/* ------------------------------------------------------------------ */

/**
 * Validate a cached item against the current policy.
 *
 * Returns an object with `valid: boolean` and `reasons: string[]`.
 *
 * Checks performed:
 *   1. Content type against policy allowlist (Claims 6, 16)
 *   2. Cache age against policy maximum (Claims 7, 17)
 *   3. Content integrity -- stored hash vs recomputed hash (Claims 8, 18)
 *   4. Origin against policy origin allowlist (Claims 6, 16)
 *
 * @param {string} url
 * @param {Response} response   - the cached Response
 * @param {Object}  meta        - temporal metadata
 * @returns {Promise<{valid: boolean, reasons: string[]}>}
 */
async function validateContent(url, response, meta) {
  const reasons = [];

  if (!meta) {
    reasons.push('missing_metadata');
    return { valid: false, reasons };
  }

  // 1. Content type allowlist
  const ct = meta.contentType || '';
  const typeAllowed = currentPolicy.allowedContentTypes.some(prefix =>
    ct.startsWith(prefix)
  );
  if (!typeAllowed) {
    reasons.push(`content_type_blocked: ${ct}`);
  }

  // 2. Cache age
  const age = Date.now() - (meta.cacheTime || 0);
  if (age > currentPolicy.maxCacheAge) {
    reasons.push(`cache_expired: age=${Math.round(age / 1000)}s`);
  }

  // 3. Content integrity
  try {
    const clone = response.clone();
    const buf = await clone.arrayBuffer();
    const currentHash = await sha256(buf);
    if (meta.contentHash && currentHash !== meta.contentHash) {
      reasons.push('integrity_mismatch');
    }
  } catch (_) {
    reasons.push('integrity_check_failed');
  }

  // 4. Origin allowlist
  if (
    currentPolicy.allowedOrigins.length > 0 &&
    meta.origin &&
    !currentPolicy.allowedOrigins.includes(meta.origin)
  ) {
    reasons.push(`origin_blocked: ${meta.origin}`);
  }

  // 5. Policy level regression (Claims 3-5, 13-15)
  //    If the item was cached under a less restrictive policy and the
  //    current policy is more restrictive, the cached version is stale.
  if (
    typeof meta.policyLevel === 'number' &&
    meta.policyLevel < currentPolicy.policyLevel
  ) {
    reasons.push(
      `policy_regression: cached@level${meta.policyLevel} < current@level${currentPolicy.policyLevel}`
    );
  }

  return { valid: reasons.length === 0, reasons };
}

/* ------------------------------------------------------------------ */
/*  Quarantine (Patent Claims 3-5, 13-15)                              */
/* ------------------------------------------------------------------ */

/**
 * Move a cached response into the quarantine cache.
 *
 * @param {string}   cacheName - source cache name
 * @param {string}   url
 * @param {Response} response
 * @param {string[]} reasons
 * @returns {Promise<void>}
 */
async function quarantineItem(cacheName, url, response, reasons) {
  try {
    const qCache = await caches.open(CACHE_QUARANTINE);
    await qCache.put(new Request(url), response.clone());

    // Update metadata to reflect quarantine
    const meta = (await getMetadata(url)) || {};
    meta.quarantinedAt = Date.now();
    meta.quarantineReasons = reasons;
    meta.quarantineSource = cacheName;
    await storeMetadata(url, meta);

    // Remove from source cache
    const src = await caches.open(cacheName);
    await src.delete(new Request(url));

    await audit('QUARANTINE', { url, reasons, source: cacheName });
  } catch (_) {
    // Non-fatal.
  }
}

/* ------------------------------------------------------------------ */
/*  Full cache scan                                                    */
/* ------------------------------------------------------------------ */

/**
 * Iterate every item in the static and dynamic caches, validate
 * each against the current policy, and quarantine failures.
 *
 * @returns {Promise<Object>} scan report
 */
async function fullCacheScan() {
  const report = { scanned: 0, valid: 0, quarantined: 0, errors: 0, items: [] };

  for (const cacheName of [CACHE_STATIC, CACHE_DYNAMIC]) {
    try {
      const cache = await caches.open(cacheName);
      const requests = await cache.keys();

      for (const request of requests) {
        report.scanned++;
        try {
          const response = await cache.match(request);
          if (!response) continue;

          const meta = await getMetadata(request.url);
          const result = await validateContent(request.url, response, meta);

          if (result.valid) {
            report.valid++;
          } else {
            report.quarantined++;
            report.items.push({ url: request.url, reasons: result.reasons });
            await quarantineItem(cacheName, request.url, response, result.reasons);
          }
        } catch (_) {
          report.errors++;
        }
      }
    } catch (_) {
      report.errors++;
    }
  }

  await audit('FULL_SCAN', report);
  return report;
}

/* ------------------------------------------------------------------ */
/*  Cache statistics                                                   */
/* ------------------------------------------------------------------ */

/**
 * Gather cache statistics for the status report.
 * @returns {Promise<Object>}
 */
async function getCacheStats() {
  const stats = {};
  for (const name of ALL_CACHES) {
    try {
      const cache = await caches.open(name);
      const keys = await cache.keys();
      stats[name] = keys.length;
    } catch (_) {
      stats[name] = -1;
    }
  }
  return stats;
}

/**
 * Build a quarantine report listing all quarantined items.
 * @returns {Promise<Array>}
 */
async function getQuarantineReport() {
  const items = [];
  try {
    const cache = await caches.open(CACHE_QUARANTINE);
    const requests = await cache.keys();
    for (const request of requests) {
      const meta = await getMetadata(request.url);
      items.push({
        url: request.url,
        quarantinedAt: meta?.quarantinedAt || null,
        reasons: meta?.quarantineReasons || [],
        source: meta?.quarantineSource || null,
      });
    }
  } catch (_) {
    // Non-fatal.
  }
  return items;
}

/* ------------------------------------------------------------------ */
/*  Install event                                                      */
/* ------------------------------------------------------------------ */

/**
 * Pre-cache site assets with temporal metadata.
 * (Patent Claims 3-5, 13-15)
 *
 * @listens install
 */
self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      try {
        const cache = await caches.open(CACHE_STATIC);
        const now = Date.now();

        for (const url of PRECACHE_URLS) {
          try {
            const response = await fetch(url, { cache: 'no-cache' });
            if (!response.ok) continue;

            const clone = response.clone();
            const buf = await clone.arrayBuffer();
            const hash = await sha256(buf);
            const contentType = response.headers.get('content-type') || '';
            const origin = new URL(response.url).origin;

            await cache.put(new Request(url), response);

            await storeMetadata(new URL(url, self.location.origin).href, {
              cacheTime: now,
              policyLevel: currentPolicy.policyLevel,
              contentHash: hash,
              contentType,
              origin,
            });
          } catch (_) {
            // Individual asset failure should not block install.
          }
        }

        await audit('INSTALL', {
          assets: PRECACHE_URLS.length,
          policyLevel: currentPolicy.policyLevel,
        });
      } catch (_) {
        // Fatal install errors are logged but do not throw.
      }

      // Activate immediately without waiting for existing clients.
      await self.skipWaiting();
    })()
  );
});

/* ------------------------------------------------------------------ */
/*  Activate event                                                     */
/* ------------------------------------------------------------------ */

/**
 * Clean stale caches and run a validation sweep on all cached content.
 * (Patent Claims 1-2, 12)
 *
 * @listens activate
 */
self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      try {
        // Remove caches that are not in our known set.
        const cacheNames = await caches.keys();
        await Promise.all(
          cacheNames
            .filter(name => !ALL_CACHES.includes(name))
            .map(name => caches.delete(name))
        );

        // Run validation sweep on surviving caches.
        const report = await fullCacheScan();
        await audit('ACTIVATE', { cleanedCaches: cacheNames.length, scanReport: report });
      } catch (_) {
        // Non-fatal.
      }

      // Claim all open clients immediately.
      await self.clients.claim();
    })()
  );
});

/* ------------------------------------------------------------------ */
/*  Fetch event (Patent Claims 3-5, 13-15)                            */
/* ------------------------------------------------------------------ */

/**
 * Intercept every fetch request. For cached responses, extract and
 * validate temporal attributes. If the cached version was stored under
 * a less restrictive policy, block it and fetch fresh.
 *
 * The strategy is cache-first for static assets and network-first for
 * everything else, with policy validation on every cache hit.
 *
 * @listens fetch
 */
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Only handle GET requests; let others pass through.
  if (request.method !== 'GET') return;

  event.respondWith(
    (async () => {
      try {
        return await handleFetch(request);
      } catch (err) {
        // Ultimate fallback: always try the network so the site never breaks.
        try {
          return await fetch(request);
        } catch (_) {
          return new Response('Service Unavailable', {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'text/plain' },
          });
        }
      }
    })()
  );
});

/**
 * Core fetch handler with policy-aware cache validation.
 *
 * @param {Request} request
 * @returns {Promise<Response>}
 */
async function handleFetch(request) {
  const url = request.url;

  // Attempt cache match across static and dynamic caches.
  for (const cacheName of [CACHE_STATIC, CACHE_DYNAMIC]) {
    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);
    if (!cached) continue;

    // Extract temporal attributes (Patent Claims 3-5, 13-15).
    const meta = await getMetadata(url);

    // Validate against current policy.
    const result = await validateContent(url, cached, meta);

    if (result.valid) {
      // Cache hit is compliant -- serve it.
      audit('INTERCEPT', { url, action: 'serve_cache', cache: cacheName });
      return cached;
    }

    // Cache hit is non-compliant. Quarantine and fall through to network.
    await quarantineItem(cacheName, url, cached, result.reasons);
    audit('INTERCEPT', { url, action: 'block_cache', reasons: result.reasons });
    break;
  }

  // Network fetch.
  const response = await fetch(request);

  // Only cache successful, same-origin or CORS responses.
  if (response.ok && (response.type === 'basic' || response.type === 'cors')) {
    try {
      const clone = response.clone();
      const buf = await clone.arrayBuffer();
      const hash = await sha256(buf);
      const contentType = response.headers.get('content-type') || '';
      const origin = new URL(response.url).origin;

      const dynamicCache = await caches.open(CACHE_DYNAMIC);
      await dynamicCache.put(request, response.clone());

      await storeMetadata(url, {
        cacheTime: Date.now(),
        policyLevel: currentPolicy.policyLevel,
        contentHash: hash,
        contentType,
        origin,
      });

      audit('INTERCEPT', { url, action: 'cache_network', cache: CACHE_DYNAMIC });
    } catch (_) {
      // Caching failure should not prevent the response.
    }
  }

  return response;
}

/* ------------------------------------------------------------------ */
/*  Message API (Patent Claims 1-2, 12 -- policy transitions)          */
/* ------------------------------------------------------------------ */

/**
 * Handle messages from the main thread.
 *
 * Supported message types:
 *   POLICY_UPDATE     -- receive a new policy and re-validate caches
 *   SCAN_REQUEST      -- trigger a full cache scan
 *   GET_AUDIT_LOG     -- return the audit trail
 *   GET_STATUS        -- return SW status and cache statistics
 *   QUARANTINE_REPORT -- return quarantined items
 *
 * @listens message
 */
self.addEventListener('message', (event) => {
  const { data } = event;
  if (!data || !data.type) return;

  const respond = (payload) => {
    if (event.ports && event.ports[0]) {
      event.ports[0].postMessage(payload);
    } else if (event.source) {
      event.source.postMessage(payload);
    }
  };

  switch (data.type) {
    /**
     * POLICY_UPDATE (Patent Claims 1-2, 12)
     *
     * Receive a policy transition from the main thread. Iterate all
     * caches, validate each item against the new policy, quarantine
     * non-compliant items, and respond with a validation report.
     */
    case 'POLICY_UPDATE':
      (async () => {
        try {
          const oldPolicy = { ...currentPolicy };
          currentPolicy = {
            ...currentPolicy,
            ...data.policy,
            timestamp: Date.now(),
          };

          await audit('POLICY_UPDATE', {
            from: oldPolicy,
            to: currentPolicy,
          });

          // Re-validate all caches under new policy.
          const report = await fullCacheScan();

          respond({
            type: 'POLICY_UPDATE_ACK',
            success: true,
            oldPolicyLevel: oldPolicy.policyLevel,
            newPolicyLevel: currentPolicy.policyLevel,
            report,
          });
        } catch (err) {
          respond({
            type: 'POLICY_UPDATE_ACK',
            success: false,
            error: err.message,
          });
        }
      })();
      break;

    /** SCAN_REQUEST -- trigger a full cache scan. */
    case 'SCAN_REQUEST':
      (async () => {
        try {
          const report = await fullCacheScan();
          respond({ type: 'SCAN_RESULT', success: true, report });
        } catch (err) {
          respond({ type: 'SCAN_RESULT', success: false, error: err.message });
        }
      })();
      break;

    /** GET_AUDIT_LOG (Patent Claims 9-11, 19-21) */
    case 'GET_AUDIT_LOG':
      (async () => {
        try {
          const log = await getAuditLog();
          respond({ type: 'AUDIT_LOG', success: true, log });
        } catch (err) {
          respond({ type: 'AUDIT_LOG', success: false, error: err.message });
        }
      })();
      break;

    /** GET_STATUS -- return SW status and cache statistics. */
    case 'GET_STATUS':
      (async () => {
        try {
          const stats = await getCacheStats();
          respond({
            type: 'STATUS',
            success: true,
            status: {
              version: '1.0.0',
              policyLevel: currentPolicy.policyLevel,
              policyTimestamp: currentPolicy.timestamp,
              cacheStats: stats,
              upSince: performance.timeOrigin,
            },
          });
        } catch (err) {
          respond({ type: 'STATUS', success: false, error: err.message });
        }
      })();
      break;

    /** QUARANTINE_REPORT -- return quarantined items. */
    case 'QUARANTINE_REPORT':
      (async () => {
        try {
          const items = await getQuarantineReport();
          respond({ type: 'QUARANTINE_REPORT_RESULT', success: true, items });
        } catch (err) {
          respond({
            type: 'QUARANTINE_REPORT_RESULT',
            success: false,
            error: err.message,
          });
        }
      })();
      break;

    default:
      respond({ type: 'UNKNOWN_MESSAGE', original: data.type });
      break;
  }
});
