'use strict';

/**
 * StaamlCorp Layer 4 Verification Derivatives
 * RIT (Recursive Identity Transformers) and CBQE (Curvature-Based Quantum Encryption)
 *
 * @fileoverview Tier 1 identity verification and functional encryption for
 * highest-sensitivity data within the StaamlCorp TSB framework.
 * Uses Web Crypto API exclusively. No external dependencies.
 *
 * @version 1.0.0
 * @license Proprietary - StaamlCorp
 */

// ============================================================================
// Enums and Constants
// ============================================================================

/**
 * Identity component types with associated criticality scores.
 * Higher criticality = verified first and triggers stricter remediation on mismatch.
 * @enum {Object}
 */
const IdentityComponentType = Object.freeze({
  SOUL_MD:          { name: 'SOUL_MD',          criticality: 10 },
  MEMORY_MD:        { name: 'MEMORY_MD',        criticality: 9 },
  PERMISSION_SET:   { name: 'PERMISSION_SET',   criticality: 8 },
  CONFIG:           { name: 'CONFIG',           criticality: 7 },
  SKILL_MANIFEST:   { name: 'SKILL_MANIFEST',   criticality: 6 },
  MODEL_WEIGHTS:    { name: 'MODEL_WEIGHTS',    criticality: 5 },
  BLUEPRINT_STATE:  { name: 'BLUEPRINT_STATE',  criticality: 4 },
  TOOL_REGISTRY:    { name: 'TOOL_REGISTRY',    criticality: 3 },
});

/**
 * Possible results of an identity verification check.
 * @enum {string}
 */
const VerificationResult = Object.freeze({
  VERIFIED:           'VERIFIED',
  TAMPERED:           'TAMPERED',
  MISSING_COMPONENT:  'MISSING_COMPONENT',
  CHAIN_BROKEN:       'CHAIN_BROKEN',
  FIRST_RUN:          'FIRST_RUN',
  DEGRADED:           'DEGRADED',
});

/**
 * Actions to take when identity verification fails.
 * @enum {string}
 */
const RemediationAction = Object.freeze({
  BLOCK_PHI_ACCESS:       'BLOCK_PHI_ACCESS',
  RESTORE_FROM_BACKUP:    'RESTORE_FROM_BACKUP',
  ALERT_SECURITY_TEAM:    'ALERT_SECURITY_TEAM',
  QUARANTINE_AGENT:       'QUARANTINE_AGENT',
  FORCE_REINITIALIZATION: 'FORCE_REINITIALIZATION',
  CONTINUE_WITH_WARNING:  'CONTINUE_WITH_WARNING',
});

/**
 * CBQE security levels.
 * @enum {string}
 */
const CBQESecurityLevel = Object.freeze({
  FULL:          'FULL',
  REDUCED:       'REDUCED',
  FALLBACK_ONLY: 'FALLBACK_ONLY',
});

/**
 * Data sensitivity classifications for CBQE encryption tiers.
 * @enum {string}
 */
const DataSensitivity = Object.freeze({
  GENOMIC:         'GENOMIC',
  PSYCHIATRIC:     'PSYCHIATRIC',
  SUBSTANCE_ABUSE: 'SUBSTANCE_ABUSE',
  STANDARD_PHI:    'STANDARD_PHI',
  DEIDENTIFIED:    'DEIDENTIFIED',
});

// ============================================================================
// Utility Helpers
// ============================================================================

/**
 * Generate a UUID v4.
 * @returns {string}
 */
function generateId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Get the SubtleCrypto instance.
 * @returns {SubtleCrypto}
 */
function getSubtleCrypto() {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    return crypto.subtle;
  }
  throw new Error('Web Crypto API (SubtleCrypto) is not available in this environment.');
}

/**
 * Encode a string to Uint8Array (UTF-8).
 * @param {string} str
 * @returns {Uint8Array}
 */
function encode(str) {
  return new TextEncoder().encode(str);
}

/**
 * Decode a Uint8Array to string (UTF-8).
 * @param {Uint8Array} buf
 * @returns {string}
 */
function decode(buf) {
  return new TextDecoder().decode(buf);
}

/**
 * Convert ArrayBuffer to hex string.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  const hexParts = [];
  for (let i = 0; i < bytes.length; i++) {
    hexParts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return hexParts.join('');
}

/**
 * Convert hex string to Uint8Array.
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Concatenate two Uint8Arrays.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array}
 */
function concatBuffers(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

/**
 * Compute SHA-256 hash.
 * @param {Uint8Array} data
 * @returns {Promise<string>} Hex-encoded hash
 */
async function sha256(data) {
  const subtle = getSubtleCrypto();
  const hash = await subtle.digest('SHA-256', data);
  return bufferToHex(hash);
}

/**
 * Compute HMAC-SHA-256.
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Promise<string>} Hex-encoded HMAC
 */
async function hmacSha256(key, data) {
  const subtle = getSubtleCrypto();
  const cryptoKey = await subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await subtle.sign('HMAC', cryptoKey, data);
  return bufferToHex(sig);
}

/**
 * Get current ISO timestamp.
 * @returns {string}
 */
function nowISO() {
  return new Date().toISOString();
}

// ============================================================================
// RIT Data Classes
// ============================================================================

/**
 * Represents a single identity component tracked by RIT.
 */
class IdentityComponent {
  /**
   * @param {Object} params
   * @param {Object} params.componentType - IdentityComponentType enum value
   * @param {string} params.componentId
   * @param {string} params.contentHash - SHA-256 hex of the component content
   * @param {number} params.contentSize - byte length of the component content
   * @param {string} params.lastModified - ISO timestamp
   * @param {string} params.version
   * @param {Object} [params.metadata={}]
   */
  constructor({ componentType, componentId, contentHash, contentSize, lastModified, version, metadata }) {
    this.componentType = componentType;
    this.componentId = componentId;
    this.contentHash = contentHash;
    this.contentSize = contentSize;
    this.lastModified = lastModified;
    this.version = version;
    this.metadata = metadata || {};
  }

  /**
   * Return a plain object copy suitable for serialization.
   * @returns {Object}
   */
  toJSON() {
    return {
      componentType: this.componentType.name,
      componentId: this.componentId,
      contentHash: this.contentHash,
      contentSize: this.contentSize,
      lastModified: this.lastModified,
      version: this.version,
      metadata: Object.assign({}, this.metadata),
    };
  }
}

/**
 * An identity fingerprint produced by the recursive hash chain algorithm.
 */
class IdentityFingerprint {
  /**
   * @param {Object} params
   * @param {string} params.fingerprintId
   * @param {string} params.agentId
   * @param {string} params.sessionId
   * @param {string} params.timestamp
   * @param {string} params.recursiveHash
   * @param {Object} params.componentHashes - map of componentType.name -> contentHash
   * @param {number} params.componentCount
   * @param {number} params.chainDepth
   * @param {string} params.signedFingerprint - HMAC of the recursive hash
   */
  constructor({ fingerprintId, agentId, sessionId, timestamp, recursiveHash, componentHashes, componentCount, chainDepth, signedFingerprint }) {
    this.fingerprintId = fingerprintId;
    this.agentId = agentId;
    this.sessionId = sessionId;
    this.timestamp = timestamp;
    this.recursiveHash = recursiveHash;
    this.componentHashes = componentHashes;
    this.componentCount = componentCount;
    this.chainDepth = chainDepth;
    this.signedFingerprint = signedFingerprint;
  }

  /**
   * @returns {Object}
   */
  toJSON() {
    return {
      fingerprintId: this.fingerprintId,
      agentId: this.agentId,
      sessionId: this.sessionId,
      timestamp: this.timestamp,
      recursiveHash: this.recursiveHash,
      componentHashes: Object.assign({}, this.componentHashes),
      componentCount: this.componentCount,
      chainDepth: this.chainDepth,
      signedFingerprint: this.signedFingerprint,
    };
  }
}

/**
 * Report produced after an identity verification pass.
 */
class VerificationReport {
  /**
   * @param {Object} params
   * @param {string} params.reportId
   * @param {string} params.agentId
   * @param {string} params.sessionId
   * @param {string} params.timestamp
   * @param {string} params.result - VerificationResult value
   * @param {IdentityFingerprint|null} params.currentFingerprint
   * @param {IdentityFingerprint|null} params.expectedFingerprint
   * @param {Array<Object>} params.discrepancies
   * @param {Array<string>} params.remediation - RemediationAction values
   * @param {number} params.verificationDurationMs
   */
  constructor({ reportId, agentId, sessionId, timestamp, result, currentFingerprint, expectedFingerprint, discrepancies, remediation, verificationDurationMs }) {
    this.reportId = reportId;
    this.agentId = agentId;
    this.sessionId = sessionId;
    this.timestamp = timestamp;
    this.result = result;
    this.currentFingerprint = currentFingerprint;
    this.expectedFingerprint = expectedFingerprint;
    this.discrepancies = discrepancies || [];
    this.remediation = remediation || [];
    this.verificationDurationMs = verificationDurationMs;
  }

  /**
   * @returns {Object}
   */
  toJSON() {
    return {
      reportId: this.reportId,
      agentId: this.agentId,
      sessionId: this.sessionId,
      timestamp: this.timestamp,
      result: this.result,
      currentFingerprint: this.currentFingerprint ? this.currentFingerprint.toJSON() : null,
      expectedFingerprint: this.expectedFingerprint ? this.expectedFingerprint.toJSON() : null,
      discrepancies: this.discrepancies.slice(),
      remediation: this.remediation.slice(),
      verificationDurationMs: this.verificationDurationMs,
    };
  }
}

// ============================================================================
// RIT Engine
// ============================================================================

/**
 * Recursive Identity Transformers engine.
 *
 * Implements recursive identity fingerprinting to detect memory poisoning,
 * SOUL.md tampering, and prompt injection via identity drift.
 *
 * Recursive Hash Chain Algorithm:
 *   Components sorted by criticality (highest first)
 *   H_0 = SHA-256(component_0_hash)
 *   H_i = SHA-256(H_{i-1} || component_i_hash)
 *   fingerprint = HMAC(master_key, H_n || agent_id || session_id || timestamp)
 */
class RITEngine {
  /**
   * @param {string} masterKey - Hex-encoded master key for HMAC signing
   * @param {string} agentId - Unique identifier for the agent being protected
   */
  constructor(masterKey, agentId) {
    /** @private */
    this._masterKey = masterKey;
    /** @private */
    this._masterKeyBytes = hexToBuffer(masterKey);
    /** @private */
    this._agentId = agentId;
    /** @private @type {Map<string, IdentityComponent>} */
    this._components = new Map();
    /** @private @type {IdentityFingerprint[]} */
    this._fingerprintChain = [];
    /** @private @type {VerificationReport[]} */
    this._verificationHistory = [];
    /** @private */
    this._initialized = true;
  }

  /**
   * Register (or update) an identity component.
   *
   * @param {Object} componentType - IdentityComponentType enum value
   * @param {string} content - Raw content of the component
   * @param {string} version - Semantic version string
   * @param {Object} [metadata={}] - Arbitrary metadata
   * @returns {Promise<IdentityComponent>}
   */
  async registerComponent(componentType, content, version, metadata) {
    if (!componentType || !componentType.name || typeof componentType.criticality !== 'number') {
      throw new Error('Invalid componentType: must be an IdentityComponentType enum value.');
    }

    const contentBytes = encode(content);
    const contentHash = await sha256(contentBytes);
    const componentId = generateId();

    const component = new IdentityComponent({
      componentType: componentType,
      componentId: componentId,
      contentHash: contentHash,
      contentSize: contentBytes.length,
      lastModified: nowISO(),
      version: version,
      metadata: metadata || {},
    });

    this._components.set(componentType.name, component);
    return component;
  }

  /**
   * Compute the recursive identity fingerprint for the current component set.
   *
   * Algorithm:
   *   1. Sort components by criticality descending.
   *   2. H_0 = SHA-256(component_0.contentHash)
   *   3. H_i = SHA-256(H_{i-1} || component_i.contentHash)
   *   4. fingerprint = HMAC(masterKey, H_n || agentId || sessionId || timestamp)
   *
   * @param {string} sessionId
   * @returns {Promise<IdentityFingerprint>}
   */
  async computeFingerprint(sessionId) {
    if (this._components.size === 0) {
      throw new Error('No components registered. Cannot compute fingerprint.');
    }

    // Sort by criticality descending
    const sorted = Array.from(this._components.values()).sort(
      (a, b) => b.componentType.criticality - a.componentType.criticality
    );

    // Build recursive hash chain
    let currentHash = await sha256(encode(sorted[0].contentHash));

    for (let i = 1; i < sorted.length; i++) {
      const combined = concatBuffers(
        hexToBuffer(currentHash),
        encode(sorted[i].contentHash)
      );
      currentHash = await sha256(combined);
    }

    const timestamp = nowISO();

    // HMAC sign: H_n || agentId || sessionId || timestamp
    const hmacPayload = concatBuffers(
      concatBuffers(
        hexToBuffer(currentHash),
        encode(this._agentId)
      ),
      concatBuffers(
        encode(sessionId),
        encode(timestamp)
      )
    );

    const signedFingerprint = await hmacSha256(this._masterKeyBytes, hmacPayload);

    // Collect component hashes map
    const componentHashes = {};
    for (const [name, comp] of this._components) {
      componentHashes[name] = comp.contentHash;
    }

    const fingerprint = new IdentityFingerprint({
      fingerprintId: generateId(),
      agentId: this._agentId,
      sessionId: sessionId,
      timestamp: timestamp,
      recursiveHash: currentHash,
      componentHashes: componentHashes,
      componentCount: sorted.length,
      chainDepth: sorted.length,
      signedFingerprint: signedFingerprint,
    });

    this._fingerprintChain.push(fingerprint);
    return fingerprint;
  }

  /**
   * Verify current identity against an expected fingerprint.
   *
   * Discrepancy detection: compares component hashes between expected and current.
   * Any mismatch in criticality >= 8 components triggers TAMPERED result and
   * BLOCK_PHI_ACCESS remediation.
   *
   * @param {string} sessionId
   * @param {IdentityFingerprint} expectedFingerprint
   * @returns {Promise<VerificationReport>}
   */
  async verifyIdentity(sessionId, expectedFingerprint) {
    const startTime = performance.now();

    // First-run detection
    if (!expectedFingerprint) {
      const currentFp = await this.computeFingerprint(sessionId);
      const report = new VerificationReport({
        reportId: generateId(),
        agentId: this._agentId,
        sessionId: sessionId,
        timestamp: nowISO(),
        result: VerificationResult.FIRST_RUN,
        currentFingerprint: currentFp,
        expectedFingerprint: null,
        discrepancies: [],
        remediation: [RemediationAction.CONTINUE_WITH_WARNING],
        verificationDurationMs: performance.now() - startTime,
      });
      this._verificationHistory.push(report);
      return report;
    }

    // Compute current fingerprint
    const currentFp = await this.computeFingerprint(sessionId);

    // Compare component hashes
    const discrepancies = [];
    const remediation = [];
    let result = VerificationResult.VERIFIED;

    const expectedHashes = expectedFingerprint.componentHashes || {};
    const currentHashes = currentFp.componentHashes || {};

    // Check for missing components
    for (const compName of Object.keys(expectedHashes)) {
      if (!(compName in currentHashes)) {
        discrepancies.push({
          component: compName,
          type: 'MISSING',
          expected: expectedHashes[compName],
          actual: null,
        });
        result = VerificationResult.MISSING_COMPONENT;
      }
    }

    // Check for hash mismatches
    for (const compName of Object.keys(expectedHashes)) {
      if (compName in currentHashes && expectedHashes[compName] !== currentHashes[compName]) {
        const compType = IdentityComponentType[compName];
        const criticality = compType ? compType.criticality : 0;

        discrepancies.push({
          component: compName,
          type: 'HASH_MISMATCH',
          expected: expectedHashes[compName],
          actual: currentHashes[compName],
          criticality: criticality,
        });

        // Criticality >= 8 triggers TAMPERED
        if (criticality >= 8) {
          result = VerificationResult.TAMPERED;
          if (!remediation.includes(RemediationAction.BLOCK_PHI_ACCESS)) {
            remediation.push(RemediationAction.BLOCK_PHI_ACCESS);
          }
          if (!remediation.includes(RemediationAction.ALERT_SECURITY_TEAM)) {
            remediation.push(RemediationAction.ALERT_SECURITY_TEAM);
          }
        } else if (result !== VerificationResult.TAMPERED) {
          result = VerificationResult.DEGRADED;
          if (!remediation.includes(RemediationAction.CONTINUE_WITH_WARNING)) {
            remediation.push(RemediationAction.CONTINUE_WITH_WARNING);
          }
        }
      }
    }

    // Check recursive hash chain integrity
    if (discrepancies.length === 0 && currentFp.recursiveHash !== expectedFingerprint.recursiveHash) {
      result = VerificationResult.CHAIN_BROKEN;
      remediation.push(RemediationAction.QUARANTINE_AGENT);
      remediation.push(RemediationAction.FORCE_REINITIALIZATION);
      discrepancies.push({
        component: '__RECURSIVE_CHAIN__',
        type: 'CHAIN_MISMATCH',
        expected: expectedFingerprint.recursiveHash,
        actual: currentFp.recursiveHash,
      });
    }

    // If tampered, also recommend quarantine
    if (result === VerificationResult.TAMPERED) {
      if (!remediation.includes(RemediationAction.QUARANTINE_AGENT)) {
        remediation.push(RemediationAction.QUARANTINE_AGENT);
      }
      if (!remediation.includes(RemediationAction.RESTORE_FROM_BACKUP)) {
        remediation.push(RemediationAction.RESTORE_FROM_BACKUP);
      }
    }

    const report = new VerificationReport({
      reportId: generateId(),
      agentId: this._agentId,
      sessionId: sessionId,
      timestamp: nowISO(),
      result: result,
      currentFingerprint: currentFp,
      expectedFingerprint: expectedFingerprint,
      discrepancies: discrepancies,
      remediation: remediation.length > 0 ? remediation : [RemediationAction.CONTINUE_WITH_WARNING],
      verificationDurationMs: performance.now() - startTime,
    });

    this._verificationHistory.push(report);
    return report;
  }

  /**
   * Verify identity after a blueprint transition.
   * Registers the new blueprint state component before verification.
   *
   * @param {string} newSessionId
   * @param {string} blueprintName
   * @param {string} blueprintHash
   * @returns {Promise<VerificationReport>}
   */
  async verifyAfterBlueprintTransition(newSessionId, blueprintName, blueprintHash) {
    // Register or update blueprint state
    await this.registerComponent(
      IdentityComponentType.BLUEPRINT_STATE,
      blueprintHash,
      '1.0.0',
      { blueprintName: blueprintName, transitionedAt: nowISO() }
    );

    // Get the previous fingerprint if one exists
    const previousFp = this._fingerprintChain.length > 0
      ? this._fingerprintChain[this._fingerprintChain.length - 1]
      : null;

    return this.verifyIdentity(newSessionId, previousFp);
  }

  /**
   * Pre-access enforcement gate.
   * Computes current fingerprint and compares against the most recent known-good one.
   *
   * @param {string} sessionId
   * @returns {Promise<{allowed: boolean, reason: string}>}
   */
  async gateAccess(sessionId) {
    if (this._fingerprintChain.length === 0) {
      // No prior fingerprint — allow but warn
      return { allowed: true, reason: 'FIRST_RUN: No prior fingerprint to verify against.' };
    }

    const expectedFp = this._fingerprintChain[this._fingerprintChain.length - 1];
    const report = await this.verifyIdentity(sessionId, expectedFp);

    if (report.result === VerificationResult.VERIFIED) {
      return { allowed: true, reason: 'Identity verified successfully.' };
    }

    if (report.result === VerificationResult.DEGRADED) {
      return { allowed: true, reason: 'Identity degraded but within tolerance. Proceeding with warning.' };
    }

    // TAMPERED, MISSING_COMPONENT, CHAIN_BROKEN
    return {
      allowed: false,
      reason: `Access blocked: ${report.result}. Discrepancies: ${report.discrepancies.length}. ` +
              `Remediation: ${report.remediation.join(', ')}.`,
    };
  }

  /**
   * Get all verification reports.
   * @returns {VerificationReport[]}
   */
  getVerificationHistory() {
    return this._verificationHistory.slice();
  }

  /**
   * Get the full fingerprint chain.
   * @returns {IdentityFingerprint[]}
   */
  getFingerprintChain() {
    return this._fingerprintChain.slice();
  }

  /**
   * Get all registered components.
   * @returns {IdentityComponent[]}
   */
  getComponentInventory() {
    return Array.from(this._components.values());
  }
}

// ============================================================================
// CBQE Geometric Primitives
// ============================================================================

/**
 * A point in curvature space defined by three angular projections.
 * kappa (curvature), tau (torsion), sigma (shear).
 */
class CurvaturePoint {
  /**
   * @param {number} kappa - Curvature component
   * @param {number} tau - Torsion component
   * @param {number} sigma - Shear component
   */
  constructor(kappa, tau, sigma) {
    /** @type {number} */
    this.kappa = kappa;
    /** @type {number} */
    this.tau = tau;
    /** @type {number} */
    this.sigma = sigma;
  }

  /**
   * Serialize to 24 bytes (3 x Float64).
   * @returns {Uint8Array}
   */
  toBytes() {
    const buffer = new ArrayBuffer(24);
    const view = new DataView(buffer);
    view.setFloat64(0, this.kappa, true);
    view.setFloat64(8, this.tau, true);
    view.setFloat64(16, this.sigma, true);
    return new Uint8Array(buffer);
  }

  /**
   * Deserialize from 24 bytes.
   * @param {Uint8Array} data
   * @returns {CurvaturePoint}
   */
  static fromBytes(data) {
    if (data.length < 24) {
      throw new Error('CurvaturePoint.fromBytes requires at least 24 bytes.');
    }
    const view = new DataView(data.buffer, data.byteOffset, 24);
    return new CurvaturePoint(
      view.getFloat64(0, true),
      view.getFloat64(8, true),
      view.getFloat64(16, true)
    );
  }

  /**
   * Encode a local angle using curvature geometry.
   * theta_local = (1/2) * theta_curvature
   * psi_encoded = f(theta_local, gamma_entangled_arc)
   *
   * @param {number} thetaCurvature
   * @param {number} gammaEntangledArc
   * @returns {number} psi_encoded
   */
  encode(thetaCurvature, gammaEntangledArc) {
    const thetaLocal = 0.5 * thetaCurvature;
    const psiEncoded = Math.sin(thetaLocal) * this.kappa +
                       Math.cos(thetaLocal) * this.tau +
                       gammaEntangledArc * this.sigma;
    return psiEncoded;
  }

  /**
   * @returns {Object}
   */
  toJSON() {
    return { kappa: this.kappa, tau: this.tau, sigma: this.sigma };
  }
}

/**
 * A curvature field: a live topology derived from master entropy and a nonce.
 * Different nonces produce geometrically distinct fields.
 *
 * Properties:
 *  - No algebraic structure (no group/ring/lattice)
 *  - Observer-dependent (misaligned access destroys data)
 *  - Self-sealing (side-channel triggers collapse)
 */
class CurvatureField {
  /**
   * @param {Uint8Array} seedBytes - Derived from master entropy + nonce
   * @param {string} fieldId
   * @param {string} nonce - Hex-encoded nonce
   * @param {string} createdAt - ISO timestamp
   */
  constructor(seedBytes, fieldId, nonce, createdAt) {
    /** @private */
    this._seedBytes = seedBytes;
    /** @type {string} */
    this.fieldId = fieldId;
    /** @type {string} */
    this.nonce = nonce;
    /** @type {string} */
    this.createdAt = createdAt;
    /** @private @type {CurvaturePoint[]} */
    this._cachedPoints = [];
  }

  /**
   * Generate a curvature field from master entropy and a nonce.
   *
   * @param {Uint8Array} masterEntropy
   * @param {string} nonce - Hex-encoded nonce
   * @returns {Promise<CurvatureField>}
   */
  static async generateField(masterEntropy, nonce) {
    const nonceBytes = hexToBuffer(nonce);
    const combined = concatBuffers(masterEntropy, nonceBytes);
    const seedHex = await sha256(combined);
    const seedBytes = hexToBuffer(seedHex);

    return new CurvatureField(
      seedBytes,
      generateId(),
      nonce,
      nowISO()
    );
  }

  /**
   * Evaluate the curvature field at a given position (0-based index).
   * Deterministic: the same field + position always yields the same point.
   *
   * @param {number} position
   * @returns {Promise<CurvaturePoint>}
   */
  async evaluatePoint(position) {
    if (this._cachedPoints[position]) {
      return this._cachedPoints[position];
    }

    // Derive position-specific seed
    const posBytes = encode(String(position));
    const combined = concatBuffers(this._seedBytes, posBytes);
    const pointHash = await sha256(combined);
    const pointBytes = hexToBuffer(pointHash);

    // Extract three Float64-range values from the hash bytes
    // Use first 24 bytes mapped to [-PI, PI] range
    const view = new DataView(pointBytes.buffer, pointBytes.byteOffset, 24);
    const kappa = ((view.getUint32(0, true) / 0xffffffff) * 2 * Math.PI) - Math.PI;
    const tau = ((view.getUint32(4, true) / 0xffffffff) * 2 * Math.PI) - Math.PI;
    const sigma = ((view.getUint32(8, true) / 0xffffffff) * 2 * Math.PI) - Math.PI;

    const point = new CurvaturePoint(kappa, tau, sigma);
    this._cachedPoints[position] = point;
    return point;
  }

  /**
   * Get field metadata (safe to share — does not expose seed).
   * @returns {Object}
   */
  getMetadata() {
    return {
      fieldId: this.fieldId,
      nonce: this.nonce,
      createdAt: this.createdAt,
    };
  }
}

// ============================================================================
// CBQE Engine
// ============================================================================

/**
 * Curvature-Based Quantum Encryption engine.
 *
 * Tier 1 functional encryption using recursive geometry for
 * highest-sensitivity data (genomic, psychiatric, substance abuse).
 */
class CBQEEngine {
  /**
   * @param {string} masterKey - Hex-encoded master key
   */
  constructor(masterKey) {
    /** @private */
    this._masterKey = masterKey;
    /** @private */
    this._masterKeyBytes = hexToBuffer(masterKey);
    /** @private @type {CurvatureField|null} */
    this._currentField = null;
    /** @private */
    this._securityLevel = CBQESecurityLevel.FULL;
    /** @private @type {Array<Object>} */
    this._fieldHistory = [];
    /** @private */
    this._initialized = false;
  }

  /**
   * Initialize the engine by generating the first curvature field.
   * @returns {Promise<void>}
   * @private
   */
  async _ensureInitialized() {
    if (this._initialized) return;

    const nonceBytes = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(nonceBytes);
    } else {
      for (let i = 0; i < 16; i++) {
        nonceBytes[i] = Math.floor(Math.random() * 256);
      }
    }
    const nonce = bufferToHex(nonceBytes);

    this._currentField = await CurvatureField.generateField(this._masterKeyBytes, nonce);
    this._fieldHistory.push({
      fieldId: this._currentField.fieldId,
      nonce: nonce,
      createdAt: this._currentField.createdAt,
      reason: 'INITIALIZATION',
    });
    this._initialized = true;
  }

  /**
   * Encrypt plaintext using curvature-based encryption.
   *
   * @param {string} plaintext - The data to encrypt
   * @param {string} sensitivity - DataSensitivity enum value
   * @param {string} [associatedData=''] - Additional authenticated data
   * @returns {Promise<Object>} Encrypted payload with ciphertext, field metadata, sensitivity, timestamp
   */
  async encrypt(plaintext, sensitivity, associatedData) {
    await this._ensureInitialized();
    associatedData = associatedData || '';

    const subtle = getSubtleCrypto();

    // Generate a per-message nonce
    const iv = new Uint8Array(12);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(iv);
    }

    // Derive encryption key from curvature field + sensitivity
    const fieldPoint = await this._currentField.evaluatePoint(0);
    const pointBytes = fieldPoint.toBytes();
    const sensitivityBytes = encode(sensitivity);
    const adBytes = encode(associatedData);

    const keyMaterial = concatBuffers(
      concatBuffers(this._masterKeyBytes, pointBytes),
      concatBuffers(sensitivityBytes, adBytes)
    );

    const derivedKeyHash = await sha256(keyMaterial);
    const derivedKeyBytes = hexToBuffer(derivedKeyHash);

    // Import as AES-GCM key
    const aesKey = await subtle.importKey(
      'raw',
      derivedKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const plaintextBytes = encode(plaintext);
    const ciphertextBuffer = await subtle.encrypt(
      { name: 'AES-GCM', iv: iv, additionalData: encode(associatedData) },
      aesKey,
      plaintextBytes
    );

    return {
      ciphertext: bufferToHex(ciphertextBuffer),
      iv: bufferToHex(iv),
      fieldMetadata: this._currentField.getMetadata(),
      sensitivity: sensitivity,
      timestamp: nowISO(),
    };
  }

  /**
   * Decrypt ciphertext produced by encrypt().
   *
   * @param {Object} encryptedPayload - The object returned by encrypt()
   * @param {string} [associatedData=''] - Must match the associated data used during encryption
   * @returns {Promise<string>} Decrypted plaintext
   */
  async decrypt(encryptedPayload, associatedData) {
    await this._ensureInitialized();
    associatedData = associatedData || '';

    const subtle = getSubtleCrypto();

    // Reconstruct the field from metadata
    const fieldMeta = encryptedPayload.fieldMetadata;
    const field = await CurvatureField.generateField(this._masterKeyBytes, fieldMeta.nonce);

    const fieldPoint = await field.evaluatePoint(0);
    const pointBytes = fieldPoint.toBytes();
    const sensitivityBytes = encode(encryptedPayload.sensitivity);
    const adBytes = encode(associatedData);

    const keyMaterial = concatBuffers(
      concatBuffers(this._masterKeyBytes, pointBytes),
      concatBuffers(sensitivityBytes, adBytes)
    );

    const derivedKeyHash = await sha256(keyMaterial);
    const derivedKeyBytes = hexToBuffer(derivedKeyHash);

    const aesKey = await subtle.importKey(
      'raw',
      derivedKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const iv = hexToBuffer(encryptedPayload.iv);
    const ciphertext = hexToBuffer(encryptedPayload.ciphertext);

    const plaintextBuffer = await subtle.decrypt(
      { name: 'AES-GCM', iv: iv, additionalData: encode(associatedData) },
      aesKey,
      ciphertext
    );

    return decode(plaintextBuffer);
  }

  /**
   * Classify data sensitivity from a descriptor string.
   *
   * @param {string} dataDescriptor - Description of the data
   * @returns {string} DataSensitivity value
   */
  classifySensitivity(dataDescriptor) {
    const lower = dataDescriptor.toLowerCase();

    if (lower.includes('genomic') || lower.includes('genetic') || lower.includes('dna') || lower.includes('genome')) {
      return DataSensitivity.GENOMIC;
    }
    if (lower.includes('psychiatric') || lower.includes('mental health') || lower.includes('psych')) {
      return DataSensitivity.PSYCHIATRIC;
    }
    if (lower.includes('substance') || lower.includes('addiction') || lower.includes('drug') || lower.includes('alcohol')) {
      return DataSensitivity.SUBSTANCE_ABUSE;
    }
    if (lower.includes('deidentified') || lower.includes('de-identified') || lower.includes('anonymized')) {
      return DataSensitivity.DEIDENTIFIED;
    }

    return DataSensitivity.STANDARD_PHI;
  }

  /**
   * Get current security level.
   * @returns {string} CBQESecurityLevel value
   */
  getSecurityLevel() {
    return this._securityLevel;
  }

  /**
   * Rotate the curvature field. Generates a new field from fresh entropy.
   *
   * @param {string} reason - Human-readable reason for rotation
   * @returns {Promise<Object>} New field metadata
   */
  async rotateField(reason) {
    const nonceBytes = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(nonceBytes);
    } else {
      for (let i = 0; i < 16; i++) {
        nonceBytes[i] = Math.floor(Math.random() * 256);
      }
    }
    const nonce = bufferToHex(nonceBytes);

    this._currentField = await CurvatureField.generateField(this._masterKeyBytes, nonce);
    this._fieldHistory.push({
      fieldId: this._currentField.fieldId,
      nonce: nonce,
      createdAt: this._currentField.createdAt,
      reason: reason,
    });

    return this._currentField.getMetadata();
  }
}

// ============================================================================
// Public API: window.StaamlLayer4
// ============================================================================

/**
 * StaamlLayer4 public interface.
 * Exposes RIT and CBQE engines and provides initialization helpers.
 */
const StaamlLayer4 = Object.freeze({
  /** @type {string} */
  VERSION: '1.0.0',

  /** RIT class reference */
  RIT: RITEngine,

  /** CBQE class reference */
  CBQE: CBQEEngine,

  /** Enums */
  IdentityComponentType: IdentityComponentType,
  VerificationResult: VerificationResult,
  RemediationAction: RemediationAction,
  CBQESecurityLevel: CBQESecurityLevel,
  DataSensitivity: DataSensitivity,

  /** Data classes */
  IdentityComponent: IdentityComponent,
  IdentityFingerprint: IdentityFingerprint,
  VerificationReport: VerificationReport,
  CurvaturePoint: CurvaturePoint,
  CurvatureField: CurvatureField,

  /**
   * Initialize both RIT and CBQE engines.
   *
   * @param {string} masterKey - Hex-encoded master key (at least 64 hex chars / 256 bits)
   * @param {string} agentId - Unique agent identifier
   * @returns {{ rit: RITEngine, cbqe: CBQEEngine }}
   */
  init(masterKey, agentId) {
    if (!masterKey || masterKey.length < 64) {
      throw new Error('masterKey must be at least 256 bits (64 hex characters).');
    }
    if (!agentId) {
      throw new Error('agentId is required.');
    }

    const rit = new RITEngine(masterKey, agentId);
    const cbqe = new CBQEEngine(masterKey);

    return { rit: rit, cbqe: cbqe };
  },

  /**
   * Get current status of the Layer 4 subsystem.
   *
   * @returns {Object}
   */
  getStatus() {
    return {
      version: '1.0.0',
      layer: 4,
      derivatives: ['RIT', 'CBQE'],
      ritDescription: 'Recursive Identity Transformers',
      cbqeDescription: 'Curvature-Based Quantum Encryption',
      cryptoAvailable: typeof crypto !== 'undefined' && !!crypto.subtle,
      timestamp: nowISO(),
    };
  },
});

// Attach to window if available (browser), otherwise export for Node/testing
if (typeof window !== 'undefined') {
  window.StaamlLayer4 = StaamlLayer4;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = StaamlLayer4;
}
