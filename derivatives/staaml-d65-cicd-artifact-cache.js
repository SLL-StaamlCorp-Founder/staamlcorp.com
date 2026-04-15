'use strict';

/**
 * StaamlCorp Temporal Security Derivative D65
 * CI/CD Build Artifact Cache Posture Gate
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

  // =========== D65: CI/CD Build Artifact Cache Posture Gate ===========
/**
   * D65Engine: Build artifacts validated against deployment policy
   */
  class D65Engine {
    constructor() {
      this.artifacts = new Map();
      this.deploymentGate = [];
      this.stats = {
        artifactsRegistered: 0,
        cacheValidations: 0,
        deploymentsGated: 0,
        deploymentsAllowed: 0
      };
    }

    /**
     * Register a build artifact
     */
    registerArtifact(artifactId, type = 'docker', hash = '', buildTime = now()) {
      this.artifacts.set(artifactId, {
        id: artifactId,
        type,
        hash,
        buildTime,
        registered: now(),
        approved: false
      });
      this.stats.artifactsRegistered++;
      return artifactId;
    }

    /**
     * Validate build cache against policy
     */
    validateBuildCache(artifactId, currentPostureLevel, policy = {}) {
      const artifact = this.artifacts.get(artifactId);
      if (!artifact) return null;

      const minLevel = policy.minPostureLevel || PostureLevel.VERIFIED;
      const maxAge = policy.maxAgeMs || 2592000000; // 30 days
      const age = now() - artifact.buildTime;

      const validation = {
        artifactId,
        valid: currentPostureLevel >= minLevel && age <= maxAge,
        reason: currentPostureLevel < minLevel ? 'Insufficient posture' :
                age > maxAge ? 'Cache expired' : 'Valid',
        validated: now()
      };

      this.stats.cacheValidations++;
      if (validation.valid) artifact.approved = true;

      return validation;
    }

    /**
     * Gate deployment based on artifact validation
     */
    gateDeployment(deploymentId, artifactIds, currentPostureLevel) {
      this.stats.deploymentsGated++;

      const artifactValidations = artifactIds.map(id =>
        this.validateBuildCache(id, currentPostureLevel));

      const allValid = artifactValidations.every(v => v && v.valid);

      const gate = {
        deploymentId,
        timestamp: now(),
        allowed: allValid,
        artifacts: artifactValidations
      };

      this.deploymentGate.push(gate);
      if (allValid) this.stats.deploymentsAllowed++;

      return gate;
    }

    /**
     * Get build statistics
     */
    getBuildStats() {
      return {
        ...this.stats,
        registeredArtifacts: this.artifacts.size,
        approvedArtifacts: Array.from(this.artifacts.values())
          .filter(a => a.approved).length
      };
    }

    /**
     * Handle posture transitions
     */
    onPostureTransition(priorLevel, currentLevel, delta) {
      const revalidations = [];

      this.artifacts.forEach((artifact, artifactId) => {
        if (artifact.approved && currentLevel < priorLevel) {
          const validation = this.validateBuildCache(artifactId, currentLevel);
          if (!validation.valid) {
            artifact.approved = false;
            revalidations.push(artifactId);
          }
        }
      });

      return { revalidatedArtifacts: revalidations };
    }

    /**
     * Get comprehensive statistics
     */
    getStats() {
      return this.getBuildStats();
    }
  }

  globalThis.StaamlD65 = { PostureLevel, D65Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
