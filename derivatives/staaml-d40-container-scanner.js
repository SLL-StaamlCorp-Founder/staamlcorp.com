'use strict';

/**
 * StaamlCorp Temporal Security Derivative D40
 * Posture-Aware Container Image Scanner
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

  // =========== D40: Posture-Aware Container Image Scanner ===========
/**
   * D40: OCI image layers carry posture tags, admission controller validates
   * Enforces container image posture compliance at admission
   */
  class D40Engine {
    constructor() {
      this.images = new Map();
      this.scannerStats = {
        imagesScanned: 0,
        layersValidated: 0,
        imagesBlocked: 0,
        complianceFailures: 0
      };
      this.id = generateId();
    }

    /**
     * Scan container image for posture
     * @param {string} imageName Image name/reference
     * @param {string[]} layerIds Layer identifiers
     * @returns {object} Scan result {imageId, layers, compliant}
     */
    scanImage(imageName, layerIds) {
      const imageId = generateId();
      const layers = layerIds.map(lid => ({
        id: lid,
        posture: PostureLevel.BASELINE,
        scanned: now()
      }));

      this.images.set(imageId, {
        name: imageName,
        layers,
        scanned: now(),
        compliant: true,
        admissionDecision: null
      });

      this.scannerStats.imagesScanned++;
      return { imageId, layers: layers.length, compliant: true };
    }

    /**
     * Validate image layers against policy
     * @param {string} imageId Image to validate
     * @param {number} requiredPosture Required layer posture
     * @returns {object} Validation result {valid, failedLayers}
     */
    validateLayers(imageId, requiredPosture) {
      const image = this.images.get(imageId);

      if (!image) {
        this.scannerStats.complianceFailures++;
        return { valid: false, error: 'Image not found' };
      }

      const failedLayers = image.layers.filter(l => l.posture < requiredPosture);
      const valid = failedLayers.length === 0;

      if (!valid) {
        this.scannerStats.complianceFailures++;
        image.compliant = false;
      }

      this.scannerStats.layersValidated += image.layers.length;
      return { valid, failedLayers: failedLayers.length, totalLayers: image.layers.length };
    }

    /**
     * Block non-compliant images
     * @param {string} imageId Image to evaluate
     * @param {number} requiredPosture Minimum required posture
     * @returns {object} Admission decision {allowed, imageId, reason}
     */
    blockNonCompliant(imageId, requiredPosture) {
      const image = this.images.get(imageId);

      if (!image) {
        return { allowed: false, reason: 'Image not found' };
      }

      const validation = this.validateLayers(imageId, requiredPosture);
      const allowed = validation.valid;

      if (!allowed) {
        this.scannerStats.imagesBlocked++;
      }

      image.admissionDecision = allowed ? 'APPROVED' : 'REJECTED';

      return {
        allowed,
        imageId,
        reason: allowed ? 'Image compliant' : `${validation.failedLayers} non-compliant layers`
      };
    }

    /**
     * Get scanner statistics
     * @returns {object} Current scanner stats
     */
    getScannerStats() {
      return {
        ...this.scannerStats,
        registeredImages: this.images.size
      };
    }

    onPostureTransition(priorLevel, currentLevel, delta) {
      // Re-scan images on posture transition
      this.images.forEach(image => {
        if (currentLevel < priorLevel) {
          image.layers.forEach(layer => {
            layer.posture = Math.min(layer.posture, currentLevel);
          });
        }
      });
    }

    getStats() {
      return this.getScannerStats();
    }
  }

  globalThis.StaamlD40 = { PostureLevel, D40Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
