'use strict';

/**
 * StaamlCorp Temporal Security Derivative D51
 * Biometric/Contextual Posture Triggers
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

  // =========== D51: Biometric/Contextual Posture Triggers ===========
/**
   * D51Engine - Biometric and Contextual Posture Management
   * Biometric signals trigger posture changes
   */
  class D51Engine {
    constructor() {
      this.id = generateId();
      this.biometricRegistry = new Map();
      this.triggerHistory = [];
      this.postureEscalations = [];
      this.createdAt = now();
    }

    /**
     * Register a biometric sensor/signal
     * @param {string} biometricType - Type (face, fingerprint, iris, etc.)
     * @param {number} triggerPostureLevel - Posture level to trigger
     * @returns {object} Registration record
     */
    registerBiometric(biometricType, triggerPostureLevel) {
      const bioId = generateId();
      const bioRecord = {
        id: bioId,
        type: biometricType,
        triggerPostureLevel,
        registeredAt: now(),
        verificationCount: 0,
        failureCount: 0,
        isActive: true
      };

      this.biometricRegistry.set(bioId, bioRecord);
      return bioRecord;
    }

    /**
     * Evaluate biometric signal for trigger activation
     * @param {string} bioId - Biometric ID
     * @param {boolean} isVerified - Whether biometric verified successfully
     * @returns {object} Trigger evaluation result
     */
    evaluateTrigger(bioId, isVerified) {
      const bioRecord = this.biometricRegistry.get(bioId);
      if (!bioRecord) return null;

      if (isVerified) {
        bioRecord.verificationCount += 1;
      } else {
        bioRecord.failureCount += 1;
      }

      const shouldTrigger = isVerified && bioRecord.isActive;

      this.triggerHistory.push({
        bioId,
        timestamp: now(),
        type: bioRecord.type,
        isVerified,
        triggered: shouldTrigger,
        targetPosture: bioRecord.triggerPostureLevel
      });

      return {
        bioId,
        triggered: shouldTrigger,
        targetPostureLevel: shouldTrigger ? bioRecord.triggerPostureLevel : null
      };
    }

    /**
     * Escalate posture based on biometric evaluation
     * @param {string} bioId - Biometric ID
     * @param {number} currentPosture - Current posture level
     * @returns {number|null} New posture level or null if no change
     */
    escalatePosture(bioId, currentPosture) {
      const bioRecord = this.biometricRegistry.get(bioId);
      if (!bioRecord || !bioRecord.isActive) return null;

      const newPosture = Math.max(currentPosture, bioRecord.triggerPostureLevel);
      const escalated = newPosture > currentPosture;

      this.postureEscalations.push({
        bioId,
        timestamp: now(),
        bioType: bioRecord.type,
        priorPosture: currentPosture,
        newPosture,
        escalated
      });

      return escalated ? newPosture : null;
    }

    /**
     * Get biometric statistics
     * @returns {object} Engine statistics
     */
    getBiometricStats() {
      const activeBio = Array.from(this.biometricRegistry.values())
        .filter(b => b.isActive).length;
      const totalVerifications = Array.from(this.biometricRegistry.values())
        .reduce((sum, b) => sum + b.verificationCount, 0);

      return {
        engineId: this.id,
        registeredBiometrics: this.biometricRegistry.size,
        activeBiometrics: activeBio,
        inactiveBiometrics: this.biometricRegistry.size - activeBio,
        totalVerifications,
        totalFailures: Array.from(this.biometricRegistry.values())
          .reduce((sum, b) => sum + b.failureCount, 0),
        triggerEvents: this.triggerHistory.length,
        escalationEvents: this.postureEscalations.length,
        createdAt: this.createdAt,
        uptime: now() - this.createdAt
      };
    }

    onPostureTransition(priorLevel, currentLevel, delta) {
      this.triggerHistory.push({
        type: 'posture_transition',
        timestamp: now(),
        priorLevel,
        currentLevel,
        delta,
        activeBioCount: Array.from(this.biometricRegistry.values())
          .filter(b => b.isActive).length
      });
    }
  }

  globalThis.StaamlD51 = { PostureLevel, D51Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
