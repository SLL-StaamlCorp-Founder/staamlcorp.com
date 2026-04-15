'use strict';

/**
 * StaamlCorp Temporal Security Derivative D33
 * Posture-Extended Cache Coherency Protocol (P-MESI)
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

  // =========== D33: Posture-Extended Cache Coherency Protocol (P-MESI) ===========
/**
   * D33: MESI protocol extended with posture states for CPU cache lines
   * Manages cache coherency with posture-aware state transitions
   */
  const CacheLineState = Object.freeze({
    MODIFIED: 'M',
    EXCLUSIVE: 'E',
    SHARED: 'S',
    INVALID: 'I'
  });

  class D33Engine {
    constructor() {
      this.cacheLines = new Map();
      this.stateTransitions = [];
      this.coherencyStats = {
        cacheLines: 0,
        stateChanges: 0,
        invalidations: 0,
        coherencyMisses: 0
      };
      this.id = generateId();
    }

    /**
     * Register cache line with posture tracking
     * @param {string} lineId Cache line identifier
     * @param {number} posture Posture level of cache line
     * @param {string} initialState Initial MESI state
     */
    registerCacheLine(lineId, posture, initialState) {
      this.cacheLines.set(lineId, {
        posture,
        state: initialState || CacheLineState.INVALID,
        registered: now(),
        accessCount: 0,
        lastAccess: now(),
        transitionHistory: []
      });
      this.coherencyStats.cacheLines++;
    }

    /**
     * Transition cache line state
     * @param {string} lineId Cache line identifier
     * @param {string} newState New MESI state
     * @param {number} currentPosture Current system posture
     * @returns {object} Transition result {success, priorState, newState}
     */
    transitionState(lineId, newState, currentPosture) {
      const line = this.cacheLines.get(lineId);
      if (!line) {
        return { success: false, error: 'Cache line not found' };
      }

      // Posture-aware state machine: lower posture restricts to INVALID or SHARED
      if (currentPosture < PostureLevel.BASELINE && newState === CacheLineState.MODIFIED) {
        return { success: false, error: 'Insufficient posture for MODIFIED state' };
      }

      const priorState = line.state;
      line.state = newState;
      line.accessCount++;
      line.lastAccess = now();
      line.transitionHistory.push({ from: priorState, to: newState, at: now() });

      this.stateTransitions.push({ lineId, from: priorState, to: newState, timestamp: now() });
      this.coherencyStats.stateChanges++;

      return { success: true, priorState, newState, lineId };
    }

    /**
     * Broadcast cache line invalidation
     * @param {string} lineId Cache line to invalidate
     * @returns {object} Invalidation result with affected lines
     */
    broadcastInvalidation(lineId) {
      const line = this.cacheLines.get(lineId);
      if (!line) {
        return { success: false, affected: 0 };
      }

      const priorState = line.state;
      line.state = CacheLineState.INVALID;
      this.coherencyStats.invalidations++;

      // In a real system, would invalidate related cache lines in other CPUs
      return {
        success: true,
        lineId,
        priorState,
        newState: CacheLineState.INVALID,
        affected: 1
      };
    }

    /**
     * Get coherency statistics
     * @returns {object} Current coherency stats
     */
    getCoherencyStats() {
      return {
        ...this.coherencyStats,
        recentTransitions: this.stateTransitions.slice(-10)
      };
    }

    onPostureTransition(priorLevel, currentLevel, delta) {
      // On posture downgrade, restrict cache line states
      if (currentLevel < priorLevel) {
        this.cacheLines.forEach((line, lineId) => {
          if (line.state === CacheLineState.MODIFIED) {
            this.transitionState(lineId, CacheLineState.SHARED, currentLevel);
          }
        });
      }
    }

    getStats() {
      return this.getCoherencyStats();
    }
  }

  globalThis.StaamlD33 = { PostureLevel, D33Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
