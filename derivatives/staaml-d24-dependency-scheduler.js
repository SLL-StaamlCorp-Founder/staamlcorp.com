'use strict';

/**
 * StaamlCorp Temporal Security Derivative D24
 * Dependency-Aware Validation Scheduler
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

class D24Engine {
    constructor() {
      this.dependencies = new Map();
      this.validationQueue = [];
      this.stats = { scheduled: 0, validated: 0, deadlocks: 0 };
    }

    /**
     * Add validation dependency
     * @param {string} validator
     * @param {Array<string>} dependsOn
     */
    addDependency(validator, dependsOn) {
      this.dependencies.set(validator, {
        validator,
        dependsOn,
        addedAt: now()
      });
    }

    /**
     * Schedule validation with topological sort
     * @returns {Array<string>}
     */
    scheduleValidation() {
      const sorted = [];
      const visited = new Set();
      const visiting = new Set();

      const visit = (node) => {
        if (visited.has(node)) return true;
        if (visiting.has(node)) return false; // Cycle detected

        visiting.add(node);
        const deps = this.dependencies.get(node);

        if (deps) {
          for (const dep of deps.dependsOn) {
            if (!visit(dep)) return false;
          }
        }

        visiting.delete(node);
        visited.add(node);
        sorted.push(node);
        return true;
      };

      for (const validator of this.dependencies.keys()) {
        if (!visited.has(validator)) {
          if (!visit(validator)) {
            this.stats.deadlocks++;
            return [];
          }
        }
      }

      this.validationQueue = sorted;
      this.stats.scheduled++;
      return sorted;
    }

    /**
     * Detect deadlock in dependency graph
     * @returns {boolean}
     */
    detectDeadlock() {
      const visited = new Set();
      const visiting = new Set();

      const hasCycle = (node) => {
        if (visited.has(node)) return false;
        if (visiting.has(node)) return true;

        visiting.add(node);
        const deps = this.dependencies.get(node);

        if (deps) {
          for (const dep of deps.dependsOn) {
            if (hasCycle(dep)) return true;
          }
        }

        visiting.delete(node);
        visited.add(node);
        return false;
      };

      for (const validator of this.dependencies.keys()) {
        if (!visited.has(validator)) {
          if (hasCycle(validator)) {
            this.stats.deadlocks++;
            return true;
          }
        }
      }
      return false;
    }

    /**
     * Get schedule statistics
     * @returns {Object}
     */
    getScheduleStats() {
      return {
        totalValidators: this.dependencies.size,
        queueLength: this.validationQueue.length,
        ...this.stats
      };
    }

    /**
     * Handle posture transition
     * @param {number} priorLevel
     * @param {number} currentLevel
     * @param {number} delta
     */
    onPostureTransition(priorLevel, currentLevel, delta) {
      this.scheduleValidation();
    }
  }

  globalThis.StaamlD24 = { PostureLevel, D24Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
