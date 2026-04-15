'use strict';

/**
 * StaamlCorp Temporal Security Derivative D18
 * Message Queue Posture Bridge
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

class D18Engine {
    constructor() {
      this.queue = [];
      this.quarantine = [];
      this.stats = { published: 0, consumed: 0, quarantined: 0 };
      this.postureLevel = PostureLevel.PROVISIONAL;
    }

    /**
     * Publish message with posture metadata
     * @param {string} topic
     * @param {*} payload
     * @returns {Object}
     */
    publishWithPosture(topic, payload) {
      const message = {
        id: generateId(),
        topic,
        payload,
        postureEpoch: this.postureLevel,
        publishedAt: now()
      };
      this.queue.push(message);
      this.stats.published++;
      return message;
    }

    /**
     * Consume message with posture validation
     * @returns {*}
     */
    consumeWithValidation() {
      while (this.queue.length > 0) {
        const message = this.queue.shift();
        const age = now() - message.publishedAt;
        const isStale = age > 3600000 || message.postureEpoch < this.postureLevel - 1;

        if (isStale) {
          this.quarantine.push(message);
          this.stats.quarantined++;
        } else {
          this.stats.consumed++;
          return message;
        }
      }
      return null;
    }

    /**
     * Quarantine stale messages
     * @returns {number} Count quarantined
     */
    quarantineStale() {
      let count = 0;
      const temp = [];
      for (const msg of this.queue) {
        const age = now() - msg.publishedAt;
        if (age > 3600000) {
          this.quarantine.push(msg);
          count++;
          this.stats.quarantined++;
        } else {
          temp.push(msg);
        }
      }
      this.queue = temp;
      return count;
    }

    /**
     * Get queue statistics
     * @returns {Object}
     */
    getQueueStats() {
      return {
        queueLength: this.queue.length,
        quarantineLength: this.quarantine.length,
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
      this.postureLevel = currentLevel;
      if (delta < 0) this.quarantineStale();
    }
  }

  globalThis.StaamlD18 = { PostureLevel, D18Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
