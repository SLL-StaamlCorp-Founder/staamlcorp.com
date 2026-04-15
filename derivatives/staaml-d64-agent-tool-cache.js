'use strict';

/**
 * StaamlCorp Temporal Security Derivative D64
 * AI Agent Tool and Credential Cache Posture Controller
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

  // =========== D64: AI Agent Tool and Credential Cache Posture Controller ===========
/**
   * D64Engine: LangChain/CrewAI/MCP tool registrations and credential validation
   */
  class D64Engine {
    constructor() {
      this.agents = new Map();
      this.toolCache = new Map();
      this.credentials = new Map();
      this.stats = {
        agentsRegistered: 0,
        toolsValidated: 0,
        credentialsInvalidated: 0,
        cacheHits: 0
      };
    }

    /**
     * Register an AI agent with tools
     */
    registerAgent(agentId, name, tools = []) {
      this.agents.set(agentId, {
        id: agentId,
        name,
        tools,
        registeredAt: now(),
        postureLevel: PostureLevel.UNTRUSTED
      });
      this.stats.agentsRegistered++;
      return agentId;
    }

    /**
     * Validate tool cache against current posture
     */
    validateToolCache(agentId, currentPostureLevel) {
      const agent = this.agents.get(agentId);
      if (!agent) return null;

      const validation = {
        agentId,
        validated: true,
        tools: [],
        timestamp: now()
      };

      agent.tools.forEach(tool => {
        const minLevel = tool.minPostureLevel || PostureLevel.TRUSTED;
        const allowed = currentPostureLevel >= minLevel;

        if (allowed) {
          this.stats.cacheHits++;
        }

        validation.tools.push({
          name: tool.name,
          allowed,
          minRequired: minLevel
        });
      });

      this.toolCache.set(agentId, validation);
      this.stats.toolsValidated++;
      return validation;
    }

    /**
     * Invalidate credentials on posture downgrade
     */
    invalidateCredentials(agentId, credentialIds = []) {
      const credentials = this.credentials.get(agentId) || [];
      const invalidated = [];

      credentialIds.forEach(credId => {
        const cred = credentials.find(c => c.id === credId);
        if (cred) {
          cred.valid = false;
          cred.invalidatedAt = now();
          invalidated.push(credId);
          this.stats.credentialsInvalidated++;
        }
      });

      return {
        agentId,
        invalidatedCount: invalidated.length,
        invalidated
      };
    }

    /**
     * Get agent statistics
     */
    getAgentStats() {
      return {
        ...this.stats,
        registeredAgents: this.agents.size,
        cachedValidations: this.toolCache.size
      };
    }

    /**
     * Handle posture transitions
     */
    onPostureTransition(priorLevel, currentLevel, delta) {
      const transitionResults = [];

      if (currentLevel < priorLevel) {
        // Posture downgrade
        this.agents.forEach((agent, agentId) => {
          const validation = this.validateToolCache(agentId, currentLevel);
          const invalidCreds = agent.tools
            .filter(t => currentLevel < (t.minPostureLevel || PostureLevel.TRUSTED))
            .map(t => t.id || generateId());

          if (invalidCreds.length > 0) {
            this.invalidateCredentials(agentId, invalidCreds);
            transitionResults.push({ agentId, action: 'invalidate' });
          }
        });
      }

      return { transitionResults };
    }

    /**
     * Get comprehensive statistics
     */
    getStats() {
      return this.getAgentStats();
    }
  }

  globalThis.StaamlD64 = { PostureLevel, D64Engine };

})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
