/**
 * StaamlCorp Agent Integration Layer
 * Provides ingress/egress to STAAML Corp autonomous AI agents
 * from the staamlcorp.com website.
 *
 * Agent Fleet:
 *   CIPO Agent       — Chief IP Officer (port 8090)
 *   Prosecution      — Patent prosecution (port 8091)
 *   Prior Art        — Prior art research (port 8092)
 *   CLO              — Chief Licensing Officer (port 8093)
 *   Valuation        — IP valuation (port 8094)
 *   Litigation       — IP enforcement (port 8095)
 *   Infringement     — Infringement detection (port 8096)
 *   Royalty          — Royalty tracking (port 8097)
 *   Standards        — Standards compliance (port 8098)
 *   Competitive Intel— Market intelligence (port 8099)
 *   Finance          — Financial tracking (port 8100)
 *   Evangelist       — Academic outreach (port 8101)
 *   Data Room        — Document management (port 8102)
 *   Ops Controller   — System operations (port 8103)
 *   Event Bus        — Inter-agent messaging (port 8104)
 */

window.StaamlAgents = (function() {
  'use strict';

  // Agent gateway configuration
  // In production, this points to the OpenClaw gateway which routes to agents
  const CONFIG = {
    gatewayUrl: window.STAAML_GATEWAY_URL || '',
    gatewayAuth: window.STAAML_GATEWAY_AUTH || '',
    timeout: 30000,
    retries: 2
  };

  // Agent registry with public-facing endpoints
  const AGENTS = {
    'cipo':             { port: 8090, name: 'CIPO Agent',              description: 'Chief IP Officer — portfolio oversight' },
    'prosecution':      { port: 8091, name: 'Prosecution Agent',       description: 'Patent prosecution management' },
    'prior-art':        { port: 8092, name: 'Prior Art Agent',         description: 'Prior art landscape surveillance' },
    'clo':              { port: 8093, name: 'CLO Agent',               description: 'Licensing pipeline management' },
    'valuation':        { port: 8094, name: 'Valuation Agent',         description: 'IP portfolio valuation' },
    'litigation':       { port: 8095, name: 'Litigation Agent',        description: 'IP enforcement support' },
    'infringement':     { port: 8096, name: 'Infringement Agent',      description: 'Infringement detection & monitoring' },
    'royalty':          { port: 8097, name: 'Royalty Agent',            description: 'Royalty tracking & audit' },
    'standards':        { port: 8098, name: 'Standards Agent',         description: 'Standards body monitoring' },
    'competitive-intel':{ port: 8099, name: 'Competitive Intel Agent', description: 'Market intelligence' },
    'finance':          { port: 8100, name: 'Finance Agent',           description: 'Financial operations' },
    'evangelist':       { port: 8101, name: 'Evangelist Agent',        description: 'Academic & media outreach' },
    'data-room':        { port: 8102, name: 'Data Room Agent',         description: 'Secure document management' },
    'ops-controller':   { port: 8103, name: 'Ops Controller Agent',    description: 'System health monitoring' },
    'event-bus':        { port: 8104, name: 'Event Bus',               description: 'Inter-agent messaging' }
  };

  // Public-facing API endpoints available to website visitors
  const PUBLIC_ENDPOINTS = {
    // Licensing inquiry — routes to CLO Agent
    submitLicensingInquiry: async function(data) {
      return await callAgent('clo', '/api/licensing/inquiry', {
        company: data.company,
        contact: data.contact,
        email: data.email,
        platform: data.platform,
        interestLevel: data.interestLevel,
        message: data.message,
        source: 'staamlcorp.com'
      });
    },

    // Risk assessment results — routes to Infringement Agent
    submitAssessmentResults: async function(data) {
      return await callAgent('infringement', '/api/assessment/intake', {
        riskScore: data.riskScore,
        riskLevel: data.riskLevel,
        platformTypes: data.platformTypes,
        contentTypes: data.contentTypes,
        cacheLocations: data.cacheLocations,
        currentMitigation: data.currentMitigation,
        timestamp: new Date().toISOString(),
        source: 'staamlcorp.com/assessment'
      });
    },

    // Newsletter signup — routes to Evangelist Agent
    subscribeNewsletter: async function(email) {
      return await callAgent('evangelist', '/api/outreach/subscribe', {
        email: email,
        source: 'staamlcorp.com',
        interests: ['research', 'licensing', 'patent-updates']
      });
    },

    // Contact form — routes to CIPO Agent for triage
    submitContactForm: async function(data) {
      return await callAgent('cipo', '/api/contact/intake', {
        firstName: data.firstName,
        lastName: data.lastName,
        email: data.email,
        company: data.company,
        subject: data.subject,
        message: data.message,
        source: 'staamlcorp.com/contact',
        timestamp: new Date().toISOString()
      });
    },

    // Agent fleet status — routes to Ops Controller
    getAgentStatus: async function() {
      return await callAgent('ops-controller', '/api/health/fleet', {});
    },

    // Patent status — routes to Prosecution Agent
    getPatentStatus: async function() {
      return await callAgent('prosecution', '/api/status/patent', {
        applicationNumber: '19/640,793',
        docket: 'SLL-2025-001'
      });
    }
  };

  /**
   * Call an agent endpoint through the OpenClaw gateway
   */
  async function callAgent(agentId, endpoint, payload) {
    const agent = AGENTS[agentId];
    if (!agent) {
      return { success: false, error: 'Unknown agent: ' + agentId };
    }

    // If no gateway configured, queue for later processing
    if (!CONFIG.gatewayUrl) {
      return queueOfflineRequest(agentId, endpoint, payload);
    }

    const url = CONFIG.gatewayUrl + '/route/' + agentId + endpoint;

    for (let attempt = 0; attempt <= CONFIG.retries; attempt++) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-StaamlCorp-Source': 'website',
            'X-StaamlCorp-Agent': agentId,
            ...(CONFIG.gatewayAuth ? { 'Authorization': 'Bearer ' + CONFIG.gatewayAuth } : {})
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(CONFIG.timeout)
        });

        if (!response.ok) {
          throw new Error('Agent returned ' + response.status);
        }

        return await response.json();
      } catch (err) {
        if (attempt === CONFIG.retries) {
          console.warn('[StaamlAgents] Agent ' + agentId + ' unreachable after ' + (CONFIG.retries + 1) + ' attempts');
          return queueOfflineRequest(agentId, endpoint, payload);
        }
        // Exponential backoff
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
      }
    }
  }

  /**
   * Queue request for processing when agents come online
   * Stores in localStorage for later retrieval
   */
  function queueOfflineRequest(agentId, endpoint, payload) {
    const queue = JSON.parse(localStorage.getItem('staaml_agent_queue') || '[]');
    const entry = {
      id: 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
      agentId: agentId,
      endpoint: endpoint,
      payload: payload,
      timestamp: new Date().toISOString(),
      status: 'queued'
    };
    queue.push(entry);
    localStorage.setItem('staaml_agent_queue', JSON.stringify(queue));

    return {
      success: true,
      queued: true,
      requestId: entry.id,
      message: 'Request queued. Our team will process this within one business day.'
    };
  }

  /**
   * Process any queued requests (called when gateway becomes available)
   */
  async function processQueue() {
    const queue = JSON.parse(localStorage.getItem('staaml_agent_queue') || '[]');
    const pending = queue.filter(q => q.status === 'queued');

    for (const entry of pending) {
      const result = await callAgent(entry.agentId, entry.endpoint, entry.payload);
      if (result.success && !result.queued) {
        entry.status = 'sent';
      }
    }

    localStorage.setItem('staaml_agent_queue', JSON.stringify(queue));
  }

  // Public API
  return {
    config: CONFIG,
    agents: AGENTS,
    api: PUBLIC_ENDPOINTS,
    callAgent: callAgent,
    processQueue: processQueue,

    // Convenience: check if agents are reachable
    isOnline: async function() {
      if (!CONFIG.gatewayUrl) return false;
      try {
        const r = await fetch(CONFIG.gatewayUrl + '/health', {
          signal: AbortSignal.timeout(5000)
        });
        return r.ok;
      } catch {
        return false;
      }
    }
  };
})();
