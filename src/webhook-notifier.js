import axios from 'axios';

export class WebhookNotifier {
  constructor(options = {}) {
    this.webhooks = options.webhooks || [];
    this.enabled = options.enabled !== false;
    this.retryAttempts = options.retryAttempts || 3;
    this.retryDelay = options.retryDelay || 1000;
    this.timeout = options.timeout || 5000;
    
    this.triggerConditions = {
      onHighRisk: options.onHighRisk !== false,
      onMalicious: options.onMalicious !== false,
      onPhishing: options.onPhishing !== false,
      onMalware: options.onMalware !== false,
      onError: options.onError || false,
      minRiskScore: options.minRiskScore || 70
    };

    this.notificationQueue = [];
    this.stats = {
      sent: 0,
      failed: 0,
      retries: 0
    };
  }

  async notify(analysisResult, eventType = 'analysis_complete') {
    if (!this.enabled || this.webhooks.length === 0) {
      return { sent: false, reason: 'Notifications disabled or no webhooks configured' };
    }

    if (!this._shouldNotify(analysisResult, eventType)) {
      return { sent: false, reason: 'Trigger conditions not met' };
    }

    const payload = this._buildPayload(analysisResult, eventType);
    const results = [];

    for (const webhook of this.webhooks) {
      const result = await this._sendWebhook(webhook, payload);
      results.push(result);
    }

    return {
      sent: true,
      results: results,
      payload: payload
    };
  }

  async notifyBatch(analysisResults, eventType = 'batch_complete') {
    if (!this.enabled || this.webhooks.length === 0) {
      return { sent: false, reason: 'Notifications disabled or no webhooks configured' };
    }

    const highRiskResults = analysisResults.filter(r => 
      r.security?.risk?.score >= this.triggerConditions.minRiskScore
    );

    if (highRiskResults.length === 0 && !this.triggerConditions.onError) {
      return { sent: false, reason: 'No high-risk results to notify' };
    }

    const payload = {
      eventType: eventType,
      timestamp: new Date().toISOString(),
      summary: {
        total: analysisResults.length,
        highRisk: highRiskResults.length,
        topThreats: highRiskResults.slice(0, 5).map(r => ({
          url: r.url,
          riskScore: r.security?.risk?.score,
          riskLevel: r.security?.risk?.level,
          classification: r.mlClassification?.classification
        }))
      },
      results: highRiskResults
    };

    const results = [];
    for (const webhook of this.webhooks) {
      const result = await this._sendWebhook(webhook, payload);
      results.push(result);
    }

    return {
      sent: true,
      results: results,
      payload: payload
    };
  }

  _shouldNotify(result, eventType) {
    if (eventType === 'error' && this.triggerConditions.onError) {
      return true;
    }

    if (!result.success) {
      return this.triggerConditions.onError;
    }

    const riskScore = result.security?.risk?.score || 0;
    const riskLevel = result.security?.risk?.level;
    const classification = result.mlClassification?.classification;

    if (this.triggerConditions.onHighRisk && riskScore >= this.triggerConditions.minRiskScore) {
      return true;
    }

    if (this.triggerConditions.onMalicious && (classification === 'malicious' || riskLevel === 'high')) {
      return true;
    }

    if (this.triggerConditions.onPhishing && result.threat?.phishingIndicators?.detected) {
      return true;
    }

    if (this.triggerConditions.onMalware && result.threat?.malwareRisk?.risk > 50) {
      return true;
    }

    return false;
  }

  _buildPayload(result, eventType) {
    return {
      eventType: eventType,
      timestamp: new Date().toISOString(),
      url: result.url,
      finalDestination: result.finalDestination,
      security: {
        riskScore: result.security?.risk?.score,
        riskLevel: result.security?.risk?.level,
        factors: result.security?.risk?.factors
      },
      classification: result.mlClassification ? {
        type: result.mlClassification.classification,
        confidence: result.mlClassification.confidence,
        explanation: result.mlClassification.explanation
      } : null,
      threat: result.threat ? {
        level: result.threat.threatLevel?.level,
        score: result.threat.threatLevel?.score,
        phishing: result.threat.phishingIndicators?.detected,
        malware: result.threat.malwareRisk?.risk > 50
      } : null,
      trace: {
        totalHops: result.trace?.totalHops,
        protocolDowngrade: result.security?.risk?.details?.protocolDowngrade
      },
      metadata: result.metadata
    };
  }

  async _sendWebhook(webhook, payload, attempt = 1) {
    try {
      const response = await axios({
        method: webhook.method || 'POST',
        url: webhook.url,
        data: payload,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'URLDeepTrace-Webhook/1.0',
          ...(webhook.headers || {})
        },
        timeout: this.timeout
      });

      this.stats.sent++;

      return {
        webhook: webhook.url,
        success: true,
        statusCode: response.status,
        attempt: attempt
      };

    } catch (error) {
      if (attempt < this.retryAttempts) {
        this.stats.retries++;
        await this._delay(this.retryDelay * attempt);
        return this._sendWebhook(webhook, payload, attempt + 1);
      }

      this.stats.failed++;

      return {
        webhook: webhook.url,
        success: false,
        error: error.message,
        attempt: attempt
      };
    }
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  addWebhook(url, options = {}) {
    this.webhooks.push({
      url: url,
      method: options.method || 'POST',
      headers: options.headers || {}
    });
  }

  removeWebhook(url) {
    this.webhooks = this.webhooks.filter(w => w.url !== url);
  }

  clearWebhooks() {
    this.webhooks = [];
  }

  getStats() {
    return {
      ...this.stats,
      webhookCount: this.webhooks.length,
      successRate: this.stats.sent > 0 
        ? Math.round((this.stats.sent / (this.stats.sent + this.stats.failed)) * 100)
        : 0
    };
  }

  resetStats() {
    this.stats = {
      sent: 0,
      failed: 0,
      retries: 0
    };
  }
}