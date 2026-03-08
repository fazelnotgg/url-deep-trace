import { URLTracer } from './tracer.js';
import { RiskEngine } from './risk-engine.js';
import { PerformanceManager } from './performance-manager.js';
import { ReputationCache } from './reputation-cache.js';
import { ThreatIntelligence } from './threat-intelligence.js';
import { MLClassifier } from './ml-classifier.js';
import { WebhookNotifier } from './webhook-notifier.js';
import { RateLimiter } from './rate-limiter.js';
import { ReportingEngine } from './reporting-engine.js';

export class URLDeepTrace {
  constructor(options = {}) {
    this.tracer = new URLTracer({
      maxHops: options.maxHops || 20,
      timeout: options.timeout || 15000,
      userAgent: options.userAgent,
      enableDeepAnalysis: options.enableDeepAnalysis !== false,
      analysisDepth: options.analysisDepth || 'full'
    });
    
    this.riskEngine = new RiskEngine();
    
    this.performanceManager = new PerformanceManager({
      maxConcurrent: options.maxConcurrent || 5,
      retryAttempts: options.retryAttempts || 2,
      retryDelay: options.retryDelay || 1000
    });

    this.reputationCache = new ReputationCache({
      maxAge: options.cacheMaxAge || 3600000,
      maxSize: options.cacheMaxSize || 10000
    });

    this.threatIntelligence = new ThreatIntelligence();
    this.mlClassifier = new MLClassifier();
    
    this.webhookNotifier = new WebhookNotifier({
      webhooks: options.webhooks || [],
      enabled: options.enableWebhooks || false,
      onHighRisk: options.notifyOnHighRisk !== false,
      onMalicious: options.notifyOnMalicious !== false,
      minRiskScore: options.notifyMinRiskScore || 70
    });

    this.rateLimiter = new RateLimiter({
      maxRequestsPerWindow: options.maxRequestsPerWindow || 100,
      windowSizeMs: options.rateLimitWindow || 60000,
      maxConcurrent: options.maxConcurrent || 10
    });

    this.reportingEngine = new ReportingEngine();
    
    this.enableCache = options.enableCache !== false;
    this.enableThreatIntel = options.enableThreatIntel !== false;
    this.enableMLClassification = options.enableMLClassification !== false;
    this.enableRateLimit = options.enableRateLimit !== false;
  }

  async analyze(url) {
    const startTime = Date.now();

    try {
      if (!this._isValidUrl(url)) {
        throw new Error('Invalid URL format');
      }

      if (this.enableRateLimit) {
        const domain = new URL(url).hostname;
        const release = await this.rateLimiter.acquire(domain);
        
        try {
          return await this._performAnalysis(url, startTime);
        } catch (error) {
          return {
            success: false,
            url: url,
            error: error.message || 'Analysis failed',
            stack: error.stack,
            metadata: {
              analyzedAt: new Date().toISOString(),
              executionTime: Date.now() - startTime
            }
          };
        } finally {
          release();
        }
      } else {
        return await this._performAnalysis(url, startTime);
      }

    } catch (error) {
      console.error('Analysis Error:', error.message);
      console.error('Stack:', error.stack);
      return {
        success: false,
        url: url,
        error: error.message || 'Unknown error',
        stack: error.stack,
        metadata: {
          analyzedAt: new Date().toISOString(),
          executionTime: Date.now() - startTime
        }
      };
    }
  }

  async _performAnalysis(url, startTime) {
    if (this.enableCache) {
      const reputation = this.reputationCache.getReputation(url);
      
      if (reputation.status === 'blacklisted') {
        return {
          success: false,
          url: url,
          blocked: true,
          reason: 'URL is blacklisted',
          blacklistInfo: reputation.info,
          metadata: {
            analyzedAt: new Date().toISOString(),
            executionTime: Date.now() - startTime
          }
        };
      }

      if (reputation.status === 'whitelisted') {
        return {
          success: true,
          url: url,
          whitelisted: true,
          whitelistInfo: reputation.info,
          metadata: {
            analyzedAt: new Date().toISOString(),
            executionTime: Date.now() - startTime
          }
        };
      }

      if (reputation.status === 'cached') {
        return {
          ...reputation.data,
          cached: true,
          metadata: {
            ...reputation.data.metadata,
            cacheHit: true
          }
        };
      }
    }

    let traceResult;
    try {
      traceResult = await this.tracer.trace(url);
    } catch (error) {
      return {
        success: false,
        url: url,
        error: `Trace failed: ${error.message}`,
        metadata: {
          analyzedAt: new Date().toISOString(),
          executionTime: Date.now() - startTime
        }
      };
    }

    let riskAssessment;
    try {
      riskAssessment = this.riskEngine.analyze(traceResult);
    } catch (error) {
      riskAssessment = {
        score: 0,
        level: 'unknown',
        factors: [`Risk analysis failed: ${error.message}`],
        details: {}
      };
    }

    const result = {
      success: traceResult.success,
      url: url,
      finalDestination: traceResult.finalUrl,
      trace: {
        totalHops: traceResult.totalHops,
        chain: traceResult.chain,
        behavioral: traceResult.behavioral
      },
      security: {
        risk: riskAssessment
      },
      metadata: {
        analyzedAt: new Date().toISOString(),
        executionTime: Date.now() - startTime
      }
    };

    if (this.enableThreatIntel) {
      try {
        result.threat = this.threatIntelligence.analyze(traceResult.chain, result);
        result.threatReport = this.threatIntelligence.generateThreatReport(result.threat);
      } catch (error) {
        result.threat = {
          error: `Threat analysis failed: ${error.message}`
        };
      }
    }

    if (this.enableMLClassification) {
      try {
        result.mlClassification = this.mlClassifier.classify(result);
      } catch (error) {
        result.mlClassification = {
          error: `ML classification failed: ${error.message}`
        };
      }
    }

    if (this.enableCache && traceResult.success) {
      this.reputationCache.set(url, result);
    }

    try {
      await this.webhookNotifier.notify(result, 'analysis_complete');
    } catch (error) {
      // Webhook errors should not break the analysis
    }

    return result;
  }

  async analyzeMultiple(urls) {
    const results = await this.performanceManager.analyzeBatch(urls, this);

    await this.webhookNotifier.notifyBatch(results, 'batch_complete');

    return {
      total: urls.length,
      results: results,
      summary: this.performanceManager.generateReport(results)
    };
  }

  async analyzeMultipleParallel(urls, options = {}) {
    const batchSize = options.batchSize || 10;
    const allResults = [];

    for (let i = 0; i < urls.length; i += batchSize) {
      const batch = urls.slice(i, i + batchSize);
      const batchResults = await this.performanceManager.analyzeBatch(batch, this);
      allResults.push(...batchResults);
    }

    return {
      total: urls.length,
      results: allResults,
      summary: this.performanceManager.generateReport(allResults)
    };
  }

  exportResults(results, format = 'json', options = {}) {
    if (format === 'json') {
      return this.performanceManager.exportToJSON(results, options);
    } else if (format === 'csv') {
      return this.performanceManager.exportToCSV(results);
    } else {
      throw new Error(`Unsupported export format: ${format}`);
    }
  }

  addToBlacklist(url, reason) {
    this.reputationCache.addToBlacklist(url, reason);
  }

  addToWhitelist(url, reason) {
    this.reputationCache.addToWhitelist(url, reason);
  }

  bulkAddBlacklist(urls, reason) {
    this.reputationCache.bulkAddBlacklist(urls, reason);
  }

  bulkAddWhitelist(urls, reason) {
    this.reputationCache.bulkAddWhitelist(urls, reason);
  }

  importBlacklist(data) {
    this.reputationCache.importBlacklist(data);
  }

  importWhitelist(data) {
    this.reputationCache.importWhitelist(data);
  }

  exportBlacklist() {
    return this.reputationCache.exportBlacklist();
  }

  exportWhitelist() {
    return this.reputationCache.exportWhitelist();
  }

  getCacheStats() {
    return this.reputationCache.getStats();
  }

  clearCache() {
    this.reputationCache.clear();
  }

  pruneCache() {
    return this.reputationCache.pruneExpired();
  }

  trainClassifier(url, label) {
    if (this.enableMLClassification) {
      this.analyze(url).then(result => {
        const features = this.mlClassifier.extractFeatures(result);
        this.mlClassifier.addTrainingData(url, features, label);
      });
    }
  }

  exportMLModel() {
    return this.mlClassifier.exportModel();
  }

  importMLModel(modelData) {
    this.mlClassifier.importModel(modelData);
  }

  adjustMLWeights(adjustments) {
    this.mlClassifier.adjustWeights(adjustments);
  }

  getFeatureImportance() {
    return this.mlClassifier.getFeatureImportance();
  }

  generateReport(analysisResult, type = 'technical', options = {}) {
    return this.reportingEngine.generateReport(analysisResult, type, options);
  }

  generateBatchReport(batchResults, type = 'executive', options = {}) {
    return this.reportingEngine.generateBatchReport(batchResults, type, options);
  }

  addWebhook(url, options = {}) {
    this.webhookNotifier.addWebhook(url, options);
  }

  removeWebhook(url) {
    this.webhookNotifier.removeWebhook(url);
  }

  getWebhookStats() {
    return this.webhookNotifier.getStats();
  }

  setDomainRateLimit(domain, maxRequests, windowMs) {
    this.rateLimiter.setDomainLimit(domain, maxRequests, windowMs);
  }

  getRateLimitStats() {
    return this.rateLimiter.getStats();
  }

  getRemainingQuota(domain = 'global') {
    return this.rateLimiter.getRemainingQuota(domain);
  }

  _isValidUrl(urlString) {
    try {
      const url = new URL(urlString);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (error) {
      return false;
    }
  }

  _generateSummary(results) {
    const summary = {
      successful: 0,
      failed: 0,
      riskLevels: {
        minimal: 0,
        low: 0,
        medium: 0,
        high: 0,
        unknown: 0
      },
      avgHops: 0,
      avgExecutionTime: 0
    };

    let totalHops = 0;
    let totalTime = 0;

    for (const result of results) {
      if (result.success) {
        summary.successful++;
        totalHops += result.trace.totalHops;
        
        if (result.security.risk.level) {
          summary.riskLevels[result.security.risk.level]++;
        }
      } else {
        summary.failed++;
      }

      totalTime += result.metadata.executionTime;
    }

    if (summary.successful > 0) {
      summary.avgHops = Math.round((totalHops / summary.successful) * 100) / 100;
    }

    if (results.length > 0) {
      summary.avgExecutionTime = Math.round((totalTime / results.length) * 100) / 100;
    }

    return summary;
  }
}

export { URLTracer } from './tracer.js';
export { RiskEngine } from './risk-engine.js';
export { TLSInspector } from './tls-inspector.js';
export { LexicalAnalyzer } from './lexical-analyzer.js';
export { HTMLAnalyzer } from './html-analyzer.js';
export { DomainIntelligence } from './domain-intelligence.js';
export { HeaderFingerprint } from './header-fingerprint.js';
export { PerformanceManager } from './performance-manager.js';
export { ReputationCache } from './reputation-cache.js';
export { BehavioralAnalyzer } from './behavioral-analyzer.js';
export { ThreatIntelligence } from './threat-intelligence.js';
export { MLClassifier } from './ml-classifier.js';
export { WebhookNotifier } from './webhook-notifier.js';
export { RateLimiter } from './rate-limiter.js';
export { ReportingEngine } from './reporting-engine.js';

export default URLDeepTrace;