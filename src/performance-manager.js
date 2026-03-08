export class PerformanceManager {
  constructor(options = {}) {
    this.maxConcurrent = options.maxConcurrent || 5;
    this.retryAttempts = options.retryAttempts || 2;
    this.retryDelay = options.retryDelay || 1000;
    this.progressCallback = options.onProgress || null;
  }

  async analyzeBatch(urls, analyzer) {
    const results = new Array(urls.length);
    const semaphore = { count: 0, queue: [] };
    
    const processUrl = async (url, index) => {
      while (semaphore.count >= this.maxConcurrent) {
        await new Promise(resolve => semaphore.queue.push(resolve));
      }
      
      semaphore.count++;
      
      try {
        const result = await this._analyzeWithRetry(url, analyzer);
        results[index] = result;
        return result;
      } finally {
        semaphore.count--;
        if (semaphore.queue.length > 0) {
          const next = semaphore.queue.shift();
          next();
        }
        
        if (this.progressCallback) {
          this.progressCallback({ completed: index + 1, total: urls.length });
        }
      }
    };

    const promises = urls.map((url, index) => processUrl(url, index));
    await Promise.allSettled(promises);

    return results.filter(r => r !== undefined);
  }

  async analyzeBatchParallel(urls, analyzer, options = {}) {
    const batchSize = options.batchSize || this.maxConcurrent;
    const results = [];
    const useRetry = options.retry !== false;
    
    for (let i = 0; i < urls.length; i += batchSize) {
      const batch = urls.slice(i, i + batchSize);
      
      const batchPromises = batch.map((url, index) => 
        (async () => {
          try {
            return useRetry 
              ? await this._analyzeWithRetry(url, analyzer)
              : await analyzer.analyze(url);
          } catch (error) {
            return {
              success: false,
              url: url,
              error: error.message,
              metadata: {
                analyzedAt: new Date().toISOString()
              }
            };
          }
        })()
      );
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      if (this.progressCallback) {
        this.progressCallback({ 
          completed: Math.min(i + batchSize, urls.length), 
          total: urls.length,
          batch: Math.ceil((i + batchSize) / batchSize)
        });
      }
    }

    return results;
  }

  async _analyzeWithRetry(url, analyzer, attempt = 1) {
    try {
      return await analyzer.analyze(url);
    } catch (error) {
      if (attempt < this.retryAttempts) {
        await this._delay(this.retryDelay * attempt);
        return this._analyzeWithRetry(url, analyzer, attempt + 1);
      }
      throw error;
    }
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  generateReport(results) {
    const summary = {
      total: results.length,
      successful: 0,
      failed: 0,
      riskDistribution: {
        minimal: 0,
        low: 0,
        medium: 0,
        high: 0,
        unknown: 0
      },
      performance: {
        avgExecutionTime: 0,
        minExecutionTime: Infinity,
        maxExecutionTime: 0,
        totalExecutionTime: 0
      },
      redirects: {
        avgHops: 0,
        maxHops: 0,
        totalHops: 0
      },
      security: {
        protocolDowngrades: 0,
        certIssues: 0,
        suspiciousDomains: 0
      }
    };

    let totalTime = 0;
    let totalHops = 0;

    for (const result of results) {
      if (result.success) {
        summary.successful++;

        if (result.security?.risk?.level) {
          summary.riskDistribution[result.security.risk.level]++;
        }

        if (result.trace?.totalHops) {
          totalHops += result.trace.totalHops;
          summary.redirects.maxHops = Math.max(summary.redirects.maxHops, result.trace.totalHops);
        }

        if (result.security?.risk?.details?.protocolDowngrade) {
          summary.security.protocolDowngrades++;
        }

        if (result.security?.risk?.details?.certificateIssues) {
          const certIssues = result.security.risk.details.certificateIssues;
          if (certIssues.expired > 0 || certIssues.expiringSoon > 0 || certIssues.invalid > 0) {
            summary.security.certIssues++;
          }
        }

        if (result.security?.risk?.details?.suspiciousDomains?.length > 0) {
          summary.security.suspiciousDomains++;
        }
      } else {
        summary.failed++;
      }

      if (result.metadata?.executionTime) {
        const execTime = result.metadata.executionTime;
        totalTime += execTime;
        summary.performance.minExecutionTime = Math.min(summary.performance.minExecutionTime, execTime);
        summary.performance.maxExecutionTime = Math.max(summary.performance.maxExecutionTime, execTime);
      }
    }

    if (summary.successful > 0) {
      summary.redirects.avgHops = Math.round((totalHops / summary.successful) * 100) / 100;
    }

    if (results.length > 0) {
      summary.performance.avgExecutionTime = Math.round((totalTime / results.length) * 100) / 100;
      summary.performance.totalExecutionTime = totalTime;
    }

    if (summary.performance.minExecutionTime === Infinity) {
      summary.performance.minExecutionTime = 0;
    }

    return summary;
  }

  exportToJSON(results, options = {}) {
    const data = {
      metadata: {
        exportedAt: new Date().toISOString(),
        totalURLs: results.length,
        version: '1.0.0'
      },
      summary: this.generateReport(results),
      results: results
    };

    if (options.includeRawData === false) {
      data.results = results.map(r => ({
        url: r.url,
        success: r.success,
        finalDestination: r.finalDestination,
        riskLevel: r.security?.risk?.level,
        riskScore: r.security?.risk?.score,
        totalHops: r.trace?.totalHops
      }));
    }

    return JSON.stringify(data, null, options.pretty ? 2 : 0);
  }

  exportToCSV(results) {
    const headers = [
      'URL',
      'Success',
      'Final Destination',
      'Risk Level',
      'Risk Score',
      'Total Hops',
      'Execution Time (ms)',
      'Protocol Downgrade',
      'Certificate Issues',
      'Analyzed At'
    ];

    const rows = [headers];

    for (const result of results) {
      const row = [
        result.url || '',
        result.success ? 'true' : 'false',
        result.finalDestination || '',
        result.security?.risk?.level || '',
        result.security?.risk?.score || '0',
        result.trace?.totalHops || '0',
        result.metadata?.executionTime || '0',
        result.security?.risk?.details?.protocolDowngrade ? 'true' : 'false',
        this._hasCertIssues(result) ? 'true' : 'false',
        result.metadata?.analyzedAt || ''
      ];

      rows.push(row);
    }

    return rows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
  }

  _hasCertIssues(result) {
    const certIssues = result.security?.risk?.details?.certificateIssues;
    if (!certIssues) return false;
    return certIssues.expired > 0 || certIssues.expiringSoon > 0 || certIssues.invalid > 0;
  }
}