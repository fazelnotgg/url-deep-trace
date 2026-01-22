export class RateLimiter {
  constructor(options = {}) {
    this.maxRequestsPerWindow = options.maxRequestsPerWindow || 100;
    this.windowSizeMs = options.windowSizeMs || 60000;
    this.maxConcurrent = options.maxConcurrent || 10;
    
    this.requestLog = [];
    this.activeRequests = 0;
    this.waitingQueue = [];
    
    this.stats = {
      totalRequests: 0,
      blocked: 0,
      queued: 0,
      successful: 0
    };

    this.perDomainLimits = new Map();
    this.domainRequestLogs = new Map();
  }

  async acquire(domain = 'global') {
    this.stats.totalRequests++;

    if (this.activeRequests >= this.maxConcurrent) {
      this.stats.queued++;
      await this._waitForSlot();
    }

    if (!this._canMakeRequest(domain)) {
      this.stats.blocked++;
      const waitTime = this._getWaitTime(domain);
      await this._delay(waitTime);
    }

    this.activeRequests++;
    this._logRequest(domain);
    this.stats.successful++;

    return () => this.release();
  }

  release() {
    this.activeRequests--;
    
    if (this.waitingQueue.length > 0) {
      const resolver = this.waitingQueue.shift();
      resolver();
    }
  }

  _canMakeRequest(domain) {
    this._cleanOldRequests(domain);

    const globalCount = this.requestLog.length;
    if (globalCount >= this.maxRequestsPerWindow) {
      return false;
    }

    if (domain !== 'global' && this.perDomainLimits.has(domain)) {
      const limit = this.perDomainLimits.get(domain);
      const domainLog = this.domainRequestLogs.get(domain) || [];
      
      if (domainLog.length >= limit.maxRequests) {
        return false;
      }
    }

    return true;
  }

  _logRequest(domain) {
    const now = Date.now();
    
    this.requestLog.push(now);
    
    if (domain !== 'global') {
      if (!this.domainRequestLogs.has(domain)) {
        this.domainRequestLogs.set(domain, []);
      }
      this.domainRequestLogs.get(domain).push(now);
    }
  }

  _cleanOldRequests(domain) {
    const cutoff = Date.now() - this.windowSizeMs;
    
    this.requestLog = this.requestLog.filter(timestamp => timestamp > cutoff);
    
    if (domain !== 'global' && this.domainRequestLogs.has(domain)) {
      const domainLog = this.domainRequestLogs.get(domain);
      this.domainRequestLogs.set(
        domain,
        domainLog.filter(timestamp => timestamp > cutoff)
      );
    }
  }

  _getWaitTime(domain) {
    if (this.requestLog.length === 0) {
      return 0;
    }

    const oldestRequest = Math.min(...this.requestLog);
    const timeUntilExpiry = (oldestRequest + this.windowSizeMs) - Date.now();
    
    return Math.max(0, timeUntilExpiry);
  }

  _waitForSlot() {
    return new Promise(resolve => {
      this.waitingQueue.push(resolve);
    });
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  setDomainLimit(domain, maxRequests, windowMs) {
    this.perDomainLimits.set(domain, {
      maxRequests: maxRequests,
      windowMs: windowMs || this.windowSizeMs
    });
  }

  removeDomainLimit(domain) {
    this.perDomainLimits.delete(domain);
    this.domainRequestLogs.delete(domain);
  }

  getRemainingQuota(domain = 'global') {
    this._cleanOldRequests(domain);

    if (domain === 'global') {
      return Math.max(0, this.maxRequestsPerWindow - this.requestLog.length);
    }

    if (this.perDomainLimits.has(domain)) {
      const limit = this.perDomainLimits.get(domain);
      const domainLog = this.domainRequestLogs.get(domain) || [];
      return Math.max(0, limit.maxRequests - domainLog.length);
    }

    return this.maxRequestsPerWindow;
  }

  getStats() {
    return {
      ...this.stats,
      activeRequests: this.activeRequests,
      queueLength: this.waitingQueue.length,
      currentWindowRequests: this.requestLog.length,
      remainingQuota: this.getRemainingQuota(),
      utilizationRate: this.maxRequestsPerWindow > 0
        ? Math.round((this.requestLog.length / this.maxRequestsPerWindow) * 100)
        : 0
    };
  }

  reset() {
    this.requestLog = [];
    this.domainRequestLogs.clear();
    this.stats = {
      totalRequests: 0,
      blocked: 0,
      queued: 0,
      successful: 0
    };
  }

  async executeWithLimit(fn, domain = 'global') {
    const release = await this.acquire(domain);
    
    try {
      const result = await fn();
      return result;
    } finally {
      release();
    }
  }
}