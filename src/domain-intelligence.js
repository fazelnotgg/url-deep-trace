import dns from 'dns';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);

export class DomainIntelligence {
  constructor(options = {}) {
    this.knownProviders = {
      cloudflare: ['1.1.1.1', '1.0.0.1'],
      google: ['8.8.8.8', '8.8.4.4'],
      awsNameservers: ['ns-', '.awsdns-']
    };

    this.suspiciousTLDs = [
      'xyz', 'top', 'work', 'click', 'link', 'download',
      'stream', 'loan', 'win', 'bid', 'gq', 'ml', 'ga',
      'cf', 'tk', 'pw'
    ];

    this.trustedTLDs = [
      'com', 'net', 'org', 'edu', 'gov', 'mil'
    ];
    
    this.dnsCache = new Map();
    this.dnsCacheTTL = options.dnsCacheTTL || 300000;
    this.dnsCacheMaxSize = options.dnsCacheMaxSize || 1000;
    this.dnsTimeout = options.dnsTimeout || 5000;
  }

  _getCacheKey(hostname, type) {
    return `${hostname}:${type}`;
  }

  _getCachedDNS(hostname, type) {
    const key = this._getCacheKey(hostname, type);
    const cached = this.dnsCache.get(key);
    
    if (!cached) return null;
    
    if (Date.now() - cached.timestamp > this.dnsCacheTTL) {
      this.dnsCache.delete(key);
      return null;
    }
    
    return cached.data;
  }

  _setCachedDNS(hostname, type, data) {
    if (this.dnsCache.size >= this.dnsCacheMaxSize) {
      const oldestKey = this.dnsCache.keys().next().value;
      this.dnsCache.delete(oldestKey);
    }
    
    const key = this._getCacheKey(hostname, type);
    this.dnsCache.set(key, {
      data: data,
      timestamp: Date.now()
    });
  }

  async _queryWithTimeout(hostname, resolver, type) {
    return Promise.race([
      resolver(hostname),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error(`DNS ${type} timeout`)), this.dnsTimeout)
      )
    ]);
  }

  async analyze(hostname) {
    const analysis = {
      hostname: hostname,
      tld: this._extractTLD(hostname),
      dnsRecords: await this._queryDNS(hostname),
      reputation: this._assessReputation(hostname),
      ageEstimate: this._estimateAge(hostname),
      structure: this._analyzeStructure(hostname),
      timestamp: new Date().toISOString()
    };

    analysis.riskScore = this._calculateDomainRisk(analysis);

    return analysis;
  }

  async _queryDNS(hostname) {
    const cachedRecords = this._getCachedDNS(hostname, 'all');
    if (cachedRecords) {
      return { ...cachedRecords, cached: true };
    }

    const records = {
      ipv4: [],
      ipv6: [],
      mx: [],
      txt: [],
      querySuccess: false,
      errors: [],
      hasMX: false,
      hasSPF: false,
      hasDMARC: false
    };

    const dnsQueries = [];
    
    dnsQueries.push(
      (async () => {
        try {
          records.ipv4 = await this._queryWithTimeout(hostname, resolve4, 'A');
          records.querySuccess = true;
        } catch (error) {
          records.errors.push(`IPv4: ${error.code || error.message}`);
        }
      })()
    );

    dnsQueries.push(
      (async () => {
        try {
          records.ipv6 = await this._queryWithTimeout(hostname, resolve6, 'AAAA');
        } catch (error) {
          records.errors.push(`IPv6: ${error.code || error.message}`);
        }
      })()
    );

    dnsQueries.push(
      (async () => {
        try {
          records.mx = await this._queryWithTimeout(hostname, resolveMx, 'MX');
          records.hasMX = records.mx.length > 0;
        } catch (error) {
          records.errors.push(`MX: ${error.code || error.message}`);
        }
      })()
    );

    dnsQueries.push(
      (async () => {
        try {
          const txtRecords = await this._queryWithTimeout(hostname, resolveTxt, 'TXT');
          records.txt = txtRecords.map(r => r.join(''));
          records.hasSPF = records.txt.some(r => r.toLowerCase().includes('v=spf1'));
        } catch (error) {
          records.errors.push(`TXT: ${error.code || error.message}`);
        }
      })()
    );

    await Promise.all(dnsQueries);

    try {
      const dmarcRecords = await this._queryWithTimeout(`_dmarc.${hostname}`, resolveTxt, 'DMARC');
      records.hasDMARC = dmarcRecords.some(r => r.join('').toLowerCase().includes('v=dmarc1'));
    } catch (error) {
    }

    this._setCachedDNS(hostname, 'all', records);

    return records;
  }

  _extractTLD(hostname) {
    const parts = hostname.split('.');
    return parts[parts.length - 1];
  }

  _assessReputation(hostname) {
    const tld = this._extractTLD(hostname);
    
    return {
      tld: tld,
      isSuspiciousTLD: this.suspiciousTLDs.includes(tld.toLowerCase()),
      isTrustedTLD: this.trustedTLDs.includes(tld.toLowerCase()),
      hasNumbers: /\d/.test(hostname),
      hasHyphens: hostname.includes('-'),
      numberCount: (hostname.match(/\d/g) || []).length,
      hyphenCount: (hostname.match(/-/g) || []).length,
      length: hostname.length
    };
  }

  _estimateAge(hostname) {
    const tld = this._extractTLD(hostname);
    const hasNumbers = /\d{4,}/.test(hostname);
    const isVeryShort = hostname.length < 10;
    
    let ageIndicator = 'unknown';
    const signals = [];

    if (this.trustedTLDs.includes(tld.toLowerCase()) && !hasNumbers && !isVeryShort) {
      ageIndicator = 'likely_mature';
      signals.push('trusted_tld');
    }

    if (this.suspiciousTLDs.includes(tld.toLowerCase())) {
      ageIndicator = 'likely_new';
      signals.push('suspicious_tld');
    }

    if (hasNumbers) {
      signals.push('contains_numbers');
    }

    if (hostname.length > 30) {
      ageIndicator = 'likely_new';
      signals.push('unusually_long');
    }

    return {
      indicator: ageIndicator,
      signals: signals
    };
  }

  _analyzeStructure(hostname) {
    const parts = hostname.split('.');
    const labels = parts.length;
    const subdomains = labels > 2 ? labels - 2 : 0;

    const hasWWW = hostname.startsWith('www.');
    const longestLabel = Math.max(...parts.map(p => p.length));
    const shortestLabel = Math.min(...parts.map(p => p.length));

    return {
      labels: labels,
      subdomains: subdomains,
      hasWWW: hasWWW,
      longestLabel: longestLabel,
      shortestLabel: shortestLabel,
      totalLength: hostname.length,
      averageLabelLength: Math.round(hostname.replace(/\./g, '').length / labels)
    };
  }

  _calculateDomainRisk(analysis) {
    let score = 0;

    if (analysis.reputation.isSuspiciousTLD) {
      score += 20;
    }

    if (!analysis.dnsRecords.querySuccess) {
      score += 25;
    }

    if (!analysis.dnsRecords.hasMX) {
      score += 10;
    }

    if (!analysis.dnsRecords.hasSPF && analysis.dnsRecords.hasMX) {
      score += 8;
    }

    if (!analysis.dnsRecords.hasDMARC && analysis.dnsRecords.hasMX) {
      score += 5;
    }

    if (analysis.reputation.numberCount > 5) {
      score += 10;
    }

    if (analysis.reputation.hyphenCount > 2) {
      score += 8;
    }

    if (analysis.structure.subdomains > 4) {
      score += 12;
    }

    if (analysis.structure.longestLabel > 25) {
      score += 10;
    }

    if (analysis.ageEstimate.indicator === 'likely_new') {
      score += 15;
    }

    if (analysis.structure.totalLength > 50) {
      score += 8;
    }

    return Math.min(score, 100);
  }
}