export class BehavioralAnalyzer {
  constructor() {
    this.redirectPatterns = {
      bounceChain: [],
      temporalPatterns: [],
      geographicPatterns: []
    };

    this.suspiciousBehaviors = {
      rapidRedirects: 3,
      crossDomainThreshold: 4,
      protocolSwitchThreshold: 2,
      cookieManipulationThreshold: 5
    };
  }

  analyze(chain) {
    return {
      redirectBehavior: this._analyzeRedirectBehavior(chain),
      domainHopping: this._analyzeDomainHopping(chain),
      protocolBehavior: this._analyzeProtocolBehavior(chain),
      cookieBehavior: this._analyzeCookieBehavior(chain),
      timingAnalysis: this._analyzeTimingPatterns(chain),
      contentEvolution: this._analyzeContentEvolution(chain),
      trustChainAnalysis: this._analyzeTrustChain(chain),
      cloakingDetection: this._detectCloaking(chain),
      behavioralScore: 0
    };
  }

  _analyzeRedirectBehavior(chain) {
    const redirects = chain.filter(hop => hop.type === 'redirect');
    
    if (redirects.length === 0) {
      return {
        pattern: 'direct',
        complexity: 0,
        suspicious: false
      };
    }

    const types = redirects.map(r => r.redirectType);
    const uniqueTypes = new Set(types);

    const hasMetaRefresh = types.includes('meta-refresh');
    const hasJavaScript = types.includes('javascript');
    const hasHTTP = types.includes('http');

    let pattern = 'simple';
    let complexity = redirects.length;

    if (uniqueTypes.size > 2) {
      pattern = 'complex_mixed';
      complexity += 10;
    } else if (hasMetaRefresh && hasJavaScript) {
      pattern = 'obfuscated';
      complexity += 15;
    } else if (redirects.length > 5) {
      pattern = 'chain';
      complexity += 8;
    }

    const rapidRedirects = this._detectRapidRedirects(redirects);
    if (rapidRedirects) {
      complexity += 12;
    }

    return {
      pattern: pattern,
      complexity: complexity,
      redirectCount: redirects.length,
      typeDistribution: Object.fromEntries(uniqueTypes),
      hasMetaRefresh: hasMetaRefresh,
      hasJavaScript: hasJavaScript,
      rapidRedirects: rapidRedirects,
      suspicious: complexity > 15 || rapidRedirects
    };
  }

  _analyzeDomainHopping(chain) {
    const domains = [];
    const domainTransitions = [];

    for (const hop of chain) {
      if (hop.url) {
        try {
          const url = new URL(hop.url);
          domains.push(url.hostname);
        } catch (e) {
          continue;
        }
      }
    }

    const uniqueDomains = new Set(domains);
    
    for (let i = 0; i < domains.length - 1; i++) {
      if (domains[i] !== domains[i + 1]) {
        domainTransitions.push({
          from: domains[i],
          to: domains[i + 1],
          index: i
        });
      }
    }

    const tldChanges = this._analyzeTLDChanges(domains);
    const registrarChanges = this._estimateRegistrarChanges(domains);

    return {
      uniqueDomains: uniqueDomains.size,
      totalHops: domains.length,
      domainTransitions: domainTransitions.length,
      transitions: domainTransitions,
      tldChanges: tldChanges,
      registrarChanges: registrarChanges,
      dominanceRatio: domains.length > 0 
        ? Math.round((1 - (uniqueDomains.size / domains.length)) * 100) 
        : 0,
      isSuspicious: uniqueDomains.size > this.suspiciousBehaviors.crossDomainThreshold
    };
  }

  _analyzeProtocolBehavior(chain) {
    const protocols = [];
    const switches = [];

    for (const hop of chain) {
      if (hop.protocol) {
        protocols.push(hop.protocol);
      }
    }

    for (let i = 0; i < protocols.length - 1; i++) {
      if (protocols[i] !== protocols[i + 1]) {
        switches.push({
          from: protocols[i],
          to: protocols[i + 1],
          index: i,
          isDowngrade: protocols[i] === 'https' && protocols[i + 1] === 'http'
        });
      }
    }

    const downgrades = switches.filter(s => s.isDowngrade).length;
    const upgrades = switches.filter(s => 
      s.from === 'http' && s.to === 'https'
    ).length;

    return {
      protocolSwitches: switches.length,
      downgrades: downgrades,
      upgrades: upgrades,
      switches: switches,
      finalProtocol: protocols[protocols.length - 1],
      isSuspicious: downgrades > 0 || switches.length > this.suspiciousBehaviors.protocolSwitchThreshold
    };
  }

  _analyzeCookieBehavior(chain) {
    let totalCookiesSet = 0;
    let secureCookies = 0;
    let insecureCookies = 0;
    const cookieOperations = [];

    for (const hop of chain) {
      if (hop.headers && hop.headers['set-cookie']) {
        const cookies = Array.isArray(hop.headers['set-cookie']) 
          ? hop.headers['set-cookie'] 
          : [hop.headers['set-cookie']];

        totalCookiesSet += cookies.length;

        for (const cookie of cookies) {
          const isSecure = /;\s*secure/i.test(cookie) && 
                          /;\s*httponly/i.test(cookie);
          
          if (isSecure) {
            secureCookies++;
          } else {
            insecureCookies++;
          }

          cookieOperations.push({
            hop: hop.url,
            isSecure: isSecure,
            hasSameSite: /;\s*samesite/i.test(cookie)
          });
        }
      }
    }

    return {
      totalCookiesSet: totalCookiesSet,
      secureCookies: secureCookies,
      insecureCookies: insecureCookies,
      operations: cookieOperations,
      manipulationLevel: totalCookiesSet > this.suspiciousBehaviors.cookieManipulationThreshold 
        ? 'high' 
        : totalCookiesSet > 2 ? 'medium' : 'low',
      isSuspicious: insecureCookies > secureCookies || 
                    totalCookiesSet > this.suspiciousBehaviors.cookieManipulationThreshold
    };
  }

  _analyzeTimingPatterns(chain) {
    const timings = [];
    
    for (const hop of chain) {
      if (hop.timing) {
        const total = Object.values(hop.timing).reduce((a, b) => a + b, 0);
        timings.push({
          hop: hop.url,
          total: total,
          breakdown: hop.timing
        });
      }
    }

    if (timings.length === 0) {
      return {
        available: false
      };
    }

    const totalTimes = timings.map(t => t.total);
    const avgTime = totalTimes.reduce((a, b) => a + b, 0) / totalTimes.length;
    const maxTime = Math.max(...totalTimes);
    const minTime = Math.min(...totalTimes);

    const variance = totalTimes.reduce((acc, time) => 
      acc + Math.pow(time - avgTime, 2), 0
    ) / totalTimes.length;
    const stdDev = Math.sqrt(variance);

    const anomalies = timings.filter(t => 
      Math.abs(t.total - avgTime) > stdDev * 2
    );

    return {
      available: true,
      avgTime: Math.round(avgTime),
      maxTime: Math.round(maxTime),
      minTime: Math.round(minTime),
      stdDev: Math.round(stdDev),
      anomalies: anomalies.length,
      anomalyDetails: anomalies,
      hasSignificantVariance: stdDev > avgTime * 0.5
    };
  }

  _analyzeContentEvolution(chain) {
    const contentTypes = [];
    const statusCodes = [];
    const responseSizes = [];

    for (const hop of chain) {
      if (hop.headers && hop.headers['content-type']) {
        contentTypes.push(hop.headers['content-type']);
      }
      if (hop.statusCode) {
        statusCodes.push(hop.statusCode);
      }
      if (hop.headers && hop.headers['content-length']) {
        responseSizes.push(parseInt(hop.headers['content-length'], 10));
      }
    }

    const contentTypeChanges = new Set(contentTypes).size;
    const statusCodePattern = this._analyzeStatusPattern(statusCodes);

    return {
      contentTypeChanges: contentTypeChanges,
      contentTypes: Array.from(new Set(contentTypes)),
      statusCodePattern: statusCodePattern,
      responseSizeVariation: responseSizes.length > 0 
        ? Math.max(...responseSizes) - Math.min(...responseSizes)
        : 0,
      isSuspicious: contentTypeChanges > 3
    };
  }

  _analyzeTrustChain(chain) {
    let trustScore = 100;
    const trustViolations = [];

    for (let i = 0; i < chain.length - 1; i++) {
      const current = chain[i];
      const next = chain[i + 1];

      if (current.protocol === 'https' && next.protocol === 'http') {
        trustScore -= 25;
        trustViolations.push({
          type: 'protocol_downgrade',
          from: current.url,
          to: next.url
        });
      }

      if (current.tlsInfo && !current.tlsInfo.valid) {
        trustScore -= 20;
        trustViolations.push({
          type: 'invalid_certificate',
          url: current.url
        });
      }

      if (current.tlsInfo && current.tlsInfo.isExpired) {
        trustScore -= 30;
        trustViolations.push({
          type: 'expired_certificate',
          url: current.url
        });
      }

      if (current.headerFingerprint && 
          current.headerFingerprint.security.score < 30) {
        trustScore -= 15;
        trustViolations.push({
          type: 'weak_security_headers',
          url: current.url
        });
      }
    }

    trustScore = Math.max(0, trustScore);

    return {
      trustScore: trustScore,
      violations: trustViolations.length,
      violationDetails: trustViolations,
      trustLevel: trustScore > 80 ? 'high' : 
                  trustScore > 50 ? 'medium' : 
                  trustScore > 20 ? 'low' : 'critical'
    };
  }

  _detectCloaking(chain) {
    const indicators = [];

    const userAgentSensitive = this._detectUserAgentCloaking(chain);
    if (userAgentSensitive) {
      indicators.push('user_agent_sensitive');
    }

    const hasHiddenRedirects = chain.some(hop => 
      hop.redirectType === 'javascript' || hop.redirectType === 'meta-refresh'
    );
    if (hasHiddenRedirects) {
      indicators.push('hidden_redirects');
    }

    const hasObfuscatedContent = chain.some(hop => 
      hop.htmlAnalysis && hop.htmlAnalysis.obfuscation.detected
    );
    if (hasObfuscatedContent) {
      indicators.push('obfuscated_content');
    }

    return {
      detected: indicators.length > 0,
      indicators: indicators,
      confidenceLevel: indicators.length > 2 ? 'high' : 
                       indicators.length > 0 ? 'medium' : 'low'
    };
  }

  _detectRapidRedirects(redirects) {
    if (redirects.length < this.suspiciousBehaviors.rapidRedirects) {
      return false;
    }

    for (let i = 0; i < redirects.length - 2; i++) {
      const window = redirects.slice(i, i + 3);
      const timestamps = window.map(r => new Date(r.timestamp).getTime());
      
      const timeDiff = timestamps[2] - timestamps[0];
      if (timeDiff < 1000) {
        return true;
      }
    }

    return false;
  }

  _analyzeTLDChanges(domains) {
    const tlds = domains.map(d => d.split('.').pop());
    let changes = 0;

    for (let i = 0; i < tlds.length - 1; i++) {
      if (tlds[i] !== tlds[i + 1]) {
        changes++;
      }
    }

    return changes;
  }

  _estimateRegistrarChanges(domains) {
    const uniqueDomains = [...new Set(domains)];
    return Math.max(0, uniqueDomains.length - 1);
  }

  _analyzeStatusPattern(codes) {
    const pattern = {};
    
    for (const code of codes) {
      const category = Math.floor(code / 100) + 'xx';
      pattern[category] = (pattern[category] || 0) + 1;
    }

    return pattern;
  }

  _detectUserAgentCloaking(chain) {
    return chain.some(hop => 
      hop.htmlAnalysis && 
      hop.htmlAnalysis.scripts && 
      hop.htmlAnalysis.scripts.total > 0
    );
  }
}