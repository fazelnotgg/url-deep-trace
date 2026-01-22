import { URL } from 'url';

export class RiskEngine {
  constructor() {
    this.suspiciousTLDs = [
      '.xyz',
      '.top',
      '.work',
      '.click',
      '.link',
      '.download',
      '.stream',
      '.loan',
      '.win',
      '.bid'
    ];

    this.riskThresholds = {
      low: 30,
      medium: 60,
      high: 80
    };
  }

  analyze(traceResult) {
    if (!traceResult.success || !traceResult.chain) {
      return {
        score: 0,
        level: 'unknown',
        factors: ['Analysis failed or incomplete trace']
      };
    }

    const factors = [];
    let score = 0;

    const redirectCount = traceResult.chain.filter(hop => hop.type === 'redirect').length;
    if (redirectCount > 5) {
      const points = Math.min(redirectCount * 5, 30);
      score += points;
      factors.push(`Excessive redirects: ${redirectCount} hops (+${points})`);
    }

    const hasProtocolDowngrade = this._detectProtocolDowngrade(traceResult.chain);
    if (hasProtocolDowngrade) {
      score += 35;
      factors.push('Protocol downgrade detected: HTTPS to HTTP (+35)');
    }

    const certIssues = this._analyzeCertificates(traceResult.chain);
    if (certIssues.expiringSoon > 0) {
      score += certIssues.expiringSoon * 15;
      factors.push(`Certificate(s) expiring soon: ${certIssues.expiringSoon} (+${certIssues.expiringSoon * 15})`);
    }
    if (certIssues.expired > 0) {
      score += certIssues.expired * 25;
      factors.push(`Expired certificate(s): ${certIssues.expired} (+${certIssues.expired * 25})`);
    }
    if (certIssues.invalid > 0) {
      score += certIssues.invalid * 20;
      factors.push(`Invalid certificate(s): ${certIssues.invalid} (+${certIssues.invalid * 20})`);
    }

    const suspiciousDomains = this._detectSuspiciousDomains(traceResult.chain);
    if (suspiciousDomains.length > 0) {
      score += suspiciousDomains.length * 12;
      factors.push(`Suspicious TLD(s): ${suspiciousDomains.join(', ')} (+${suspiciousDomains.length * 12})`);
    }

    const hasMetaRefresh = traceResult.chain.some(hop => hop.redirectType === 'meta-refresh');
    if (hasMetaRefresh) {
      score += 10;
      factors.push('Meta refresh redirect detected (+10)');
    }

    const hasJSRedirect = traceResult.chain.some(hop => hop.redirectType === 'javascript');
    if (hasJSRedirect) {
      score += 12;
      factors.push('JavaScript redirect detected (+12)');
    }

    const hasErrors = traceResult.chain.some(hop => hop.error);
    if (hasErrors) {
      score += 8;
      factors.push('Connection errors encountered (+8)');
    }

    const hasCircularRedirect = traceResult.chain.some(hop => 
      hop.error && hop.error.toLowerCase().includes('circular')
    );
    if (hasCircularRedirect) {
      score += 20;
      factors.push('Circular redirect pattern (+20)');
    }

    const mixedContentRisk = this._detectMixedContent(traceResult.chain);
    if (mixedContentRisk) {
      score += 15;
      factors.push('Mixed HTTP/HTTPS content (+15)');
    }

    const lexicalRisks = this._analyzeLexicalRisks(traceResult.chain);
    if (lexicalRisks.highRiskCount > 0) {
      const points = lexicalRisks.highRiskCount * 10;
      score += points;
      factors.push(`High-risk lexical patterns: ${lexicalRisks.highRiskCount} URLs (+${points})`);
    }

    const htmlRisks = this._analyzeHTMLRisks(traceResult.chain);
    if (htmlRisks.sensitiveForms > 0) {
      score += 15;
      factors.push(`Sensitive form(s) detected: ${htmlRisks.sensitiveForms} (+15)`);
    }
    if (htmlRisks.externalSubmissions > 0) {
      score += 12;
      factors.push(`External form submissions: ${htmlRisks.externalSubmissions} (+12)`);
    }
    if (htmlRisks.obfuscatedScripts > 0) {
      score += 18;
      factors.push(`Obfuscated scripts: ${htmlRisks.obfuscatedScripts} (+18)`);
    }

    const headerRisks = this._analyzeHeaderRisks(traceResult.chain);
    if (headerRisks.poorSecurityScore > 0) {
      const points = Math.round(headerRisks.poorSecurityScore / 2);
      score += points;
      factors.push(`Weak security headers (+${points})`);
    }
    if (headerRisks.insecureCookies > 0) {
      score += 10;
      factors.push(`Insecure cookie(s): ${headerRisks.insecureCookies} (+10)`);
    }

    const domainRisks = this._analyzeDomainRisks(traceResult.chain);
    if (domainRisks.noDNSRecords > 0) {
      score += 20;
      factors.push(`Domain(s) with DNS issues: ${domainRisks.noDNSRecords} (+20)`);
    }
    if (domainRisks.newDomains > 0) {
      score += 12;
      factors.push(`Likely new domains: ${domainRisks.newDomains} (+12)`);
    }

    score = Math.min(score, 100);

    const level = this._calculateRiskLevel(score);

    return {
      score: score,
      level: level,
      factors: factors.length > 0 ? factors : ['No significant risk factors detected'],
      details: {
        totalHops: traceResult.totalHops,
        redirectCount: redirectCount,
        protocolDowngrade: hasProtocolDowngrade,
        certificateIssues: certIssues,
        suspiciousDomains: suspiciousDomains,
        lexicalRisks: lexicalRisks,
        htmlRisks: htmlRisks,
        headerRisks: headerRisks,
        domainRisks: domainRisks
      }
    };
  }

  _detectProtocolDowngrade(chain) {
    for (let i = 0; i < chain.length - 1; i++) {
      const current = chain[i];
      const next = chain[i + 1];

      if (current.protocol === 'https' && next.protocol === 'http') {
        return true;
      }
    }
    return false;
  }

  _analyzeCertificates(chain) {
    const issues = {
      expiringSoon: 0,
      expired: 0,
      invalid: 0
    };

    for (const hop of chain) {
      if (hop.tlsInfo && hop.tlsInfo.valid) {
        if (hop.tlsInfo.isExpired) {
          issues.expired++;
        } else if (hop.tlsInfo.daysRemaining < 7 && hop.tlsInfo.daysRemaining >= 0) {
          issues.expiringSoon++;
        }
      } else if (hop.tlsInfo && !hop.tlsInfo.valid) {
        issues.invalid++;
      }
    }

    return issues;
  }

  _detectSuspiciousDomains(chain) {
    const suspicious = [];

    for (const hop of chain) {
      if (!hop.url) continue;

      try {
        const url = new URL(hop.url);
        const hostname = url.hostname.toLowerCase();

        for (const tld of this.suspiciousTLDs) {
          if (hostname.endsWith(tld) && !suspicious.includes(hostname)) {
            suspicious.push(hostname);
            break;
          }
        }
      } catch (error) {
        continue;
      }
    }

    return suspicious;
  }

  _detectMixedContent(chain) {
    const protocols = new Set();

    for (const hop of chain) {
      if (hop.protocol) {
        protocols.add(hop.protocol);
      }
    }

    return protocols.has('http') && protocols.has('https');
  }

  _calculateRiskLevel(score) {
    if (score >= this.riskThresholds.high) {
      return 'high';
    } else if (score >= this.riskThresholds.medium) {
      return 'medium';
    } else if (score >= this.riskThresholds.low) {
      return 'low';
    } else {
      return 'minimal';
    }
  }

  _analyzeLexicalRisks(chain) {
    let highRiskCount = 0;
    let totalRiskScore = 0;

    for (const hop of chain) {
      if (hop.lexical && hop.lexical.riskScore) {
        totalRiskScore += hop.lexical.riskScore;
        if (hop.lexical.riskScore > 50) {
          highRiskCount++;
        }
      }
    }

    return {
      highRiskCount: highRiskCount,
      averageScore: chain.length > 0 ? Math.round(totalRiskScore / chain.length) : 0
    };
  }

  _analyzeHTMLRisks(chain) {
    let sensitiveForms = 0;
    let externalSubmissions = 0;
    let obfuscatedScripts = 0;

    for (const hop of chain) {
      if (hop.htmlAnalysis) {
        if (hop.htmlAnalysis.forms?.hasSensitiveForms) {
          sensitiveForms++;
        }
        if (hop.htmlAnalysis.forms?.externalSubmissions > 0) {
          externalSubmissions += hop.htmlAnalysis.forms.externalSubmissions;
        }
        if (hop.htmlAnalysis.scripts?.obfuscated > 0) {
          obfuscatedScripts += hop.htmlAnalysis.scripts.obfuscated;
        }
      }
    }

    return {
      sensitiveForms: sensitiveForms,
      externalSubmissions: externalSubmissions,
      obfuscatedScripts: obfuscatedScripts
    };
  }

  _analyzeHeaderRisks(chain) {
    let poorSecurityScore = 0;
    let insecureCookies = 0;

    for (const hop of chain) {
      if (hop.headerFingerprint?.security) {
        const secScore = hop.headerFingerprint.security.score;
        if (secScore < 50) {
          poorSecurityScore += (50 - secScore);
        }
      }

      if (hop.headerFingerprint?.cookies?.insecureCount > 0) {
        insecureCookies += hop.headerFingerprint.cookies.insecureCount;
      }
    }

    return {
      poorSecurityScore: poorSecurityScore,
      insecureCookies: insecureCookies
    };
  }

  _analyzeDomainRisks(chain) {
    let noDNSRecords = 0;
    let newDomains = 0;

    for (const hop of chain) {
      if (hop.domainInfo) {
        if (!hop.domainInfo.dnsRecords?.querySuccess) {
          noDNSRecords++;
        }
        if (hop.domainInfo.ageEstimate?.indicator === 'likely_new') {
          newDomains++;
        }
      }
    }

    return {
      noDNSRecords: noDNSRecords,
      newDomains: newDomains
    };
  }
}