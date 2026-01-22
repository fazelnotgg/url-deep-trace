export class ThreatIntelligence {
  constructor() {
    this.maliciousPatterns = {
      phishingKeywords: [
        'verify', 'account', 'suspended', 'unusual', 'activity',
        'confirm', 'identity', 'secure', 'update', 'billing',
        'payment', 'expired', 'limited', 'time', 'winner',
        'prize', 'claim', 'urgent', 'immediate', 'action'
      ],
      
      brandImpersonation: [
        'paypal', 'amazon', 'microsoft', 'apple', 'google',
        'facebook', 'netflix', 'banking', 'login', 'signin'
      ],

      malwareIndicators: [
        'download', 'install', 'update', 'codec', 'player',
        'plugin', 'flash', 'java', 'runtime', 'crack',
        'keygen', 'serial', 'license', 'activation'
      ],

      cryptoScam: [
        'bitcoin', 'crypto', 'wallet', 'mining', 'invest',
        'profit', 'guarantee', 'roi', 'airdrop', 'presale'
      ],

      technicalSupport: [
        'support', 'helpdesk', 'technician', 'infection',
        'virus', 'malware', 'error', 'warning', 'critical'
      ]
    };

    this.suspiciousFileExtensions = [
      '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
      '.vbs', '.js', '.jar', '.wsf', '.hta', '.msi',
      '.apk', '.dmg', '.app', '.deb', '.rpm'
    ];

    this.commonCDNs = [
      'cloudflare', 'cloudfront', 'akamai', 'fastly',
      'cdn', 'jsdelivr', 'unpkg', 'cdnjs'
    ];

    this.attackVectors = {
      sqlInjection: [
        /\bselect\b.*\bfrom\b/i,
        /\bunion\b.*\bselect\b/i,
        /\bor\b.*1\s*=\s*1/i,
        /\bdrop\b.*\btable\b/i,
        /\binsert\b.*\binto\b/i
      ],
      
      xss: [
        /<script[^>]*>.*<\/script>/i,
        /javascript:/i,
        /onerror\s*=/i,
        /onload\s*=/i,
        /<iframe/i
      ],

      pathTraversal: [
        /\.\.[\/\\]/,
        /\.\.%2[fF]/,
        /%252[eE]%252[eE]/
      ],

      commandInjection: [
        /[;&|`$]/,
        /\$\(.*\)/,
        /`.*`/
      ]
    };
  }

  analyze(chain, fullAnalysisResult) {
    return {
      threatLevel: this._calculateThreatLevel(chain, fullAnalysisResult),
      phishingIndicators: this._detectPhishing(chain),
      malwareRisk: this._assessMalwareRisk(chain),
      attackVectorDetection: this._detectAttackVectors(chain),
      brandImpersonation: this._detectBrandImpersonation(chain),
      scamIndicators: this._detectScamPatterns(chain),
      dataExfiltrationRisk: this._assessDataExfiltration(chain),
      threatCategories: [],
      iocs: this._extractIOCs(chain),
      recommendedAction: 'monitor'
    };
  }

  _calculateThreatLevel(chain, fullAnalysisResult) {
    let score = 0;
    const factors = [];

    if (fullAnalysisResult && fullAnalysisResult.security) {
      const riskScore = fullAnalysisResult.security.risk.score;
      score += riskScore * 0.3;
      
      if (riskScore > 70) {
        factors.push('high_risk_score');
      }
    }

    const phishing = this._detectPhishing(chain);
    if (phishing.detected) {
      score += phishing.confidence * 0.4;
      factors.push('phishing_indicators');
    }

    const malware = this._assessMalwareRisk(chain);
    if (malware.risk > 0) {
      score += malware.risk * 0.3;
      factors.push('malware_indicators');
    }

    return {
      score: Math.min(100, Math.round(score)),
      level: score > 75 ? 'critical' :
             score > 50 ? 'high' :
             score > 25 ? 'medium' : 'low',
      factors: factors
    };
  }

  _detectPhishing(chain) {
    let indicators = 0;
    let confidence = 0;
    const details = [];

    for (const hop of chain) {
      if (hop.url) {
        const url = hop.url.toLowerCase();
        
        for (const keyword of this.maliciousPatterns.phishingKeywords) {
          if (url.includes(keyword)) {
            indicators++;
            confidence += 10;
            details.push({
              type: 'url_keyword',
              keyword: keyword,
              url: hop.url
            });
          }
        }
      }

      if (hop.htmlAnalysis) {
        if (hop.htmlAnalysis.forms && hop.htmlAnalysis.forms.hasSensitiveForms) {
          indicators++;
          confidence += 15;
          details.push({
            type: 'sensitive_form',
            url: hop.url
          });
        }

        if (hop.htmlAnalysis.forms && hop.htmlAnalysis.forms.externalSubmissions > 0) {
          indicators++;
          confidence += 20;
          details.push({
            type: 'external_form_submission',
            url: hop.url
          });
        }

        if (hop.htmlAnalysis.structure && hop.htmlAnalysis.structure.title) {
          const title = hop.htmlAnalysis.structure.title.toLowerCase();
          for (const keyword of this.maliciousPatterns.phishingKeywords) {
            if (title.includes(keyword)) {
              indicators++;
              confidence += 12;
              details.push({
                type: 'title_keyword',
                keyword: keyword,
                url: hop.url
              });
            }
          }
        }
      }

      if (hop.lexical) {
        if (hop.lexical.homoglyphDetection && hop.lexical.homoglyphDetection.hasHomoglyphs) {
          indicators++;
          confidence += 25;
          details.push({
            type: 'homoglyph_attack',
            url: hop.url
          });
        }

        if (hop.lexical.punycode && hop.lexical.punycode.detected) {
          indicators++;
          confidence += 20;
          details.push({
            type: 'punycode_detected',
            url: hop.url
          });
        }
      }
    }

    confidence = Math.min(100, confidence);

    return {
      detected: indicators > 0,
      indicators: indicators,
      confidence: confidence,
      details: details,
      severity: confidence > 70 ? 'critical' :
                confidence > 40 ? 'high' :
                confidence > 20 ? 'medium' : 'low'
    };
  }

  _assessMalwareRisk(chain) {
    let risk = 0;
    const indicators = [];

    for (const hop of chain) {
      if (hop.url) {
        const url = hop.url.toLowerCase();
        
        for (const ext of this.suspiciousFileExtensions) {
          if (url.endsWith(ext)) {
            risk += 30;
            indicators.push({
              type: 'suspicious_file_extension',
              extension: ext,
              url: hop.url
            });
          }
        }

        for (const keyword of this.maliciousPatterns.malwareIndicators) {
          if (url.includes(keyword)) {
            risk += 15;
            indicators.push({
              type: 'malware_keyword',
              keyword: keyword,
              url: hop.url
            });
          }
        }
      }

      if (hop.htmlAnalysis) {
        if (hop.htmlAnalysis.scripts.obfuscated > 0) {
          risk += 25;
          indicators.push({
            type: 'obfuscated_scripts',
            count: hop.htmlAnalysis.scripts.obfuscated,
            url: hop.url
          });
        }

        if (hop.htmlAnalysis.iframes.hiddenIframes > 0) {
          risk += 20;
          indicators.push({
            type: 'hidden_iframes',
            count: hop.htmlAnalysis.iframes.hiddenIframes,
            url: hop.url
          });
        }

        if (hop.htmlAnalysis.suspiciousElements.count > 0) {
          risk += 15;
          indicators.push({
            type: 'suspicious_elements',
            count: hop.htmlAnalysis.suspiciousElements.count,
            url: hop.url
          });
        }
      }

      if (hop.lexical && hop.lexical.path && hop.lexical.path.suspiciousExtensions) {
        risk += 25;
        indicators.push({
          type: 'path_suspicious_extension',
          extensions: hop.lexical.path.suspiciousExtensions,
          url: hop.url
        });
      }
    }

    risk = Math.min(100, risk);

    return {
      risk: risk,
      level: risk > 70 ? 'critical' :
             risk > 40 ? 'high' :
             risk > 20 ? 'medium' : 'low',
      indicators: indicators
    };
  }

  _detectAttackVectors(chain) {
    const detected = [];

    for (const hop of chain) {
      if (hop.url) {
        for (const [type, patterns] of Object.entries(this.attackVectors)) {
          for (const pattern of patterns) {
            if (pattern.test(hop.url)) {
              detected.push({
                type: type,
                url: hop.url,
                pattern: pattern.toString()
              });
            }
          }
        }
      }

      if (hop.htmlAnalysis && hop.htmlAnalysis.scripts) {
        for (const script of hop.htmlAnalysis.scripts.scripts) {
          if (script.isInline && script.contentLength > 0) {
            for (const pattern of this.attackVectors.xss) {
              detected.push({
                type: 'xss',
                url: hop.url,
                context: 'inline_script'
              });
              break;
            }
          }
        }
      }
    }

    return {
      detected: detected.length > 0,
      count: detected.length,
      vectors: detected,
      types: [...new Set(detected.map(d => d.type))]
    };
  }

  _detectBrandImpersonation(chain) {
    const impersonations = [];

    for (const hop of chain) {
      if (hop.url) {
        const url = hop.url.toLowerCase();
        
        for (const brand of this.maliciousPatterns.brandImpersonation) {
          if (url.includes(brand)) {
            try {
              const urlObj = new URL(hop.url);
              const hostname = urlObj.hostname.toLowerCase();
              
              const isLegit = hostname === `${brand}.com` || 
                            hostname.endsWith(`.${brand}.com`);
              
              if (!isLegit && !this._isKnownCDN(hostname)) {
                impersonations.push({
                  brand: brand,
                  url: hop.url,
                  hostname: hostname,
                  confidence: 'high'
                });
              }
            } catch (e) {
              continue;
            }
          }
        }
      }

      if (hop.htmlAnalysis) {
        const title = hop.htmlAnalysis.structure.title?.toLowerCase() || '';
        
        for (const brand of this.maliciousPatterns.brandImpersonation) {
          if (title.includes(brand)) {
            impersonations.push({
              brand: brand,
              url: hop.url,
              context: 'page_title',
              confidence: 'medium'
            });
          }
        }
      }
    }

    return {
      detected: impersonations.length > 0,
      count: impersonations.length,
      impersonations: impersonations
    };
  }

  _detectScamPatterns(chain) {
    const scamIndicators = [];

    for (const hop of chain) {
      if (hop.url) {
        const url = hop.url.toLowerCase();
        
        for (const keyword of this.maliciousPatterns.cryptoScam) {
          if (url.includes(keyword)) {
            scamIndicators.push({
              type: 'crypto_scam',
              keyword: keyword,
              url: hop.url
            });
          }
        }

        for (const keyword of this.maliciousPatterns.technicalSupport) {
          if (url.includes(keyword)) {
            scamIndicators.push({
              type: 'tech_support_scam',
              keyword: keyword,
              url: hop.url
            });
          }
        }
      }

      if (hop.htmlAnalysis) {
        const title = hop.htmlAnalysis.structure.title?.toLowerCase() || '';
        
        if (title.includes('winner') || title.includes('prize') || 
            title.includes('congratulation')) {
          scamIndicators.push({
            type: 'prize_scam',
            url: hop.url,
            context: 'title'
          });
        }

        if (hop.htmlAnalysis.forms.count > 0 && title.includes('claim')) {
          scamIndicators.push({
            type: 'claim_scam',
            url: hop.url,
            context: 'form_with_claim'
          });
        }
      }
    }

    return {
      detected: scamIndicators.length > 0,
      count: scamIndicators.length,
      indicators: scamIndicators,
      types: [...new Set(scamIndicators.map(s => s.type))]
    };
  }

  _assessDataExfiltration(chain) {
    let risk = 0;
    const indicators = [];

    for (const hop of chain) {
      if (hop.htmlAnalysis && hop.htmlAnalysis.forms) {
        if (hop.htmlAnalysis.forms.hasSensitiveForms) {
          risk += 30;
          indicators.push({
            type: 'sensitive_data_collection',
            url: hop.url,
            formCount: hop.htmlAnalysis.forms.forms.filter(f => f.hasSensitiveFields).length
          });
        }

        if (hop.htmlAnalysis.forms.externalSubmissions > 0) {
          risk += 40;
          indicators.push({
            type: 'external_data_submission',
            url: hop.url,
            count: hop.htmlAnalysis.forms.externalSubmissions
          });
        }
      }

      if (hop.htmlAnalysis && hop.htmlAnalysis.externalResources) {
        if (hop.htmlAnalysis.externalResources.uniqueDomains > 5) {
          risk += 20;
          indicators.push({
            type: 'multiple_external_domains',
            url: hop.url,
            count: hop.htmlAnalysis.externalResources.uniqueDomains
          });
        }
      }

      if (hop.headerFingerprint && hop.headerFingerprint.cors) {
        if (hop.headerFingerprint.cors.isInsecure) {
          risk += 25;
          indicators.push({
            type: 'insecure_cors',
            url: hop.url
          });
        }
      }
    }

    risk = Math.min(100, risk);

    return {
      risk: risk,
      level: risk > 60 ? 'high' :
             risk > 30 ? 'medium' : 'low',
      indicators: indicators
    };
  }

  _extractIOCs(chain) {
    const iocs = {
      domains: new Set(),
      ips: new Set(),
      urls: new Set(),
      hashes: new Set()
    };

    for (const hop of chain) {
      if (hop.url) {
        iocs.urls.add(hop.url);
        
        try {
          const url = new URL(hop.url);
          iocs.domains.add(url.hostname);
        } catch (e) {
          continue;
        }
      }

      if (hop.domainInfo && hop.domainInfo.dnsRecords) {
        for (const ip of hop.domainInfo.dnsRecords.ipv4 || []) {
          iocs.ips.add(ip);
        }
        for (const ip of hop.domainInfo.dnsRecords.ipv6 || []) {
          iocs.ips.add(ip);
        }
      }

      if (hop.tlsInfo && hop.tlsInfo.fingerprint) {
        iocs.hashes.add(hop.tlsInfo.fingerprint);
      }
    }

    return {
      domains: Array.from(iocs.domains),
      ips: Array.from(iocs.ips),
      urls: Array.from(iocs.urls),
      certificateHashes: Array.from(iocs.hashes)
    };
  }

  _isKnownCDN(hostname) {
    return this.commonCDNs.some(cdn => hostname.includes(cdn));
  }

  generateThreatReport(analysis) {
    const report = {
      summary: {
        threatLevel: analysis.threatLevel.level,
        threatScore: analysis.threatLevel.score,
        primaryThreats: []
      },
      findings: [],
      recommendations: []
    };

    if (analysis.phishingIndicators.detected) {
      report.summary.primaryThreats.push('Phishing');
      report.findings.push({
        category: 'Phishing',
        severity: analysis.phishingIndicators.severity,
        details: analysis.phishingIndicators.details
      });
      report.recommendations.push('Block URL immediately - Phishing detected');
    }

    if (analysis.malwareRisk.risk > 50) {
      report.summary.primaryThreats.push('Malware');
      report.findings.push({
        category: 'Malware Distribution',
        severity: analysis.malwareRisk.level,
        details: analysis.malwareRisk.indicators
      });
      report.recommendations.push('Quarantine - High malware risk');
    }

    if (analysis.brandImpersonation.detected) {
      report.summary.primaryThreats.push('Brand Impersonation');
      report.findings.push({
        category: 'Brand Impersonation',
        severity: 'high',
        details: analysis.brandImpersonation.impersonations
      });
      report.recommendations.push('Report to brand protection team');
    }

    if (analysis.dataExfiltrationRisk.risk > 40) {
      report.summary.primaryThreats.push('Data Exfiltration');
      report.findings.push({
        category: 'Data Exfiltration',
        severity: analysis.dataExfiltrationRisk.level,
        details: analysis.dataExfiltrationRisk.indicators
      });
      report.recommendations.push('Monitor for data leakage');
    }

    if (report.recommendations.length === 0) {
      report.recommendations.push('Continue monitoring');
    }

    return report;
  }
}