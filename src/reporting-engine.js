export class ReportingEngine {
  constructor() {
    this.templates = {
      executive: this._generateExecutiveReport.bind(this),
      technical: this._generateTechnicalReport.bind(this),
      compliance: this._generateComplianceReport.bind(this),
      incident: this._generateIncidentReport.bind(this)
    };
  }

  generateReport(analysisResult, type = 'technical', options = {}) {
    const template = this.templates[type];
    
    if (!template) {
      throw new Error(`Unknown report type: ${type}`);
    }

    return template(analysisResult, options);
  }

  generateBatchReport(batchResults, type = 'executive', options = {}) {
    const reports = [];
    
    for (const result of batchResults) {
      if (this._shouldIncludeInReport(result, options)) {
        reports.push(this.generateReport(result, type, options));
      }
    }

    return {
      reportType: `batch_${type}`,
      generatedAt: new Date().toISOString(),
      totalAnalyzed: batchResults.length,
      reportsIncluded: reports.length,
      summary: this._generateBatchSummary(batchResults),
      reports: reports
    };
  }

  _generateExecutiveReport(result, options) {
    return {
      reportType: 'executive',
      generatedAt: new Date().toISOString(),
      url: result.url,
      verdict: this._getExecutiveVerdict(result),
      keyFindings: this._extractKeyFindings(result),
      riskSummary: {
        level: result.security?.risk?.level,
        score: result.security?.risk?.score,
        classification: result.mlClassification?.classification
      },
      recommendations: this._generateRecommendations(result),
      impactAssessment: this._assessImpact(result)
    };
  }

  _generateTechnicalReport(result, options) {
    return {
      reportType: 'technical',
      generatedAt: new Date().toISOString(),
      url: result.url,
      finalDestination: result.finalDestination,
      
      traceAnalysis: {
        totalHops: result.trace?.totalHops,
        redirectChain: result.trace?.chain?.map(hop => ({
          url: hop.url,
          statusCode: hop.statusCode,
          redirectType: hop.redirectType,
          protocol: hop.protocol
        })),
        behavioral: result.trace?.behavioral
      },

      securityAnalysis: {
        riskAssessment: result.security?.risk,
        threatIntelligence: result.threat,
        mlClassification: result.mlClassification
      },

      technicalDetails: this._extractTechnicalDetails(result),
      
      indicators: this._extractTechnicalIndicators(result),
      
      timeline: this._buildTimeline(result)
    };
  }

  _generateComplianceReport(result, options) {
    return {
      reportType: 'compliance',
      generatedAt: new Date().toISOString(),
      url: result.url,
      
      securityPosture: {
        tlsCompliance: this._assessTLSCompliance(result),
        headerCompliance: this._assessHeaderCompliance(result),
        cookieCompliance: this._assessCookieCompliance(result),
        privacyCompliance: this._assessPrivacyCompliance(result)
      },

      vulnerabilities: this._identifyVulnerabilities(result),
      
      complianceScore: this._calculateComplianceScore(result),
      
      remediation: this._generateRemediationSteps(result),
      
      regulations: this._assessRegulatoryCompliance(result)
    };
  }

  _generateIncidentReport(result, options) {
    return {
      reportType: 'incident',
      generatedAt: new Date().toISOString(),
      incidentId: this._generateIncidentId(),
      
      incidentSummary: {
        url: result.url,
        severity: this._determineSeverity(result),
        category: this._categorizeIncident(result),
        affectedSystems: options.affectedSystems || ['Web Browsing'],
        detectedAt: result.metadata?.analyzedAt
      },

      threatDetails: {
        type: this._identifyThreatType(result),
        indicators: result.threat?.iocs || {},
        attackVectors: result.threat?.attackVectorDetection?.vectors || [],
        maliciousActivity: this._describeMaliciousActivity(result)
      },

      impact: {
        severity: this._determineSeverity(result),
        scope: this._assessScope(result),
        dataAtRisk: this._identifyDataAtRisk(result)
      },

      response: {
        immediateActions: this._generateImmediateActions(result),
        containment: this._generateContainmentSteps(result),
        investigation: this._generateInvestigationSteps(result)
      },

      evidence: this._collectEvidence(result)
    };
  }

  _shouldIncludeInReport(result, options) {
    if (options.minRiskScore && result.security?.risk?.score < options.minRiskScore) {
      return false;
    }

    if (options.classificationsOnly && options.classificationsOnly.length > 0) {
      if (!options.classificationsOnly.includes(result.mlClassification?.classification)) {
        return false;
      }
    }

    return true;
  }

  _generateBatchSummary(results) {
    const summary = {
      total: results.length,
      successful: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
      
      riskDistribution: {
        minimal: 0,
        low: 0,
        medium: 0,
        high: 0
      },

      classifications: {
        benign: 0,
        questionable: 0,
        suspicious: 0,
        malicious: 0
      },

      threats: {
        phishing: 0,
        malware: 0,
        brandImpersonation: 0,
        dataExfiltration: 0
      },

      topRisks: []
    };

    for (const result of results) {
      if (result.security?.risk?.level) {
        summary.riskDistribution[result.security.risk.level]++;
      }

      if (result.mlClassification?.classification) {
        summary.classifications[result.mlClassification.classification]++;
      }

      if (result.threat?.phishingIndicators?.detected) summary.threats.phishing++;
      if (result.threat?.malwareRisk?.risk > 50) summary.threats.malware++;
      if (result.threat?.brandImpersonation?.detected) summary.threats.brandImpersonation++;
      if (result.threat?.dataExfiltrationRisk?.risk > 40) summary.threats.dataExfiltration++;
    }

    summary.topRisks = results
      .filter(r => r.security?.risk?.score)
      .sort((a, b) => b.security.risk.score - a.security.risk.score)
      .slice(0, 10)
      .map(r => ({
        url: r.url,
        score: r.security.risk.score,
        level: r.security.risk.level
      }));

    return summary;
  }

  _getExecutiveVerdict(result) {
    const riskScore = result.security?.risk?.score || 0;
    const classification = result.mlClassification?.classification;

    if (classification === 'malicious' || riskScore >= 80) {
      return 'BLOCK - High Risk Detected';
    } else if (classification === 'suspicious' || riskScore >= 60) {
      return 'WARN - Suspicious Activity';
    } else if (riskScore >= 30) {
      return 'MONITOR - Low Risk';
    } else {
      return 'ALLOW - No Significant Risk';
    }
  }

  _extractKeyFindings(result) {
    const findings = [];

    if (result.threat?.phishingIndicators?.detected) {
      findings.push({
        severity: 'critical',
        finding: 'Phishing indicators detected',
        confidence: result.threat.phishingIndicators.confidence
      });
    }

    if (result.threat?.malwareRisk?.risk > 50) {
      findings.push({
        severity: 'critical',
        finding: 'Malware distribution risk',
        risk: result.threat.malwareRisk.risk
      });
    }

    if (result.security?.risk?.details?.protocolDowngrade) {
      findings.push({
        severity: 'high',
        finding: 'Protocol downgrade detected (HTTPS to HTTP)'
      });
    }

    if (result.security?.risk?.details?.certificateIssues) {
      const certIssues = result.security.risk.details.certificateIssues;
      if (certIssues.expired > 0 || certIssues.invalid > 0) {
        findings.push({
          severity: 'high',
          finding: 'Certificate validation issues'
        });
      }
    }

    return findings.slice(0, 5);
  }

  _generateRecommendations(result) {
    const recommendations = [];
    const riskScore = result.security?.risk?.score || 0;

    if (riskScore >= 70) {
      recommendations.push('Block access to this URL immediately');
      recommendations.push('Add to organizational blacklist');
      recommendations.push('Alert security team for investigation');
    } else if (riskScore >= 40) {
      recommendations.push('Monitor user access to this URL');
      recommendations.push('Implement additional authentication checks');
      recommendations.push('Review security policies');
    } else {
      recommendations.push('Continue monitoring');
      recommendations.push('Periodic re-assessment recommended');
    }

    return recommendations;
  }

  _assessImpact(result) {
    return {
      confidentiality: result.threat?.dataExfiltrationRisk?.risk > 40 ? 'high' : 'low',
      integrity: result.threat?.malwareRisk?.risk > 50 ? 'high' : 'low',
      availability: result.trace?.totalHops > 10 ? 'medium' : 'low'
    };
  }

  _extractTechnicalDetails(result) {
    const details = {};

    if (result.trace?.chain?.[0]) {
      const firstHop = result.trace.chain[0];
      
      details.tls = firstHop.tlsInfo;
      details.headers = firstHop.headerFingerprint;
      details.domain = firstHop.domainInfo;
      details.lexical = firstHop.lexical;
    }

    return details;
  }

  _extractTechnicalIndicators(result) {
    return {
      iocs: result.threat?.iocs || {},
      attackVectors: result.threat?.attackVectorDetection?.types || [],
      obfuscation: result.threat?.malwareRisk?.indicators || []
    };
  }

  _buildTimeline(result) {
    if (!result.trace?.chain) return [];

    return result.trace.chain.map((hop, index) => ({
      step: index + 1,
      timestamp: hop.timestamp,
      url: hop.url,
      action: hop.redirectType || 'final',
      statusCode: hop.statusCode
    }));
  }

  _assessTLSCompliance(result) {
    const chain = result.trace?.chain || [];
    let compliant = true;
    const issues = [];

    for (const hop of chain) {
      if (hop.protocol === 'https' && hop.tlsInfo) {
        if (hop.tlsInfo.isExpired) {
          compliant = false;
          issues.push('Expired certificate detected');
        }
        if (!hop.tlsInfo.valid) {
          compliant = false;
          issues.push('Invalid certificate detected');
        }
      }
    }

    return { compliant, issues };
  }

  _assessHeaderCompliance(result) {
    const chain = result.trace?.chain || [];
    const requiredHeaders = ['strict-transport-security', 'x-frame-options', 'x-content-type-options'];
    const missing = [];

    for (const hop of chain) {
      if (hop.headerFingerprint?.security) {
        for (const header of requiredHeaders) {
          if (hop.headerFingerprint.security.missing.includes(header)) {
            missing.push(header);
          }
        }
      }
    }

    return {
      compliant: missing.length === 0,
      missingHeaders: [...new Set(missing)]
    };
  }

  _assessCookieCompliance(result) {
    const chain = result.trace?.chain || [];
    let compliant = true;
    const issues = [];

    for (const hop of chain) {
      if (hop.headerFingerprint?.cookies) {
        if (hop.headerFingerprint.cookies.insecureCount > 0) {
          compliant = false;
          issues.push(`${hop.headerFingerprint.cookies.insecureCount} insecure cookies`);
        }
      }
    }

    return { compliant, issues };
  }

  _assessPrivacyCompliance(result) {
    const dataCollected = result.threat?.dataExfiltrationRisk?.risk > 0;
    const externalSharing = result.trace?.chain?.some(hop => 
      hop.htmlAnalysis?.forms?.externalSubmissions > 0
    );

    return {
      compliant: !dataCollected && !externalSharing,
      concerns: [
        ...(dataCollected ? ['Data collection detected'] : []),
        ...(externalSharing ? ['External data sharing'] : [])
      ]
    };
  }

  _identifyVulnerabilities(result) {
    const vulnerabilities = [];

    if (result.threat?.attackVectorDetection?.detected) {
      for (const vector of result.threat.attackVectorDetection.vectors) {
        vulnerabilities.push({
          type: vector.type,
          severity: 'high',
          location: vector.url
        });
      }
    }

    return vulnerabilities;
  }

  _calculateComplianceScore(result) {
    let score = 100;

    const tls = this._assessTLSCompliance(result);
    if (!tls.compliant) score -= 25;

    const headers = this._assessHeaderCompliance(result);
    if (!headers.compliant) score -= 20;

    const cookies = this._assessCookieCompliance(result);
    if (!cookies.compliant) score -= 15;

    const privacy = this._assessPrivacyCompliance(result);
    if (!privacy.compliant) score -= 20;

    return Math.max(0, score);
  }

  _generateRemediationSteps(result) {
    const steps = [];

    const tls = this._assessTLSCompliance(result);
    if (!tls.compliant) {
      steps.push('Renew/fix SSL/TLS certificates');
    }

    const headers = this._assessHeaderCompliance(result);
    if (!headers.compliant) {
      steps.push(`Implement missing security headers: ${headers.missingHeaders.join(', ')}`);
    }

    return steps;
  }

  _assessRegulatoryCompliance(result) {
    return {
      gdpr: this._assessPrivacyCompliance(result).compliant ? 'compliant' : 'non-compliant',
      pciDss: this._assessTLSCompliance(result).compliant ? 'compliant' : 'non-compliant',
      hipaa: this._assessCookieCompliance(result).compliant ? 'compliant' : 'non-compliant'
    };
  }

  _generateIncidentId() {
    return `INC-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
  }

  _determineSeverity(result) {
    const riskScore = result.security?.risk?.score || 0;
    
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 40) return 'medium';
    return 'low';
  }

  _categorizeIncident(result) {
    if (result.threat?.phishingIndicators?.detected) return 'Phishing Attack';
    if (result.threat?.malwareRisk?.risk > 50) return 'Malware Distribution';
    if (result.threat?.brandImpersonation?.detected) return 'Brand Impersonation';
    return 'Security Incident';
  }

  _identifyThreatType(result) {
    const types = [];
    
    if (result.threat?.phishingIndicators?.detected) types.push('Phishing');
    if (result.threat?.malwareRisk?.risk > 50) types.push('Malware');
    if (result.threat?.brandImpersonation?.detected) types.push('Impersonation');
    
    return types.length > 0 ? types : ['Unknown'];
  }

  _describeMaliciousActivity(result) {
    const activities = [];

    if (result.threat?.phishingIndicators?.details) {
      activities.push(...result.threat.phishingIndicators.details.map(d => d.type));
    }

    if (result.threat?.malwareRisk?.indicators) {
      activities.push(...result.threat.malwareRisk.indicators.map(i => i.type));
    }

    return [...new Set(activities)];
  }

  _assessScope(result) {
    const hops = result.trace?.totalHops || 0;
    const domains = result.threat?.iocs?.domains?.length || 0;

    if (hops > 10 || domains > 5) return 'widespread';
    if (hops > 5 || domains > 2) return 'moderate';
    return 'limited';
  }

  _identifyDataAtRisk(result) {
    const dataTypes = [];

    if (result.trace?.chain?.some(hop => hop.htmlAnalysis?.forms?.hasSensitiveForms)) {
      dataTypes.push('Credentials', 'Personal Information', 'Financial Data');
    }

    return dataTypes;
  }

  _generateImmediateActions(result) {
    return [
      'Isolate affected systems',
      'Block malicious URL at firewall',
      'Alert security team',
      'Preserve evidence'
    ];
  }

  _generateContainmentSteps(result) {
    return [
      'Add URL to organizational blacklist',
      'Update security policies',
      'Scan affected systems for compromise',
      'Review access logs'
    ];
  }

  _generateInvestigationSteps(result) {
    return [
      'Analyze complete redirect chain',
      'Identify additional IOCs',
      'Check for lateral movement',
      'Review user activity logs'
    ];
  }

  _collectEvidence(result) {
    return {
      url: result.url,
      timestamp: result.metadata?.analyzedAt,
      redirectChain: result.trace?.chain?.map(h => h.url),
      iocs: result.threat?.iocs,
      screenshots: [],
      logs: []
    };
  }
}