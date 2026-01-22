export class MLClassifier {
  constructor() {
    this.featureWeights = {
      urlLength: 0.05,
      domainAge: 0.10,
      entropy: 0.08,
      redirectCount: 0.12,
      protocolDowngrade: 0.15,
      certificateValidity: 0.10,
      securityHeaders: 0.08,
      formRisk: 0.12,
      scriptObfuscation: 0.10,
      domainReputation: 0.10
    };

    this.thresholds = {
      malicious: 0.75,
      suspicious: 0.50,
      questionable: 0.30
    };

    this.trainingData = [];
    this.modelVersion = '1.0.0';
  }

  classify(analysisResult) {
    const features = this.extractFeatures(analysisResult);
    const score = this.calculateScore(features);
    const classification = this.determineClassification(score, features);

    return {
      classification: classification,
      confidence: this.calculateConfidence(score, features),
      score: score,
      features: features,
      explanation: this.generateExplanation(classification, features),
      modelVersion: this.modelVersion
    };
  }

  extractFeatures(result) {
    const features = {};

    features.urlLength = this._normalizeUrlLength(result.url);
    features.redirectCount = this._normalizeRedirectCount(result.trace?.totalHops || 0);
    
    if (result.trace?.chain?.[0]) {
      const firstHop = result.trace.chain[0];
      
      features.entropy = this._normalizeEntropy(firstHop.lexical?.entropy || 0);
      features.domainReputation = this._normalizeDomainReputation(firstHop.domainInfo);
      features.certificateValidity = this._normalizeCertificateValidity(firstHop.tlsInfo);
      features.securityHeaders = this._normalizeSecurityHeaders(firstHop.headerFingerprint);
      features.formRisk = this._normalizeFormRisk(firstHop.htmlAnalysis);
      features.scriptObfuscation = this._normalizeScriptObfuscation(firstHop.htmlAnalysis);
    } else {
      features.entropy = 0;
      features.domainReputation = 0;
      features.certificateValidity = 0;
      features.securityHeaders = 0;
      features.formRisk = 0;
      features.scriptObfuscation = 0;
    }

    features.protocolDowngrade = result.security?.risk?.details?.protocolDowngrade ? 1.0 : 0.0;
    
    const lastHop = result.trace?.chain?.[result.trace.chain.length - 1];
    if (lastHop) {
      features.domainAge = this._normalizeDomainAge(lastHop.domainInfo);
    } else {
      features.domainAge = 0;
    }

    return features;
  }

  calculateScore(features) {
    let score = 0;

    for (const [feature, value] of Object.entries(features)) {
      const weight = this.featureWeights[feature] || 0;
      score += value * weight;
    }

    return Math.min(1.0, Math.max(0.0, score));
  }

  determineClassification(score, features) {
    if (score >= this.thresholds.malicious) {
      return 'malicious';
    } else if (score >= this.thresholds.suspicious) {
      return 'suspicious';
    } else if (score >= this.thresholds.questionable) {
      return 'questionable';
    } else {
      return 'benign';
    }
  }

  calculateConfidence(score, features) {
    const featureCount = Object.keys(features).length;
    const nonZeroFeatures = Object.values(features).filter(v => v > 0).length;
    
    const featureCompleteness = nonZeroFeatures / featureCount;
    
    let distanceToThreshold = 0;
    if (score >= this.thresholds.malicious) {
      distanceToThreshold = (score - this.thresholds.malicious) / (1.0 - this.thresholds.malicious);
    } else if (score >= this.thresholds.suspicious) {
      distanceToThreshold = (score - this.thresholds.suspicious) / 
                           (this.thresholds.malicious - this.thresholds.suspicious);
    } else if (score >= this.thresholds.questionable) {
      distanceToThreshold = (score - this.thresholds.questionable) / 
                           (this.thresholds.suspicious - this.thresholds.questionable);
    } else {
      distanceToThreshold = score / this.thresholds.questionable;
    }

    const confidence = (featureCompleteness * 0.4) + (distanceToThreshold * 0.6);
    
    return Math.round(confidence * 100);
  }

  generateExplanation(classification, features) {
    const topFeatures = Object.entries(features)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .filter(([_, value]) => value > 0.3);

    const explanations = [];

    for (const [feature, value] of topFeatures) {
      const weight = this.featureWeights[feature] || 0;
      const contribution = value * weight;
      
      explanations.push({
        feature: this._humanizeFeatureName(feature),
        value: Math.round(value * 100),
        contribution: Math.round(contribution * 100),
        impact: contribution > 0.1 ? 'high' : contribution > 0.05 ? 'medium' : 'low'
      });
    }

    return {
      classification: classification,
      primaryFactors: explanations,
      reasoning: this._generateReasoningText(classification, explanations)
    };
  }

  _normalizeUrlLength(url) {
    const length = url?.length || 0;
    if (length < 50) return 0.0;
    if (length > 200) return 1.0;
    return (length - 50) / 150;
  }

  _normalizeRedirectCount(count) {
    if (count === 0) return 0.0;
    if (count >= 10) return 1.0;
    return count / 10;
  }

  _normalizeEntropy(entropy) {
    if (entropy < 3.0) return 0.0;
    if (entropy > 5.5) return 1.0;
    return (entropy - 3.0) / 2.5;
  }

  _normalizeDomainReputation(domainInfo) {
    if (!domainInfo || !domainInfo.reputation) return 0.5;
    
    let score = 0;
    
    if (domainInfo.reputation.isSuspiciousTLD) score += 0.3;
    if (domainInfo.reputation.hasNumbers) score += 0.1;
    if (domainInfo.reputation.hyphenCount > 2) score += 0.2;
    if (!domainInfo.dnsRecords?.querySuccess) score += 0.4;
    
    return Math.min(1.0, score);
  }

  _normalizeCertificateValidity(tlsInfo) {
    if (!tlsInfo || !tlsInfo.valid) return 0.8;
    if (tlsInfo.isExpired) return 1.0;
    if (tlsInfo.daysRemaining < 7) return 0.7;
    if (tlsInfo.daysRemaining < 30) return 0.3;
    return 0.0;
  }

  _normalizeSecurityHeaders(headerFingerprint) {
    if (!headerFingerprint || !headerFingerprint.security) return 0.5;
    
    const score = headerFingerprint.security.score;
    return 1.0 - (score / 100);
  }

  _normalizeFormRisk(htmlAnalysis) {
    if (!htmlAnalysis || !htmlAnalysis.forms) return 0.0;
    
    let score = 0;
    
    if (htmlAnalysis.forms.hasSensitiveForms) score += 0.4;
    if (htmlAnalysis.forms.externalSubmissions > 0) score += 0.6;
    
    return Math.min(1.0, score);
  }

  _normalizeScriptObfuscation(htmlAnalysis) {
    if (!htmlAnalysis || !htmlAnalysis.scripts) return 0.0;
    
    const obfuscatedRatio = htmlAnalysis.scripts.total > 0
      ? htmlAnalysis.scripts.obfuscated / htmlAnalysis.scripts.total
      : 0;
    
    return obfuscatedRatio;
  }

  _normalizeDomainAge(domainInfo) {
    if (!domainInfo || !domainInfo.ageEstimate) return 0.5;
    
    if (domainInfo.ageEstimate.indicator === 'likely_new') return 0.7;
    if (domainInfo.ageEstimate.indicator === 'likely_mature') return 0.0;
    return 0.5;
  }

  _humanizeFeatureName(feature) {
    const names = {
      urlLength: 'URL Length',
      domainAge: 'Domain Age',
      entropy: 'URL Entropy',
      redirectCount: 'Redirect Count',
      protocolDowngrade: 'Protocol Downgrade',
      certificateValidity: 'Certificate Validity',
      securityHeaders: 'Security Headers',
      formRisk: 'Form Risk',
      scriptObfuscation: 'Script Obfuscation',
      domainReputation: 'Domain Reputation'
    };
    
    return names[feature] || feature;
  }

  _generateReasoningText(classification, factors) {
    if (factors.length === 0) {
      return `Classified as ${classification} with limited feature data.`;
    }

    const topFactor = factors[0];
    let text = `Classified as ${classification}. `;
    
    if (classification === 'malicious') {
      text += `Primary concern: ${topFactor.feature} shows high risk (${topFactor.value}%). `;
    } else if (classification === 'suspicious') {
      text += `${topFactor.feature} raises concerns (${topFactor.value}%). `;
    } else if (classification === 'questionable') {
      text += `${topFactor.feature} shows moderate risk (${topFactor.value}%). `;
    } else {
      text += 'No significant risk indicators detected. ';
    }

    if (factors.length > 1) {
      text += `Additional factors: ${factors.slice(1).map(f => f.feature).join(', ')}.`;
    }

    return text;
  }

  addTrainingData(url, features, label) {
    this.trainingData.push({
      url: url,
      features: features,
      label: label,
      timestamp: Date.now()
    });

    if (this.trainingData.length > 10000) {
      this.trainingData = this.trainingData.slice(-10000);
    }
  }

  exportModel() {
    return {
      version: this.modelVersion,
      weights: this.featureWeights,
      thresholds: this.thresholds,
      trainingDataSize: this.trainingData.length,
      exportedAt: new Date().toISOString()
    };
  }

  importModel(modelData) {
    if (modelData.weights) {
      this.featureWeights = { ...modelData.weights };
    }
    if (modelData.thresholds) {
      this.thresholds = { ...modelData.thresholds };
    }
    if (modelData.version) {
      this.modelVersion = modelData.version;
    }
  }

  adjustWeights(adjustments) {
    for (const [feature, adjustment] of Object.entries(adjustments)) {
      if (this.featureWeights[feature] !== undefined) {
        this.featureWeights[feature] = Math.max(0, Math.min(1, adjustment));
      }
    }

    const totalWeight = Object.values(this.featureWeights).reduce((a, b) => a + b, 0);
    if (totalWeight > 0) {
      for (const feature in this.featureWeights) {
        this.featureWeights[feature] /= totalWeight;
      }
    }
  }

  getFeatureImportance() {
    return Object.entries(this.featureWeights)
      .sort((a, b) => b[1] - a[1])
      .map(([feature, weight]) => ({
        feature: this._humanizeFeatureName(feature),
        weight: Math.round(weight * 100),
        importance: weight > 0.12 ? 'critical' :
                   weight > 0.08 ? 'high' :
                   weight > 0.05 ? 'medium' : 'low'
      }));
  }
}