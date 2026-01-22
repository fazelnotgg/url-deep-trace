import { URL } from 'url';

export class LexicalAnalyzer {
  constructor() {
    this.suspiciousPatterns = [
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
      /@/,
      /-{2,}/,
      /_{2,}/,
      /\.{2,}/,
      /0x[0-9a-f]+/i,
      /%[0-9a-f]{2}/i
    ];

    this.homoglyphChars = {
      'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
      'ѕ': 's', 'һ': 'h', 'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ԁ': 'd', 'ԍ': 'g'
    };
  }

  analyze(urlString) {
    try {
      const parsedUrl = new URL(urlString);
      
      let hostname, path, query, protocol, entropy, specialChars, suspiciousPatterns;
      let homoglyphDetection, punycode, portAnalysis;
      
      try {
        hostname = this._analyzeHostname(parsedUrl.hostname);
      } catch (e) {
        console.error('Error in _analyzeHostname:', e.message);
        hostname = { full: '', tld: '', sld: '', subdomainCount: 0, subdomains: [], length: 0 };
      }
      
      try {
        path = this._analyzePath(parsedUrl.pathname);
      } catch (e) {
        console.error('Error in _analyzePath:', e.message);
        path = { full: '/', depth: 0, length: 1, segments: [], suspiciousExtensions: [] };
      }
      
      try {
        query = this._analyzeQuery(parsedUrl.search);
      } catch (e) {
        console.error('Error in _analyzeQuery:', e.message);
        query = { exists: false, parameters: 0 };
      }
      
      try {
        protocol = parsedUrl.protocol.replace(':', '');
      } catch (e) {
        console.error('Error in protocol:', e.message);
        protocol = 'unknown';
      }
      
      try {
        entropy = this._calculateEntropy(urlString);
      } catch (e) {
        console.error('Error in _calculateEntropy:', e.message);
        entropy = 0;
      }
      
      try {
        specialChars = this._countSpecialCharacters(urlString);
      } catch (e) {
        console.error('Error in _countSpecialCharacters:', e.message);
        specialChars = {};
      }
      
      try {
        suspiciousPatterns = this._detectSuspiciousPatterns(urlString);
      } catch (e) {
        console.error('Error in _detectSuspiciousPatterns:', e.message);
        suspiciousPatterns = [];
      }
      
      try {
        homoglyphDetection = this._detectHomoglyphs(parsedUrl.hostname);
      } catch (e) {
        console.error('Error in _detectHomoglyphs:', e.message);
        homoglyphDetection = { hasHomoglyphs: false, count: 0, characters: [] };
      }
      
      try {
        punycode = this._detectPunycode(parsedUrl.hostname);
      } catch (e) {
        console.error('Error in _detectPunycode:', e.message);
        punycode = { detected: false };
      }
      
      try {
        portAnalysis = this._analyzePort(parsedUrl.port);
      } catch (e) {
        console.error('Error in _analyzePort:', e.message);
        portAnalysis = { specified: false, standard: true };
      }
      
      const features = {
        length: urlString.length,
        hostname: hostname,
        path: path,
        query: query,
        protocol: protocol,
        entropy: entropy,
        specialChars: specialChars,
        suspiciousPatterns: suspiciousPatterns,
        homoglyphDetection: homoglyphDetection,
        punycode: punycode,
        portAnalysis: portAnalysis
      };

      try {
        features.riskScore = this._calculateLexicalRisk(features);
      } catch (e) {
        console.error('Error in _calculateLexicalRisk:', e.message);
        features.riskScore = 0;
      }

      return features;
    } catch (error) {
      console.error('Lexical Analyzer Error:', error.message);
      console.error('Stack:', error.stack);
      return {
        error: error.message,
        valid: false,
        length: 0,
        entropy: 0,
        riskScore: 0,
        hostname: {},
        path: {},
        query: { exists: false },
        specialChars: {},
        suspiciousPatterns: [],
        homoglyphDetection: { hasHomoglyphs: false, count: 0, characters: [] },
        punycode: { detected: false },
        portAnalysis: { specified: false }
      };
    }
  }

  _analyzeHostname(hostname) {
    if (!hostname) {
      return {
        full: '',
        tld: '',
        sld: '',
        subdomainCount: 0,
        subdomains: [],
        length: 0,
        digitCount: 0,
        hyphenCount: 0,
        hasIPAddress: false,
        veryLongSubdomain: false
      };
    }

    const parts = hostname.split('.');
    const subdomains = parts.length > 2 ? parts.slice(0, -2) : [];
    
    return {
      full: hostname,
      tld: parts[parts.length - 1] || '',
      sld: parts.length > 1 ? parts[parts.length - 2] : '',
      subdomainCount: subdomains.length,
      subdomains: subdomains,
      length: hostname.length,
      digitCount: (hostname.match(/\d/g) || []).length,
      hyphenCount: (hostname.match(/-/g) || []).length,
      hasIPAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname),
      veryLongSubdomain: subdomains.some(s => s && s.length > 20)
    };
  }

  _analyzePath(pathname) {
    if (!pathname) {
      return {
        full: '/',
        depth: 0,
        length: 1,
        segments: [],
        hasDoubleSlash: false,
        encodedChars: 0,
        suspiciousExtensions: [],
        obfuscationIndicators: []
      };
    }

    const segments = pathname.split('/').filter(s => s.length > 0);
    
    return {
      full: pathname,
      depth: segments.length,
      length: pathname.length,
      segments: segments,
      hasDoubleSlash: pathname.includes('//'),
      encodedChars: (pathname.match(/%[0-9a-f]{2}/gi) || []).length,
      suspiciousExtensions: this._detectSuspiciousExtensions(pathname),
      obfuscationIndicators: this._detectObfuscation(pathname)
    };
  }

  _analyzeQuery(search) {
    if (!search || search === '?') {
      return { exists: false, parameters: 0 };
    }

    const params = new URLSearchParams(search);
    const paramArray = Array.from(params.entries());

    return {
      exists: true,
      full: search,
      parameters: paramArray.length,
      length: search.length,
      hasRedirect: this._hasRedirectParameter(paramArray),
      encodedChars: (search.match(/%[0-9a-f]{2}/gi) || []).length,
      suspiciousKeywords: this._detectSuspiciousQueryKeywords(search)
    };
  }

  _detectSuspiciousExtensions(path) {
    const suspiciousExts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.apk', '.dmg', '.app'];
    return suspiciousExts.filter(ext => path.toLowerCase().endsWith(ext));
  }

  _detectObfuscation(text) {
    const indicators = [];
    
    if ((text.match(/%[0-9a-f]{2}/gi) || []).length > 5) {
      indicators.push('excessive_encoding');
    }
    
    if (/[^\x00-\x7F]/.test(text)) {
      indicators.push('non_ascii_chars');
    }
    
    if (text.includes('..')) {
      indicators.push('directory_traversal');
    }
    
    if (/\x00/.test(text)) {
      indicators.push('null_byte');
    }

    return indicators;
  }

  _hasRedirectParameter(params) {
    const redirectKeywords = ['redirect', 'url', 'return', 'returnurl', 'next', 'goto', 'target', 'redir', 'dest', 'destination', 'continue'];
    
    for (const [key] of params) {
      const keyLower = key.toLowerCase();
      if (redirectKeywords.some(keyword => keyLower.includes(keyword))) {
        return true;
      }
    }
    
    return false;
  }

  _detectSuspiciousQueryKeywords(query) {
    const keywords = ['login', 'signin', 'password', 'passwd', 'pass', 'account', 'verify', 'update', 'secure', 'banking', 'paypal', 'amazon'];
    const lowerQuery = query.toLowerCase();
    
    const found = [];
    for (const keyword of keywords) {
      if (lowerQuery.includes(keyword)) {
        found.push(keyword);
      }
    }
    
    return found;
  }

  _calculateEntropy(str) {
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;

    for (const char in freq) {
      const probability = freq[char] / len;
      entropy -= probability * Math.log2(probability);
    }

    return Math.round(entropy * 100) / 100;
  }

  _countSpecialCharacters(str) {
    return {
      dots: (str.match(/\./g) || []).length,
      hyphens: (str.match(/-/g) || []).length,
      underscores: (str.match(/_/g) || []).length,
      slashes: (str.match(/\//g) || []).length,
      atSigns: (str.match(/@/g) || []).length,
      digits: (str.match(/\d/g) || []).length,
      total: str.replace(/[a-zA-Z0-9]/g, '').length
    };
  }

  _detectSuspiciousPatterns(url) {
    const matches = [];
    
    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(url)) {
        matches.push(pattern.toString());
      }
    }

    return matches;
  }

  _detectHomoglyphs(hostname) {
    const detected = [];
    
    for (const char of hostname) {
      if (this.homoglyphChars[char]) {
        detected.push({
          char: char,
          normalizedTo: this.homoglyphChars[char]
        });
      }
    }

    return {
      hasHomoglyphs: detected.length > 0,
      count: detected.length,
      characters: detected
    };
  }

  _detectPunycode(hostname) {
    const hasPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
    
    return {
      detected: hasPunycode,
      originalHostname: hostname
    };
  }

  _analyzePort(port) {
    if (!port) {
      return { specified: false, standard: true };
    }

    const portNum = parseInt(port, 10);
    const commonPorts = [80, 443, 8080, 8443];
    const suspiciousPorts = [4444, 5555, 6666, 7777, 8888, 9999];

    return {
      specified: true,
      port: portNum,
      isCommon: commonPorts.includes(portNum),
      isSuspicious: suspiciousPorts.includes(portNum),
      isHighPort: portNum > 49152
    };
  }

  _calculateLexicalRisk(features) {
    let score = 0;

    if (features.length > 100) score += 5;
    if (features.length > 200) score += 10;
    
    if (features.hostname && features.hostname.hasIPAddress) score += 15;
    if (features.hostname && features.hostname.subdomainCount > 3) score += 8;
    if (features.hostname && features.hostname.hyphenCount > 2) score += 5;
    if (features.hostname && features.hostname.digitCount > 5) score += 7;
    
    if (features.path && features.path.depth > 5) score += 6;
    if (features.path && features.path.encodedChars > 5) score += 8;
    if (features.path && features.path.suspiciousExtensions && features.path.suspiciousExtensions.length > 0) score += 12;
    if (features.path && features.path.obfuscationIndicators && features.path.obfuscationIndicators.length > 0) score += 10;
    
    if (features.query && features.query.hasRedirect) score += 10;
    if (features.query && features.query.suspiciousKeywords && features.query.suspiciousKeywords.length > 0) score += 8;
    if (features.query && features.query.encodedChars > 10) score += 7;
    
    if (features.entropy > 4.5) score += 6;
    
    if (features.suspiciousPatterns && features.suspiciousPatterns.length > 2) score += 10;
    
    if (features.homoglyphDetection && features.homoglyphDetection.hasHomoglyphs) score += 20;
    if (features.punycode && features.punycode.detected) score += 12;
    
    if (features.portAnalysis && features.portAnalysis.isSuspicious) score += 15;
    if (features.portAnalysis && features.portAnalysis.isHighPort) score += 8;

    return Math.min(score, 100);
  }
}