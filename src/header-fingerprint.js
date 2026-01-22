export class HeaderFingerprint {
  constructor() {
    this.knownServers = {
      nginx: /nginx/i,
      apache: /apache/i,
      iis: /microsoft-iis/i,
      cloudflare: /cloudflare/i,
      aws: /amazons3|aws/i,
      vercel: /vercel/i,
      netlify: /netlify/i
    };

    this.securityHeaders = [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'x-xss-protection',
      'referrer-policy',
      'permissions-policy'
    ];
  }

  analyze(headers) {
    if (!headers || typeof headers !== 'object') {
      return {
        error: 'Invalid headers object',
        valid: false
      };
    }

    const normalizedHeaders = this._normalizeHeaders(headers);

    return {
      server: this._analyzeServer(normalizedHeaders),
      security: this._analyzeSecurityHeaders(normalizedHeaders),
      caching: this._analyzeCaching(normalizedHeaders),
      cookies: this._analyzeCookies(normalizedHeaders),
      cors: this._analyzeCORS(normalizedHeaders),
      encoding: this._analyzeEncoding(normalizedHeaders),
      custom: this._analyzeCustomHeaders(normalizedHeaders),
      anomalies: this._detectAnomalies(normalizedHeaders),
      riskScore: 0,
      timestamp: new Date().toISOString()
    };
  }

  _normalizeHeaders(headers) {
    const normalized = {};
    
    for (const key in headers) {
      normalized[key.toLowerCase()] = headers[key];
    }

    return normalized;
  }

  _analyzeServer(headers) {
    const serverHeader = headers['server'] || '';
    const poweredBy = headers['x-powered-by'] || '';
    
    let identified = 'unknown';
    let technology = [];

    for (const [name, pattern] of Object.entries(this.knownServers)) {
      if (pattern.test(serverHeader) || pattern.test(poweredBy)) {
        identified = name;
        technology.push(name);
      }
    }

    const version = this._extractVersion(serverHeader);

    return {
      raw: serverHeader,
      identified: identified,
      technology: technology,
      version: version,
      poweredBy: poweredBy,
      exposesVersion: !!version,
      headerPresent: !!serverHeader
    };
  }

  _analyzeSecurityHeaders(headers) {
    const present = [];
    const missing = [];
    const configurations = {};

    for (const headerName of this.securityHeaders) {
      if (headers[headerName]) {
        present.push(headerName);
        configurations[headerName] = headers[headerName];
      } else {
        missing.push(headerName);
      }
    }

    const hstsConfig = this._analyzeHSTS(headers['strict-transport-security']);
    const cspConfig = this._analyzeCSP(headers['content-security-policy']);

    return {
      score: Math.round((present.length / this.securityHeaders.length) * 100),
      present: present,
      missing: missing,
      configurations: configurations,
      hsts: hstsConfig,
      csp: cspConfig,
      hasXFrameOptions: !!headers['x-frame-options'],
      hasXContentTypeOptions: !!headers['x-content-type-options']
    };
  }

  _analyzeHSTS(hstsHeader) {
    if (!hstsHeader) {
      return { enabled: false };
    }

    const maxAge = hstsHeader.match(/max-age=(\d+)/i);
    const includeSubDomains = /includesubdomains/i.test(hstsHeader);
    const preload = /preload/i.test(hstsHeader);

    return {
      enabled: true,
      maxAge: maxAge ? parseInt(maxAge[1], 10) : 0,
      includeSubDomains: includeSubDomains,
      preload: preload,
      isStrong: maxAge && parseInt(maxAge[1], 10) >= 31536000
    };
  }

  _analyzeCSP(cspHeader) {
    if (!cspHeader) {
      return { enabled: false };
    }

    const directives = cspHeader.split(';').map(d => d.trim());
    const hasDefaultSrc = directives.some(d => d.startsWith('default-src'));
    const hasScriptSrc = directives.some(d => d.startsWith('script-src'));
    const hasUnsafeInline = /unsafe-inline/i.test(cspHeader);
    const hasUnsafeEval = /unsafe-eval/i.test(cspHeader);

    return {
      enabled: true,
      directiveCount: directives.length,
      hasDefaultSrc: hasDefaultSrc,
      hasScriptSrc: hasScriptSrc,
      hasUnsafeInline: hasUnsafeInline,
      hasUnsafeEval: hasUnsafeEval,
      isStrict: hasScriptSrc && !hasUnsafeInline && !hasUnsafeEval
    };
  }

  _analyzeCaching(headers) {
    const cacheControl = headers['cache-control'] || '';
    const expires = headers['expires'] || '';
    const etag = headers['etag'] || '';
    const lastModified = headers['last-modified'] || '';

    return {
      cacheControl: cacheControl,
      expires: expires,
      hasETag: !!etag,
      hasLastModified: !!lastModified,
      isNoCache: /no-cache|no-store/i.test(cacheControl),
      maxAge: this._extractMaxAge(cacheControl)
    };
  }

  _analyzeCookies(headers) {
    const setCookie = headers['set-cookie'];
    
    if (!setCookie) {
      return {
        present: false,
        count: 0
      };
    }

    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    const analysis = [];

    for (const cookie of cookies) {
      const hasSecure = /;\s*secure/i.test(cookie);
      const hasHttpOnly = /;\s*httponly/i.test(cookie);
      const hasSameSite = /;\s*samesite/i.test(cookie);
      
      const name = cookie.split('=')[0].trim();

      analysis.push({
        name: name,
        hasSecure: hasSecure,
        hasHttpOnly: hasHttpOnly,
        hasSameSite: hasSameSite,
        isSecure: hasSecure && hasHttpOnly && hasSameSite
      });
    }

    return {
      present: true,
      count: cookies.length,
      cookies: analysis,
      allSecure: analysis.every(c => c.isSecure),
      insecureCount: analysis.filter(c => !c.isSecure).length
    };
  }

  _analyzeCORS(headers) {
    const acao = headers['access-control-allow-origin'];
    const acam = headers['access-control-allow-methods'];
    const acah = headers['access-control-allow-headers'];
    const acac = headers['access-control-allow-credentials'];

    return {
      enabled: !!acao,
      allowOrigin: acao || null,
      allowMethods: acam || null,
      allowHeaders: acah || null,
      allowCredentials: acac === 'true',
      isWildcard: acao === '*',
      isInsecure: acao === '*' && acac === 'true'
    };
  }

  _analyzeEncoding(headers) {
    const contentType = headers['content-type'] || '';
    const contentEncoding = headers['content-encoding'] || '';
    const transferEncoding = headers['transfer-encoding'] || '';

    return {
      contentType: contentType,
      charset: this._extractCharset(contentType),
      contentEncoding: contentEncoding,
      transferEncoding: transferEncoding,
      isCompressed: !!(contentEncoding && /gzip|deflate|br/i.test(contentEncoding))
    };
  }

  _analyzeCustomHeaders(headers) {
    const customHeaders = [];
    const knownHeaders = new Set([
      'date', 'server', 'content-type', 'content-length', 'connection',
      'cache-control', 'expires', 'etag', 'last-modified', 'set-cookie',
      'location', 'vary', 'age', 'via', 'pragma', 'accept-ranges',
      ...this.securityHeaders,
      'access-control-allow-origin', 'access-control-allow-methods',
      'access-control-allow-headers', 'access-control-allow-credentials'
    ]);

    for (const key in headers) {
      if (!knownHeaders.has(key) && !key.startsWith('x-')) {
        customHeaders.push(key);
      }
    }

    const xHeaders = Object.keys(headers).filter(k => k.startsWith('x-'));

    return {
      count: customHeaders.length,
      headers: customHeaders,
      xHeaders: xHeaders,
      xHeaderCount: xHeaders.length
    };
  }

  _detectAnomalies(headers) {
    const anomalies = [];

    if (headers['server'] && headers['server'].length > 100) {
      anomalies.push('unusually_long_server_header');
    }

    if (!headers['content-type']) {
      anomalies.push('missing_content_type');
    }

    const setCookie = headers['set-cookie'];
    if (setCookie) {
      const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
      if (cookies.length > 10) {
        anomalies.push('excessive_cookies');
      }
    }

    if (headers['x-powered-by']) {
      anomalies.push('exposes_technology_stack');
    }

    const totalHeaders = Object.keys(headers).length;
    if (totalHeaders < 5) {
      anomalies.push('minimal_headers');
    } else if (totalHeaders > 30) {
      anomalies.push('excessive_headers');
    }

    return {
      count: anomalies.length,
      detected: anomalies
    };
  }

  _extractVersion(serverHeader) {
    if (!serverHeader) return null;
    
    const versionMatch = serverHeader.match(/\/(\d+\.\d+(?:\.\d+)?)/);
    return versionMatch ? versionMatch[1] : null;
  }

  _extractMaxAge(cacheControl) {
    if (!cacheControl) return null;
    
    const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
    return maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;
  }

  _extractCharset(contentType) {
    if (!contentType) return null;
    
    const charsetMatch = contentType.match(/charset=([^;]+)/i);
    return charsetMatch ? charsetMatch[1].trim() : null;
  }
}