import axios from 'axios';
import { CookieJar } from 'tough-cookie';
import * as cheerio from 'cheerio';
import { URL } from 'url';
import { TLSInspector } from './tls-inspector.js';
import { LexicalAnalyzer } from './lexical-analyzer.js';
import { HTMLAnalyzer } from './html-analyzer.js';
import { DomainIntelligence } from './domain-intelligence.js';
import { HeaderFingerprint } from './header-fingerprint.js';
import { BehavioralAnalyzer } from './behavioral-analyzer.js';

export class URLTracer {
  constructor(options = {}) {
    this.maxHops = options.maxHops || 20;
    this.timeout = options.timeout || 15000;
    this.userAgent = options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
    this.tlsInspector = new TLSInspector(this.timeout);
    this.lexicalAnalyzer = new LexicalAnalyzer();
    this.htmlAnalyzer = new HTMLAnalyzer();
    this.domainIntelligence = new DomainIntelligence();
    this.headerFingerprint = new HeaderFingerprint();
    this.behavioralAnalyzer = new BehavioralAnalyzer();
    this.enableDeepAnalysis = options.enableDeepAnalysis !== false;
  }

  async trace(initialUrl) {
    const chain = [];
    const visitedUrls = new Set();
    const cookieJar = new CookieJar();
    
    let currentUrl = initialUrl;
    let hopCount = 0;

    try {
      while (hopCount < this.maxHops) {
        if (visitedUrls.has(currentUrl)) {
          chain.push({
            url: currentUrl,
            error: 'Circular redirect detected',
            type: 'error',
            timestamp: new Date().toISOString()
          });
          break;
        }

        visitedUrls.add(currentUrl);
        
        const hopResult = await this._executeHop(currentUrl, cookieJar);
        chain.push(hopResult);

        if (hopResult.error || hopResult.type === 'final') {
          break;
        }

        if (hopResult.nextUrl) {
          currentUrl = hopResult.nextUrl;
          hopCount++;
        } else {
          break;
        }
      }

      if (hopCount >= this.maxHops) {
        chain.push({
          error: 'Maximum hop limit reached',
          type: 'error',
          timestamp: new Date().toISOString()
        });
      }

      return {
        success: true,
        totalHops: chain.length,
        chain: chain,
        finalUrl: chain[chain.length - 1]?.url || currentUrl,
        behavioral: this._analyzeBehavior(chain)
      };

    } catch (error) {
      console.error('Tracer error:', error.message);
      return {
        success: false,
        error: error.message,
        totalHops: chain.length,
        chain: chain,
        finalUrl: currentUrl,
        behavioral: null
      };
    }
  }

  _analyzeBehavior(chain) {
    if (!this.enableDeepAnalysis || chain.length === 0) {
      return null;
    }

    try {
      return this.behavioralAnalyzer.analyze(chain);
    } catch (error) {
      console.error('Behavioral analysis error:', error.message);
      return null;
    }
  }

  async _executeHop(url, cookieJar) {
    const timestamp = new Date().toISOString();
    const hopData = {
      url: url,
      timestamp: timestamp,
      protocol: null,
      statusCode: null,
      headers: {},
      tlsInfo: null,
      redirectType: null,
      nextUrl: null,
      type: 'intermediate',
      timing: {},
      lexical: null,
      headerFingerprint: null,
      htmlAnalysis: null,
      domainInfo: null
    };

    try {
      const parsedUrl = new URL(url);
      hopData.protocol = parsedUrl.protocol.replace(':', '');

      if (this.enableDeepAnalysis) {
        const lexicalStart = Date.now();
        hopData.lexical = this.lexicalAnalyzer.analyze(url);
        hopData.timing.lexicalAnalysis = Date.now() - lexicalStart;
      }

      if (parsedUrl.protocol === 'https:') {
        const tlsStart = Date.now();
        hopData.tlsInfo = await this.tlsInspector.inspect(url);
        hopData.timing.tlsInspection = Date.now() - tlsStart;
      }

      if (this.enableDeepAnalysis) {
        const domainStart = Date.now();
        hopData.domainInfo = await this.domainIntelligence.analyze(parsedUrl.hostname);
        hopData.timing.domainAnalysis = Date.now() - domainStart;
      }

      const cookies = await cookieJar.getCookieString(url);
      
      const requestStart = Date.now();
      const response = await axios({
        method: 'GET',
        url: url,
        maxRedirects: 0,
        validateStatus: () => true,
        timeout: this.timeout,
        headers: {
          'User-Agent': this.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate',
          'Connection': 'keep-alive',
          'Upgrade-Insecure-Requests': '1',
          ...(cookies ? { 'Cookie': cookies } : {})
        }
      });

      hopData.timing.httpRequest = Date.now() - requestStart;
      hopData.statusCode = response.status;
      hopData.headers = response.headers;

      if (this.enableDeepAnalysis) {
        const headerStart = Date.now();
        hopData.headerFingerprint = this.headerFingerprint.analyze(response.headers);
        hopData.timing.headerAnalysis = Date.now() - headerStart;
      }

      if (response.headers['set-cookie']) {
        const setCookieArray = Array.isArray(response.headers['set-cookie']) 
          ? response.headers['set-cookie'] 
          : [response.headers['set-cookie']];
        
        for (const cookieStr of setCookieArray) {
          await cookieJar.setCookie(cookieStr, url);
        }
      }

      if (response.status >= 300 && response.status < 400) {
        hopData.redirectType = 'http';
        hopData.nextUrl = this._resolveUrl(url, response.headers.location);
        hopData.type = 'redirect';
      } else if (response.status === 200 && response.headers['content-type']?.includes('text/html')) {
        const htmlData = response.data;

        if (this.enableDeepAnalysis && htmlData) {
          const htmlStart = Date.now();
          hopData.htmlAnalysis = this.htmlAnalyzer.analyze(htmlData, url);
          hopData.timing.htmlAnalysis = Date.now() - htmlStart;
        }

        const metaRefreshUrl = this._detectMetaRefresh(htmlData, url);
        const jsRedirectUrl = this.enableDeepAnalysis ? this._detectJSRedirect(htmlData, url) : null;
        
        if (metaRefreshUrl) {
          hopData.redirectType = 'meta-refresh';
          hopData.nextUrl = metaRefreshUrl;
          hopData.type = 'redirect';
        } else if (jsRedirectUrl) {
          hopData.redirectType = 'javascript';
          hopData.nextUrl = jsRedirectUrl;
          hopData.type = 'redirect';
        } else {
          hopData.type = 'final';
        }
      } else {
        hopData.type = 'final';
      }

      return hopData;

    } catch (error) {
      hopData.error = error.message;
      hopData.type = 'error';
      
      if (error.code === 'ECONNABORTED') {
        hopData.error = 'Request timeout';
      } else if (error.code === 'ENOTFOUND') {
        hopData.error = 'DNS resolution failed';
      } else if (error.code === 'ECONNREFUSED') {
        hopData.error = 'Connection refused';
      }

      return hopData;
    }
  }

  _detectMetaRefresh(html, baseUrl) {
    try {
      const $ = cheerio.load(html);
      const metaTags = $('meta[http-equiv]');

      for (let i = 0; i < metaTags.length; i++) {
        const tag = metaTags[i];
        const httpEquiv = $(tag).attr('http-equiv');
        
        if (httpEquiv && httpEquiv.toLowerCase() === 'refresh') {
          const content = $(tag).attr('content');
          
          if (content) {
            const urlMatch = content.match(/url\s*=\s*['"]?([^'">\s]+)/i);
            
            if (urlMatch && urlMatch[1]) {
              return this._resolveUrl(baseUrl, urlMatch[1]);
            }
          }
        }
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  _detectJSRedirect(html, baseUrl) {
    try {
      const locationHrefMatch = html.match(/location\.href\s*=\s*['"](https?:\/\/[^'"]+)['"]/i);
      if (locationHrefMatch) {
        return this._resolveUrl(baseUrl, locationHrefMatch[1]);
      }

      const locationReplaceMatch = html.match(/location\.replace\s*\(\s*['"](https?:\/\/[^'"]+)['"]\s*\)/i);
      if (locationReplaceMatch) {
        return this._resolveUrl(baseUrl, locationReplaceMatch[1]);
      }

      const windowLocationMatch = html.match(/window\.location\s*=\s*['"](https?:\/\/[^'"]+)['"]/i);
      if (windowLocationMatch) {
        return this._resolveUrl(baseUrl, windowLocationMatch[1]);
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  _resolveUrl(base, relative) {
    try {
      if (!relative) return null;
      
      relative = relative.trim();
      
      if (relative.startsWith('http://') || relative.startsWith('https://')) {
        return relative;
      }

      const baseUrl = new URL(base);
      return new URL(relative, baseUrl).href;
    } catch (error) {
      return null;
    }
  }
}