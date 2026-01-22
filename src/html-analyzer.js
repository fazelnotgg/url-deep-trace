import * as cheerio from 'cheerio';

export class HTMLAnalyzer {
  constructor() {
    this.suspiciousJSPatterns = [
      /eval\(/i,
      /document\.write/i,
      /fromCharCode/i,
      /atob\(/i,
      /btoa\(/i,
      /unescape\(/i,
      /\bexec\(/i,
      /Function\(/i,
      /setTimeout\s*\(/i,
      /setInterval\s*\(/i
    ];

    this.sensitiveFormFields = [
      'password', 'passwd', 'pass', 'pwd',
      'credit', 'card', 'cvv', 'ccv',
      'ssn', 'social', 'security',
      'account', 'routing',
      'pin', 'otp'
    ];
  }

  analyze(html, currentUrl) {
    try {
      const $ = cheerio.load(html);
      
      return {
        structure: this._analyzeStructure($),
        forms: this._analyzeForms($, currentUrl),
        links: this._analyzeLinks($, currentUrl),
        scripts: this._analyzeScripts($),
        iframes: this._analyzeIframes($),
        meta: this._analyzeMeta($),
        images: this._analyzeImages($),
        externalResources: this._analyzeExternalResources($, currentUrl),
        obfuscation: this._detectObfuscation($, html),
        suspiciousElements: this._detectSuspiciousElements($),
        riskScore: 0
      };
    } catch (error) {
      return {
        error: error.message,
        valid: false
      };
    }
  }

  _analyzeStructure($) {
    return {
      title: $('title').text() || '',
      titleLength: $('title').text().length,
      hasTitle: $('title').length > 0,
      totalElements: $('*').length,
      divCount: $('div').length,
      inputCount: $('input').length,
      buttonCount: $('button').length,
      linkCount: $('a').length,
      imageCount: $('img').length,
      scriptCount: $('script').length,
      hasDoctype: /<!doctype/i.test($.html()),
      hasHtml5: /<!doctype html>/i.test($.html())
    };
  }

  _analyzeForms($, currentUrl) {
    const forms = [];
    
    $('form').each((i, elem) => {
      const $form = $(elem);
      const action = $form.attr('action');
      const method = ($form.attr('method') || 'get').toLowerCase();
      
      const inputs = [];
      $form.find('input, textarea, select').each((j, input) => {
        const $input = $(input);
        const type = ($input.attr('type') || 'text').toLowerCase();
        const name = $input.attr('name') || '';
        const id = $input.attr('id') || '';
        
        inputs.push({
          type: type,
          name: name,
          id: id,
          isSensitive: this._isSensitiveField(type, name, id)
        });
      });

      const formAnalysis = {
        action: action,
        method: method,
        hasAction: !!action,
        inputCount: inputs.length,
        inputs: inputs,
        hasSensitiveFields: inputs.some(i => i.isSensitive),
        sensitiveFieldCount: inputs.filter(i => i.isSensitive).length,
        submitsToExternal: action ? this._isExternalUrl(action, currentUrl) : false,
        hasAutoSubmit: this._hasAutoSubmit($form),
        hasHiddenFields: inputs.filter(i => i.type === 'hidden').length,
        missingCSRFProtection: !this._hasCSRFProtection($form)
      };

      forms.push(formAnalysis);
    });

    return {
      count: forms.length,
      forms: forms,
      hasSensitiveForms: forms.some(f => f.hasSensitiveFields),
      externalSubmissions: forms.filter(f => f.submitsToExternal).length
    };
  }

  _analyzeLinks($, currentUrl) {
    const links = [];
    const externalLinks = [];
    const suspiciousLinks = [];

    $('a[href]').each((i, elem) => {
      const href = $(elem).attr('href');
      const text = $(elem).text().trim();
      
      if (!href) return;

      const linkData = {
        href: href,
        text: text,
        isExternal: this._isExternalUrl(href, currentUrl),
        isJavaScript: href.toLowerCase().startsWith('javascript:'),
        isEmpty: href === '#' || href === '',
        hasObfuscation: this._hasLinkObfuscation(href)
      };

      links.push(linkData);

      if (linkData.isExternal) {
        externalLinks.push(linkData);
      }

      if (linkData.isJavaScript || linkData.hasObfuscation) {
        suspiciousLinks.push(linkData);
      }
    });

    return {
      total: links.length,
      external: externalLinks.length,
      suspicious: suspiciousLinks.length,
      externalRatio: links.length > 0 ? Math.round((externalLinks.length / links.length) * 100) : 0,
      links: links.slice(0, 50),
      suspiciousLinks: suspiciousLinks
    };
  }

  _analyzeScripts($) {
    const scripts = [];
    let inlineScriptCount = 0;
    let externalScriptCount = 0;
    let obfuscatedCount = 0;

    $('script').each((i, elem) => {
      const $script = $(elem);
      const src = $script.attr('src');
      const content = $script.html();

      const scriptData = {
        isInline: !src,
        src: src || null,
        contentLength: content ? content.length : 0,
        hasObfuscation: content ? this._detectScriptObfuscation(content) : false
      };

      if (scriptData.isInline) {
        inlineScriptCount++;
      } else {
        externalScriptCount++;
      }

      if (scriptData.hasObfuscation) {
        obfuscatedCount++;
      }

      scripts.push(scriptData);
    });

    return {
      total: scripts.length,
      inline: inlineScriptCount,
      external: externalScriptCount,
      obfuscated: obfuscatedCount,
      scripts: scripts.slice(0, 20)
    };
  }

  _analyzeIframes($) {
    const iframes = [];

    $('iframe').each((i, elem) => {
      const $iframe = $(elem);
      const src = $iframe.attr('src');

      iframes.push({
        src: src || '',
        hasSrc: !!src,
        width: $iframe.attr('width'),
        height: $iframe.attr('height'),
        isHidden: this._isElementHidden($iframe)
      });
    });

    return {
      count: iframes.length,
      hasIframes: iframes.length > 0,
      hiddenIframes: iframes.filter(i => i.isHidden).length,
      iframes: iframes
    };
  }

  _analyzeMeta($) {
    const metaTags = {};

    $('meta').each((i, elem) => {
      const $meta = $(elem);
      const name = $meta.attr('name') || $meta.attr('property');
      const content = $meta.attr('content');

      if (name) {
        metaTags[name] = content;
      }
    });

    return {
      tags: metaTags,
      hasDescription: !!metaTags['description'],
      hasKeywords: !!metaTags['keywords'],
      hasAuthor: !!metaTags['author'],
      hasViewport: !!metaTags['viewport']
    };
  }

  _analyzeImages($) {
    const images = [];
    let externalImageCount = 0;

    $('img').each((i, elem) => {
      const src = $(elem).attr('src');
      const alt = $(elem).attr('alt');

      if (src) {
        const isExternal = src.startsWith('http://') || src.startsWith('https://');
        
        images.push({
          src: src,
          hasAlt: !!alt,
          isExternal: isExternal
        });

        if (isExternal) externalImageCount++;
      }
    });

    return {
      total: images.length,
      external: externalImageCount,
      withoutAlt: images.filter(i => !i.hasAlt).length
    };
  }

  _analyzeExternalResources($, currentUrl) {
    const domains = new Set();

    $('[src], [href]').each((i, elem) => {
      const $elem = $(elem);
      const url = $elem.attr('src') || $elem.attr('href');

      if (url && this._isExternalUrl(url, currentUrl)) {
        try {
          const urlObj = new URL(url, currentUrl);
          domains.add(urlObj.hostname);
        } catch (e) {
          // Invalid URL, skip
        }
      }
    });

    return {
      uniqueDomains: domains.size,
      domains: Array.from(domains)
    };
  }

  _detectObfuscation($, html) {
    const indicators = [];

    if (html.includes('eval(')) indicators.push('eval_usage');
    if (html.includes('fromCharCode')) indicators.push('char_code_encoding');
    if (html.includes('unescape(')) indicators.push('unescape_usage');
    if (/\\x[0-9a-f]{2}/i.test(html)) indicators.push('hex_encoding');
    if (/\\u[0-9a-f]{4}/i.test(html)) indicators.push('unicode_encoding');
    
    const inlineScripts = $('script:not([src])');
    let highEntropyScripts = 0;

    inlineScripts.each((i, elem) => {
      const content = $(elem).html();
      if (content && this._calculateEntropy(content) > 5) {
        highEntropyScripts++;
      }
    });

    if (highEntropyScripts > 0) {
      indicators.push(`high_entropy_scripts_${highEntropyScripts}`);
    }

    return {
      detected: indicators.length > 0,
      count: indicators.length,
      indicators: indicators
    };
  }

  _detectSuspiciousElements($) {
    const suspicious = [];

    const hiddenInputs = $('input[type="hidden"]').length;
    if (hiddenInputs > 5) {
      suspicious.push(`excessive_hidden_inputs_${hiddenInputs}`);
    }

    const popupScripts = $('script').filter((i, elem) => {
      const content = $(elem).html();
      return content && (content.includes('window.open') || content.includes('alert('));
    }).length;

    if (popupScripts > 0) {
      suspicious.push('popup_scripts');
    }

    const autoRedirects = $('script').filter((i, elem) => {
      const content = $(elem).html();
      return content && (content.includes('location.href') || content.includes('location.replace'));
    }).length;

    if (autoRedirects > 0) {
      suspicious.push('auto_redirect_scripts');
    }

    return {
      count: suspicious.length,
      elements: suspicious
    };
  }

  _isSensitiveField(type, name, id) {
    const combined = `${type} ${name} ${id}`.toLowerCase();
    return this.sensitiveFormFields.some(keyword => combined.includes(keyword));
  }

  _hasAutoSubmit($form) {
    const onsubmit = $form.attr('onsubmit');
    const html = $form.html();
    
    return (onsubmit && onsubmit.includes('submit')) || 
           (html && (html.includes('.submit()') || html.includes('autosubmit')));
  }

  _hasCSRFProtection($form) {
    let hasToken = false;

    $form.find('input[type="hidden"]').each((i, elem) => {
      const name = $(elem).attr('name') || '';
      const nameLower = name.toLowerCase();
      
      if (nameLower.includes('csrf') || nameLower.includes('token') || nameLower.includes('_token')) {
        hasToken = true;
        return false;
      }
    });

    return hasToken;
  }

  _isExternalUrl(url, currentUrl) {
    if (!url || url.startsWith('#') || url.startsWith('javascript:') || url.startsWith('data:')) {
      return false;
    }

    try {
      const urlObj = new URL(url, currentUrl);
      const currentUrlObj = new URL(currentUrl);
      return urlObj.hostname !== currentUrlObj.hostname;
    } catch (e) {
      return false;
    }
  }

  _hasLinkObfuscation(href) {
    return href.includes('%') || 
           href.includes('\\x') || 
           href.includes('\\u') ||
           href.length > 200;
  }

  _detectScriptObfuscation(content) {
    for (const pattern of this.suspiciousJSPatterns) {
      if (pattern.test(content)) {
        return true;
      }
    }

    const entropy = this._calculateEntropy(content);
    return entropy > 5.5;
  }

  _isElementHidden($elem) {
    const style = $elem.attr('style') || '';
    const width = $elem.attr('width');
    const height = $elem.attr('height');

    return style.includes('display:none') || 
           style.includes('display: none') ||
           style.includes('visibility:hidden') ||
           style.includes('visibility: hidden') ||
           (width === '0' && height === '0');
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

    return entropy;
  }
}