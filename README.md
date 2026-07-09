# @fazelstudio/url-deep-trace

[![npm version](https://img.shields.io/npm/v/@fazelstudio/url-deep-trace.svg)](https://www.npmjs.com/package/@fazelstudio/url-deep-trace) [![CI](https://github.com/fazelllyyy/url-deep-trace/actions/workflows/ci.yml/badge.svg)](https://github.com/fazelllyyy/url-deep-trace/actions/workflows/ci.yml) [![License](https://img.shields.io/npm/l/@fazelstudio/url-deep-trace.svg)](https://opensource.org/licenses/MIT)

Enterprise-grade URL tracing engine with SSL forensics, threat intelligence, ML classification, and heuristic risk scoring. Designed for SOC operations, API security services, and penetration testing workflows.

> **Note:** This library performs read-only, non-invasive analysis. It does not bypass authentication or paywalls.

## Features

### Core Tracing
- **Redirect Chain Tracing** — manual HTTP 3xx handling with cookie jar management
- **Meta Refresh Detection** — parses HTML for `<meta http-equiv="refresh">`
- **JavaScript Redirect Detection** — identifies `location.href`, `location.replace`, `window.location`
- **Deep SSL/TLS Forensics** — parallel socket-level certificate inspection with expiry tracking

### Analysis Modules

| Module | Description |
|--------|-------------|
| **Lexical Analyzer** | URL entropy, subdomain analysis, homoglyph/punycode detection, port analysis |
| **HTML Analyzer** | Form analysis, script obfuscation, iframe inspection, external resource tracking |
| **Domain Intelligence** | DNS records (A, AAAA, MX, TXT, SPF, DMARC), TLD reputation, domain age estimation |
| **Header Fingerprint** | Security header audit (HSTS, CSP, XFO, etc.), cookie security, CORS analysis |
| **Behavioral Analyzer** | Redirect patterns, domain hopping, protocol switching, cloaking detection |
| **Threat Intelligence** | Phishing, malware, SQLi/XSS detection, brand impersonation, IOC extraction |
| **ML Classifier** | Feature extraction, weighted scoring (benign → malicious), explainable AI |
| **Reputation Cache** | SHA-256 URL indexing, LRU eviction, TTL-based expiration, blacklist/whitelist |
| **Performance Manager** | Batch processing, rate limiting, exponential backoff retry |
| **Webhook Notifier** | Conditional alerts (high risk, malicious), retry mechanism, batch notifications |
| **Rate Limiter** | Sliding window algorithm, per-domain limits, queue management |
| **Reporting Engine** | JSON/CSV export, executive/technical/compliance/incident reports |

### Risk Scoring

Multi-factor heuristic scoring (0–100):

| Factor | Points |
|--------|--------|
| Excessive redirects (>5 hops) | +5–30 |
| Protocol downgrade (HTTPS → HTTP) | +35 |
| Certificate issues | +15–30 |
| Suspicious TLD (.xyz, .top, etc.) | +12/domain |
| Meta refresh / JS redirects | +10–12 |
| Circular redirects | +20 |
| HTML obfuscation | +10–25 |
| Phishing indicators | +10–25 |
| Malware indicators | +15–30 |

**Risk levels:** `minimal` (0–29), `low` (30–59), `medium` (60–79), `high` (80–100)

## Installation

```bash
npm install @fazelstudio/url-deep-trace
```

Optional dependencies for screenshot capture:

```bash
npm install playwright
# or
npm install puppeteer
```

## Quick Start

```javascript
import URLDeepTrace from '@fazelstudio/url-deep-trace';

const tracer = new URLDeepTrace({
  maxHops: 20,
  timeout: 15000,
  enableDeepAnalysis: true,
  enableThreatIntel: true,
  enableMLClassification: true,
});

const result = await tracer.analyze('https://example.com');

console.log('Risk Score:', result.security.risk.score);       // 15
console.log('Risk Level:', result.security.risk.level);      // "minimal"
console.log('ML Class:', result.mlClassification.classification);
```

## API Reference

### `URLDeepTrace(options?)`

| Option | Type | Default | Description |
|--------|------|--------|-------------|
| `maxHops` | `number` | `20` | Maximum redirect hops |
| `timeout` | `number` | `15000` | Request timeout (ms) |
| `userAgent` | `string` | preset | Custom user agent |
| `enableDeepAnalysis` | `boolean` | `true` | Enable lexical, domain, header, HTML, TLS |
| `enableThreatIntel` | `boolean` | `true` | Enable threat intelligence |
| `enableMLClassification` | `boolean` | `true` | Enable ML classifier |
| `maxConcurrent` | `number` | `5` | Concurrent analysis limit |
| `retryAttempts` | `number` | `2` | Retry attempts on failure |
| `retryDelay` | `number` | `1000` | Delay (ms) between retries |

### Methods

| Method | Description |
|--------|-------------|
| `analyze(url)` | Analyze a single URL with full forensics |
| `analyzeMultiple(urls)` | Analyze multiple URLs concurrently |
| `analyzeMultipleParallel(urls, options)` | Analyze URLs in controlled batches |
| `exportResults(results, format, options)` | Export results as JSON or CSV |

### Response Structure

```javascript
{
  success: true,
  url: "https://example.com",
  finalDestination: "https://example.com",
  trace: {
    totalHops: 1,
    chain: [{
      url: "https://example.com",
      statusCode: 200,
      protocol: "https",
      tlsInfo: { ... },
      lexical: { ... },
      domainInfo: { ... },
      headerFingerprint: { ... },
      htmlAnalysis: { ... },
      timing: { ... }
    }]
  },
  security: {
    risk: { score: 15, level: "minimal", factors: [...], details: { ... } }
  },
  metadata: {
    analyzedAt: "2026-01-21T10:30:00.000Z",
    executionTime: 2345
  }
}
```

## Architecture

```
src/
├── index.js                 # Main entry point
├── tracer.js                # Recursive URL tracer
├── tls-inspector.js         # SSL/TLS forensics
├── lexical-analyzer.js      # URL pattern analysis
├── html-analyzer.js         # HTML structure inspection
├── domain-intelligence.js   # DNS and domain analysis
├── header-fingerprint.js    # HTTP header security audit
├── risk-engine.js           # Security risk scoring
├── performance-manager.js      # Batch processing & export
├── behavioral-analyzer.js  # Redirect behavior analysis
├── threat-intelligence.js  # Phishing, malware detection
├── ml-classifier.js        # ML classification engine
├── reputation-cache.js     # LRU cache with blacklist
├── rate-limiter.js         # Sliding window rate limiter
├── webhook-notifier.js      # Conditional alerting
├── reporting-engine.js      # Multi-format report generator
├── screenshot-capture.js   # Browser screenshot (optional)
```

## Development

```bash
# Install
npm install

# Run tests
npm test
npm run test:all
npm run test:optimization

# Start API server
npm run server

# Lint & format
npm run lint
npm run format
```

## License

MIT &mdash; &copy; 2026 [Fazel](https://github.com/fazelllyyy)