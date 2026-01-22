# url-deep-trace

Enterprise-grade URL tracing engine with comprehensive security forensics, threat intelligence, machine learning classification, and compliance reporting. Designed for internal API services, SOC operations, and network security analysis.

## 🚀 Features

### Core Capabilities
- **Manual Redirect Tracing** - Handles HTTP 3xx codes manually with cookie jar management
- **Meta Refresh Detection** - Parses HTML to detect `<meta http-equiv="refresh">` redirects
- **JavaScript Redirect Detection** - Identifies location.href, location.replace, and window.location patterns
- **Deep SSL/TLS Forensics** - Parallel socket-level certificate inspection with expiry tracking
- **Heuristic Risk Scoring** - Multi-factor security assessment algorithm (0-100 scale)

### Advanced Analysis Modules

#### 1. Lexical Analyzer
Extracts URL characteristics and patterns:
- URL length, entropy calculation, special character analysis
- Subdomain count and structure analysis
- Suspicious pattern detection (IP addresses, encoding, obfuscation)
- Homoglyph and punycode detection (IDN attacks)
- Port analysis (suspicious/high ports)
- Query parameter risk assessment

#### 2. HTML Analyzer
Deep HTML structure inspection:
- Form analysis (sensitive fields, CSRF protection, auto-submit detection)
- Script obfuscation detection (eval, fromCharCode, atob patterns)
- Iframe analysis (hidden elements, external sources)
- External resource enumeration and domain tracking
- Link analysis (external vs internal ratio)
- Meta tag and content evolution inspection

#### 3. Domain Intelligence
DNS and domain reputation:
- DNS record queries (A, AAAA, MX, TXT, SPF, DMARC)
- TLD reputation assessment (suspicious vs trusted)
- Domain age estimation (heuristic-based)
- Structure analysis (labels, subdomains, patterns)
- DNS health verification

#### 4. Header Fingerprint
HTTP header security analysis:
- Server identification and version detection
- Security header coverage (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy)
- Cookie security (Secure, HttpOnly, SameSite flags)
- CORS configuration analysis
- Caching behavior assessment
- Anomaly detection

#### 5. Behavioral Analyzer
Pattern recognition and behavior analysis:
- Redirect behavior patterns (simple, chain, complex, obfuscated)
- Domain hopping detection and analysis
- Protocol switching behavior (upgrades/downgrades)
- Cookie manipulation tracking
- Timing analysis and anomaly detection
- Content evolution tracking
- Trust chain assessment
- Cloaking detection

#### 6. Threat Intelligence
Comprehensive threat detection:
- Phishing indicator detection (keywords, forms, brand impersonation)
- Malware risk assessment (file extensions, obfuscation, hidden iframes)
- Attack vector detection (SQLi, XSS, path traversal, command injection)
- Brand impersonation identification
- Scam pattern recognition (crypto, tech support, prize scams)
- Data exfiltration risk assessment
- IOC extraction (domains, IPs, URLs, certificate hashes)
- Threat report generation

#### 7. ML Classifier
Machine learning-based classification:
- Feature extraction (10+ security features)
- Score calculation with weighted features
- Classification (benign, questionable, suspicious, malicious)
- Confidence scoring
- Explainable AI (primary factors, reasoning)
- Model export/import capabilities
- Feature importance analysis
- Training data management

#### 8. Reputation Cache
High-performance caching system:
- SHA-256 hash-based URL indexing
- Blacklist/whitelist management
- LRU eviction policy
- TTL-based expiration
- Bulk import/export
- Hit rate tracking
- Cache statistics

#### 9. Performance Manager
Batch processing and optimization:
- Concurrent analysis with rate limiting
- Automatic retry mechanism with exponential backoff
- Batch processing with controlled parallelism
- Comprehensive reporting engine
- JSON and CSV export formats
- Performance metrics tracking

#### 10. Webhook Notifier
Real-time alerting system:
- Conditional webhook triggers (high risk, malicious, phishing, malware)
- Retry mechanism with configurable attempts
- Multiple webhook support
- Custom headers and methods
- Notification statistics
- Batch notification support

#### 11. Rate Limiter
Request throttling and quota management:
- Global and per-domain rate limiting
- Sliding window algorithm
- Concurrent request limiting
- Queue management
- Quota tracking
- Statistical reporting

#### 12. Reporting Engine
Multi-format report generation:
- Executive reports (high-level verdicts, recommendations)
- Technical reports (detailed trace analysis, indicators)
- Compliance reports (GDPR, PCI-DSS, HIPAA assessment)
- Incident reports (severity, IOCs, response actions)
- Batch report aggregation
- Customizable report filters

### Risk Scoring

The engine calculates risk scores (0-100) based on 20+ factors:
- Excessive redirects (>5 hops): +5-30 points
- Protocol downgrades (HTTPS → HTTP): +35 points
- Certificate issues (expired, expiring soon, invalid): +15-30 points
- Suspicious TLDs (.xyz, .top, etc.): +12 points per domain
- Meta refresh and JavaScript redirects: +10-12 points
- Circular redirect patterns: +20 points
- Lexical anomalies (entropy, obfuscation): +5-20 points
- HTML obfuscation and suspicious scripts: +10-25 points
- Weak security headers: +5-25 points
- DNS and domain issues: +12-20 points
- Phishing indicators: +10-25 points
- Malware indicators: +15-30 points

Risk levels: `minimal` (0-29), `low` (30-59), `medium` (60-79), `high` (80-100)

## Installation

```bash
npm install
```

Optional dependencies for screenshot capture:
```bash
npm install puppeteer
# or
npm install playwright
```

## Usage

### Basic Analysis

```javascript
import URLDeepTrace from './src/index.js';

const tracer = new URLDeepTrace({
  maxHops: 20,
  timeout: 15000,
  enableDeepAnalysis: true,
  enableThreatIntel: true,
  enableMLClassification: true
});

const result = await tracer.analyze('https://example.com');

console.log('Risk Level:', result.security.risk.level);
console.log('Risk Score:', result.security.risk.score);
console.log('ML Classification:', result.mlClassification.classification);
console.log('Threat Level:', result.threat.threatLevel.level);
```

### Multiple URLs (Parallel Processing)

```javascript
const urls = [
  'https://example.com',
  'https://suspicious-site.xyz',
  'https://another-domain.com'
];

const batchResult = await tracer.analyzeMultiple(urls);

console.log('Summary:', batchResult.summary);
```

### Detailed Hop Analysis

```javascript
const result = await tracer.analyze('https://example.com');

for (const hop of result.trace.chain) {
  console.log('URL:', hop.url);
  console.log('Status:', hop.statusCode);
  console.log('Lexical Risk:', hop.lexical?.riskScore);
  console.log('Domain Risk:', hop.domainInfo?.riskScore);
  console.log('Security Headers:', hop.headerFingerprint?.security.score);
}
```

### Export Results

```javascript
const batchResult = await tracer.analyzeMultiple(urls);

const jsonExport = tracer.exportResults(batchResult.results, 'json', { 
  pretty: true,
  includeRawData: true 
});

const csvExport = tracer.exportResults(batchResult.results, 'csv');
```

## Configuration Options

```javascript
const tracer = new URLDeepTrace({
  maxHops: 20,
  timeout: 15000,
  userAgent: 'Custom User Agent',
  enableDeepAnalysis: true,
  maxConcurrent: 5,
  retryAttempts: 2,
  retryDelay: 1000
});
```

## API Reference

### URLDeepTrace

#### `analyze(url: string): Promise<AnalysisResult>`
Analyzes a single URL with full forensics.

#### `analyzeMultiple(urls: string[]): Promise<BatchResult>`
Analyzes multiple URLs with concurrent processing.

#### `analyzeMultipleParallel(urls: string[], options): Promise<BatchResult>`
Analyzes URLs in controlled batches.

#### `exportResults(results: AnalysisResult[], format: string, options): string`
Exports results in JSON or CSV format.

### Response Structure

```javascript
{
  success: true,
  url: "https://example.com",
  finalDestination: "https://example.com",
  trace: {
    totalHops: 1,
    chain: [
      {
        url: "https://example.com",
        statusCode: 200,
        protocol: "https",
        tlsInfo: { ... },
        lexical: { ... },
        domainInfo: { ... },
        headerFingerprint: { ... },
        htmlAnalysis: { ... },
        timing: { ... }
      }
    ]
  },
  security: {
    risk: {
      score: 15,
      level: "minimal",
      factors: [...],
      details: { ... }
    }
  },
  metadata: {
    analyzedAt: "2025-01-21T10:30:00.000Z",
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
├── header-fingerprint.js    # HTTP header analysis
├── risk-engine.js           # Security risk scoring
└── performance-manager.js   # Batch processing & export
```

## Performance Considerations

- Deep analysis adds ~500-1000ms per URL
- Concurrent processing recommended for batches >10 URLs
- DNS queries may timeout on restrictive networks
- TLS inspection requires network access to target

## Security Notes

- All analysis is read-only and non-invasive
- Does not bypass authentication or paywalls
- Respects robots.txt (not enforced by default)
- Suitable for security research and monitoring

## License

UNLICENSED - Internal use only

## Version

1.0.0