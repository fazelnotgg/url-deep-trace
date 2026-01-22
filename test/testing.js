import URLDeepTrace from '../src/index.js';
import util from 'util';

console.log('🔍 URL Deep Trace - Single URL Test\n');
console.log('═'.repeat(70));

async function testURL() {
  const url = 'https://example.com';
  
  console.log(`\n📍 Testing URL: ${url}\n`);
  console.log('⏳ Analyzing...\n');

  const tracer = new URLDeepTrace({
    maxHops: 20,
    timeout: 15000,
    enableDeepAnalysis: true,
    enableCache: true,
    enableThreatIntel: true,
    enableMLClassification: true,
    enableRateLimit: false
  });

  const startTime = Date.now();
  
  try {
    const result = await tracer.analyze(url);
    const duration = Date.now() - startTime;

    console.log('═'.repeat(70));
    console.log(result.success ? '✅ ANALYSIS SUCCESSFUL' : '❌ ANALYSIS FAILED');
    console.log('═'.repeat(70));
    console.log(`⏱️  Duration: ${duration}ms (${(duration / 1000).toFixed(2)}s)\n`);

    if (!result.success) {
      console.log('❌ Error Details:');
      console.log(`   Message: ${result.error || 'Unknown error'}`);
      console.log('\n💡 Troubleshooting:');
      console.log('   1. Check if URL is accessible in browser');
      console.log('   2. Verify internet connection');
      console.log('   3. Try with different URL (e.g., https://example.com)');
      console.log('   4. Check if firewall is blocking the request');
      console.log('\n📝 Full Response:');
      console.log(util.inspect(result, { depth: 3, colors: true }));
      return;
    }

    console.log('┌─────────────────────────────────────────────────────────────────┐');
    console.log('│ BASIC INFORMATION                                               │');
    console.log('└─────────────────────────────────────────────────────────────────┘');
    console.log(`URL:                  ${result.url}`);
    console.log(`Success:              ${result.success}`);
    console.log(`Final Destination:    ${result.finalDestination}`);
    console.log(`Total Hops:           ${result.trace?.totalHops || 0}`);
    console.log(`Execution Time:       ${result.metadata?.executionTime || 0}ms`);

    console.log('\n┌─────────────────────────────────────────────────────────────────┐');
    console.log('│ SECURITY ASSESSMENT                                             │');
    console.log('└─────────────────────────────────────────────────────────────────┘');
    if (result.security?.risk) {
      console.log(`Risk Score:           ${result.security.risk.score}/100`);
      console.log(`Risk Level:           ${result.security.risk.level.toUpperCase()}`);
      console.log('\nTop Risk Factors:');
      result.security.risk.factors.slice(0, 5).forEach((factor, i) => {
        console.log(`  ${i + 1}. ${factor}`);
      });
    }

    if (result.mlClassification) {
      console.log('\n┌─────────────────────────────────────────────────────────────────┐');
      console.log('│ ML CLASSIFICATION                                               │');
      console.log('└─────────────────────────────────────────────────────────────────┘');
      console.log(`Classification:       ${result.mlClassification.classification.toUpperCase()}`);
      console.log(`Confidence:           ${result.mlClassification.confidence}%`);
      console.log(`\n${result.mlClassification.explanation.reasoning}`);
    }

    if (result.threat && !result.threat.error) {
      console.log('\n┌─────────────────────────────────────────────────────────────────┐');
      console.log('│ THREAT INTELLIGENCE                                             │');
      console.log('└─────────────────────────────────────────────────────────────────┘');
      console.log(`Threat Level:         ${result.threat.threatLevel?.level?.toUpperCase() || 'LOW'}`);
      console.log(`Threat Score:         ${result.threat.threatLevel?.score || 0}/100`);
      console.log(`Phishing Detected:    ${result.threat.phishingIndicators?.detected || false}`);
      console.log(`Malware Risk:         ${result.threat.malwareRisk?.level?.toUpperCase() || 'LOW'}`);
      
      if (result.threat.phishingIndicators?.detected) {
        console.log(`  Confidence:         ${result.threat.phishingIndicators.confidence}%`);
        console.log(`  Indicators:         ${result.threat.phishingIndicators.indicators}`);
      }
      
      if (result.threat.malwareRisk?.risk > 30) {
        console.log(`  Risk Score:         ${result.threat.malwareRisk.risk}/100`);
      }
    } else if (result.threat?.error) {
      console.log('\n┌─────────────────────────────────────────────────────────────────┐');
      console.log('│ THREAT INTELLIGENCE                                             │');
      console.log('└─────────────────────────────────────────────────────────────────┘');
      console.log(`⚠️  Threat analysis error: ${result.threat.error}`);
    }

    if (result.trace?.chain && result.trace.chain.length > 0) {
      console.log('\n┌─────────────────────────────────────────────────────────────────┐');
      console.log('│ REDIRECT CHAIN                                                  │');
      console.log('└─────────────────────────────────────────────────────────────────┘');
      result.trace.chain.forEach((hop, index) => {
        console.log(`\nHop ${index + 1}:`);
        console.log(`  URL:         ${hop.url}`);
        console.log(`  Status:      ${hop.statusCode || (hop.error ? 'ERROR' : 'N/A')}`);
        console.log(`  Type:        ${hop.type}`);
        if (hop.redirectType) {
          console.log(`  Redirect:    ${hop.redirectType}`);
        }
        if (hop.error) {
          console.log(`  Error:       ${hop.error}`);
        }
        if (hop.timing) {
          const totalTime = Object.values(hop.timing).reduce((a, b) => a + b, 0);
          console.log(`  Time:        ${totalTime}ms`);
        }
      });

      const firstHop = result.trace.chain[0];

      if (firstHop.tlsInfo?.valid) {
        console.log('\n┌─────────────────────────────────────────────────────────────────┐');
        console.log('│ TLS CERTIFICATE                                                 │');
        console.log('└─────────────────────────────────────────────────────────────────┘');
        console.log(`Valid:               ${firstHop.tlsInfo.valid}`);
        console.log(`Issuer:              ${firstHop.tlsInfo.issuer?.substring(0, 60)}...`);
        console.log(`Days Remaining:      ${firstHop.tlsInfo.daysRemaining} days`);
        console.log(`Expired:             ${firstHop.tlsInfo.isExpired}`);
      }

      if (firstHop.lexical) {
        console.log('\n┌─────────────────────────────────────────────────────────────────┐');
        console.log('│ LEXICAL ANALYSIS                                                │');
        console.log('└─────────────────────────────────────────────────────────────────┘');
        console.log(`URL Length:          ${firstHop.lexical.length || 'N/A'}`);
        console.log(`Entropy:             ${firstHop.lexical.entropy || 'N/A'}`);
        console.log(`Risk Score:          ${firstHop.lexical.riskScore || 0}/100`);
        console.log(`Suspicious TLD:      ${firstHop.lexical.hostname?.tld || 'unknown'}`);
        console.log(`Has Homoglyphs:      ${firstHop.lexical.homoglyphDetection?.hasHomoglyphs || false}`);
        
        if (firstHop.lexical.hostname) {
          console.log('\nHostname Details:');
          console.log(`  Full:              ${firstHop.lexical.hostname.full || 'N/A'}`);
          console.log(`  TLD:               ${firstHop.lexical.hostname.tld || 'N/A'}`);
          console.log(`  Subdomains:        ${firstHop.lexical.hostname.subdomainCount || 0}`);
          console.log(`  Digit Count:       ${firstHop.lexical.hostname.digitCount || 0}`);
        }
        
        if (firstHop.lexical.path) {
          console.log('\nPath Details:');
          console.log(`  Depth:             ${firstHop.lexical.path.depth || 0}`);
          console.log(`  Length:            ${firstHop.lexical.path.length || 0}`);
          console.log(`  Suspicious Ext:    ${firstHop.lexical.path.suspiciousExtensions?.join(', ') || 'None'}`);
        }
      } else {
        console.log('\n┌─────────────────────────────────────────────────────────────────┐');
        console.log('│ LEXICAL ANALYSIS                                                │');
        console.log('└─────────────────────────────────────────────────────────────────┘');
        console.log('⚠️  Lexical analysis data not available');
      }

      if (firstHop.domainInfo) {
        console.log('\n┌─────────────────────────────────────────────────────────────────┐');
        console.log('│ DOMAIN INTELLIGENCE                                             │');
        console.log('└─────────────────────────────────────────────────────────────────┘');
        console.log(`Hostname:            ${firstHop.domainInfo.hostname}`);
        console.log(`TLD:                 ${firstHop.domainInfo.tld}`);
        console.log(`Risk Score:          ${firstHop.domainInfo.riskScore}/100`);
        console.log(`DNS Success:         ${firstHop.domainInfo.dnsRecords?.querySuccess || false}`);
        console.log(`Has MX:              ${firstHop.domainInfo.dnsRecords?.hasMX || false}`);
        console.log(`Has SPF:             ${firstHop.domainInfo.dnsRecords?.hasSPF || false}`);
      }

      if (firstHop.headerFingerprint) {
        console.log('\n┌─────────────────────────────────────────────────────────────────┐');
        console.log('│ SECURITY HEADERS                                                │');
        console.log('└─────────────────────────────────────────────────────────────────┘');
        console.log(`Security Score:      ${firstHop.headerFingerprint.security?.score || 0}/100`);
        
        const serverInfo = firstHop.headerFingerprint.server;
        const serverName = serverInfo?.identified || 
                          (serverInfo?.raw ? serverInfo.raw.substring(0, 30) : 'Not Disclosed');
        console.log(`Server:              ${serverName}`);
        
        console.log(`HSTS Enabled:        ${firstHop.headerFingerprint.security?.hsts?.enabled || false}`);
        console.log(`CSP Enabled:         ${firstHop.headerFingerprint.security?.csp?.enabled || false}`);
        
        if (firstHop.headerFingerprint.security?.missing?.length > 0) {
          console.log(`\nMissing Headers:     ${firstHop.headerFingerprint.security.missing.length}`);
          if (firstHop.headerFingerprint.security.missing.length <= 5) {
            firstHop.headerFingerprint.security.missing.forEach(h => {
              console.log(`  - ${h}`);
            });
          }
        }
        
        if (firstHop.headerFingerprint.security?.present?.length > 0) {
          console.log(`Present Headers:     ${firstHop.headerFingerprint.security.present.length}`);
        }
      }

      if (firstHop.htmlAnalysis) {
        console.log('\n┌─────────────────────────────────────────────────────────────────┐');
        console.log('│ HTML ANALYSIS                                                   │');
        console.log('└─────────────────────────────────────────────────────────────────┘');
        console.log(`Total Elements:      ${firstHop.htmlAnalysis.structure?.totalElements || 0}`);
        console.log(`Forms:               ${firstHop.htmlAnalysis.forms?.count || 0}`);
        console.log(`Scripts:             ${firstHop.htmlAnalysis.scripts?.total || 0}`);
        console.log(`External Links:      ${firstHop.htmlAnalysis.links?.external || 0}`);
        console.log(`Obfuscated Scripts:  ${firstHop.htmlAnalysis.scripts?.obfuscated || 0}`);
      }
    }

    if (result.trace?.behavioral) {
      console.log('\n┌─────────────────────────────────────────────────────────────────┐');
      console.log('│ BEHAVIORAL ANALYSIS                                             │');
      console.log('└─────────────────────────────────────────────────────────────────┘');
      console.log(`Redirect Pattern:    ${result.trace.behavioral.redirectBehavior?.pattern || 'N/A'}`);
      console.log(`Unique Domains:      ${result.trace.behavioral.domainHopping?.uniqueDomains || 0}`);
      console.log(`Trust Score:         ${result.trace.behavioral.trustChainAnalysis?.trustScore || 0}/100`);
      console.log(`Cloaking Detected:   ${result.trace.behavioral.cloakingDetection?.detected || false}`);
    }

    console.log('\n┌─────────────────────────────────────────────────────────────────┐');
    console.log('│ CACHE STATISTICS                                                │');
    console.log('└─────────────────────────────────────────────────────────────────┘');
    const stats = tracer.getCacheStats();
    console.log(`Cache Size:          ${stats.cacheSize}`);
    console.log(`Hit Rate:            ${stats.hitRate}%`);
    console.log(`Blacklist Size:      ${stats.blacklistSize}`);
    console.log(`Whitelist Size:      ${stats.whitelistSize}`);

    console.log('\n┌─────────────────────────────────────────────────────────────────┐');
    console.log('│ FEATURE IMPORTANCE                                              │');
    console.log('└─────────────────────────────────────────────────────────────────┘');
    const features = tracer.getFeatureImportance();
    features.slice(0, 5).forEach((f, i) => {
      console.log(`${i + 1}. ${f.feature.padEnd(20)} ${f.weight}% (${f.importance})`);
    });

    console.log('\n═'.repeat(70));
    console.log('📄 FULL JSON OUTPUT');
    console.log('═'.repeat(70));
    console.log(util.inspect(result, { 
      depth: 10, 
      colors: true, 
      maxArrayLength: 10 
    }));

    console.log('\n═'.repeat(70));
    console.log('✅ TEST COMPLETED SUCCESSFULLY');
    console.log('═'.repeat(70));
    console.log(`\n⏱️  Total Time: ${duration}ms`);
    console.log('📝 To test another URL, edit line 8 in this file\n');

  } catch (error) {
    console.error('\n❌ FATAL ERROR:', error.message);
    console.error('\nStack Trace:');
    console.error(error.stack);
    console.log('\n💡 This is likely a bug in the library.');
    console.log('   Please report this error with the stack trace above.\n');
  }
}

testURL();