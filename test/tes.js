import URLDeepTrace from '../src/index.js';

console.log('🔍 Debug Test - Checking Deep Analysis\n');

async function debug() {
  const tracer = new URLDeepTrace({
    maxHops: 10,
    timeout: 15000,
    enableDeepAnalysis: true,
    enableCache: false,
    enableThreatIntel: false,
    enableMLClassification: false,
    enableRateLimit: false
  });

  console.log('Configuration:');
  console.log('  enableDeepAnalysis:', tracer.tracer.enableDeepAnalysis);
  console.log('');

  const url = 'https://example.com';
  console.log(`Testing: ${url}\n`);

  const result = await tracer.analyze(url);

  console.log('Result:');
  console.log('  Success:', result.success);
  console.log('  Total Hops:', result.trace?.totalHops);
  console.log('');

  if (result.trace?.chain && result.trace.chain.length > 0) {
    const firstHop = result.trace.chain[0];
    
    console.log('First Hop Data Available:');
    console.log('  lexical:', !!firstHop.lexical);
    console.log('  domainInfo:', !!firstHop.domainInfo);
    console.log('  headerFingerprint:', !!firstHop.headerFingerprint);
    console.log('  htmlAnalysis:', !!firstHop.htmlAnalysis);
    console.log('  tlsInfo:', !!firstHop.tlsInfo);
    console.log('');

    if (firstHop.lexical) {
      console.log('Lexical Data:');
      console.log('  length:', firstHop.lexical.length);
      console.log('  entropy:', firstHop.lexical.entropy);
      console.log('  riskScore:', firstHop.lexical.riskScore);
      console.log('  hostname:', JSON.stringify(firstHop.lexical.hostname, null, 2));
      console.log('  path:', JSON.stringify(firstHop.lexical.path, null, 2));
    } else {
      console.log('❌ Lexical data is NULL/UNDEFINED');
      console.log('   This means deep analysis is not working!');
    }

    console.log('');
    console.log('Timing Info:');
    if (firstHop.timing) {
      Object.entries(firstHop.timing).forEach(([key, value]) => {
        console.log(`  ${key}: ${value}ms`);
      });
    }

    console.log('');
    console.log('Full First Hop (limited):');
    console.log(JSON.stringify({
      url: firstHop.url,
      statusCode: firstHop.statusCode,
      protocol: firstHop.protocol,
      hasLexical: !!firstHop.lexical,
      hasDomain: !!firstHop.domainInfo,
      hasHeader: !!firstHop.headerFingerprint,
      hasHTML: !!firstHop.htmlAnalysis,
      hasTLS: !!firstHop.tlsInfo
    }, null, 2));
  }
}

debug().catch(err => {
  console.error('Error:', err.message);
  console.error(err.stack);
});