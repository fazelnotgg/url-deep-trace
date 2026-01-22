import cors from 'cors';
import express from 'express';
import URLDeepTrace from '../src/index.js';

const app = express();
app.use(cors());
const port = process.env.PORT || 3000;

app.use(express.json());

const tracer = new URLDeepTrace({
  maxHops: 20,
  timeout: 15000,
  enableDeepAnalysis: true,
  enableCache: true,
  enableThreatIntel: true,
  enableMLClassification: true,
  enableRateLimit: true,
  maxRequestsPerWindow: 100,
  rateLimitWindow: 60000,
  maxConcurrent: 10
});

app.post('/api/v1/analyze', async (req, res) => {
  try {
    const { url, options = {} } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL is required',
        message: 'Please provide a URL in the request body'
      });
    }

    const result = await tracer.analyze(url);

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/analyze/batch', async (req, res) => {
  try {
    const { urls, options = {} } = req.body;

    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({
        error: 'URLs array is required',
        message: 'Please provide an array of URLs in the request body'
      });
    }

    if (urls.length > 100) {
      return res.status(400).json({
        error: 'Too many URLs',
        message: 'Maximum 100 URLs per batch request'
      });
    }

    const result = await tracer.analyzeMultiple(urls);

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/reports/generate', async (req, res) => {
  try {
    const { url, type = 'technical', options = {} } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL is required'
      });
    }

    const result = await tracer.analyze(url);
    const report = tracer.generateReport(result, type, options);

    res.json({
      success: true,
      data: report
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/blacklist/add', async (req, res) => {
  try {
    const { url, reason = '' } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL is required'
      });
    }

    tracer.addToBlacklist(url, reason);

    res.json({
      success: true,
      message: 'URL added to blacklist',
      url: url
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/whitelist/add', async (req, res) => {
  try {
    const { url, reason = '' } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL is required'
      });
    }

    tracer.addToWhitelist(url, reason);

    res.json({
      success: true,
      message: 'URL added to whitelist',
      url: url
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/blacklist/export', (req, res) => {
  try {
    const blacklist = tracer.exportBlacklist();

    res.json({
      success: true,
      data: blacklist
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/whitelist/export', (req, res) => {
  try {
    const whitelist = tracer.exportWhitelist();

    res.json({
      success: true,
      data: whitelist
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/blacklist/import', async (req, res) => {
  try {
    const { data } = req.body;

    if (!data) {
      return res.status(400).json({
        error: 'Blacklist data is required'
      });
    }

    tracer.importBlacklist(data);

    res.json({
      success: true,
      message: 'Blacklist imported successfully'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/whitelist/import', async (req, res) => {
  try {
    const { data } = req.body;

    if (!data) {
      return res.status(400).json({
        error: 'Whitelist data is required'
      });
    }

    tracer.importWhitelist(data);

    res.json({
      success: true,
      message: 'Whitelist imported successfully'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/stats/cache', (req, res) => {
  try {
    const stats = tracer.getCacheStats();

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/stats/rate-limit', (req, res) => {
  try {
    const stats = tracer.getRateLimitStats();

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/stats/webhooks', (req, res) => {
  try {
    const stats = tracer.getWebhookStats();

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/cache/clear', (req, res) => {
  try {
    tracer.clearCache();

    res.json({
      success: true,
      message: 'Cache cleared successfully'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/cache/prune', (req, res) => {
  try {
    const pruned = tracer.pruneCache();

    res.json({
      success: true,
      message: 'Cache pruned successfully',
      prunedEntries: pruned
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/ml/feature-importance', (req, res) => {
  try {
    const importance = tracer.getFeatureImportance();

    res.json({
      success: true,
      data: importance
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/ml/model/export', (req, res) => {
  try {
    const model = tracer.exportMLModel();

    res.json({
      success: true,
      data: model
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/ml/model/import', (req, res) => {
  try {
    const { model } = req.body;

    if (!model) {
      return res.status(400).json({
        error: 'Model data is required'
      });
    }

    tracer.importMLModel(model);

    res.json({
      success: true,
      message: 'ML model imported successfully'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/v1/webhooks/add', (req, res) => {
  try {
    const { url, method = 'POST', headers = {} } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'Webhook URL is required'
      });
    }

    tracer.addWebhook(url, { method, headers });

    res.json({
      success: true,
      message: 'Webhook added successfully',
      url: url
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.delete('/api/v1/webhooks/remove', (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'Webhook URL is required'
      });
    }

    tracer.removeWebhook(url);

    res.json({
      success: true,
      message: 'Webhook removed successfully'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/v1/quota/:domain?', (req, res) => {
  try {
    const { domain = 'global' } = req.params;
    const quota = tracer.getRemainingQuota(domain);

    res.json({
      success: true,
      domain: domain,
      remainingQuota: quota
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: 'The requested API endpoint does not exist'
  });
});

app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: error.message
  });
});

app.listen(port, () => {
  console.log(`URL Deep Trace API Server running on port ${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
  console.log(`\nAvailable endpoints:`);
  console.log(`  POST   /api/v1/analyze`);
  console.log(`  POST   /api/v1/analyze/batch`);
  console.log(`  POST   /api/v1/reports/generate`);
  console.log(`  POST   /api/v1/blacklist/add`);
  console.log(`  POST   /api/v1/whitelist/add`);
  console.log(`  GET    /api/v1/blacklist/export`);
  console.log(`  GET    /api/v1/whitelist/export`);
  console.log(`  POST   /api/v1/blacklist/import`);
  console.log(`  POST   /api/v1/whitelist/import`);
  console.log(`  GET    /api/v1/stats/cache`);
  console.log(`  GET    /api/v1/stats/rate-limit`);
  console.log(`  GET    /api/v1/stats/webhooks`);
  console.log(`  POST   /api/v1/cache/clear`);
  console.log(`  POST   /api/v1/cache/prune`);
  console.log(`  GET    /api/v1/ml/feature-importance`);
  console.log(`  GET    /api/v1/ml/model/export`);
  console.log(`  POST   /api/v1/ml/model/import`);
  console.log(`  POST   /api/v1/webhooks/add`);
  console.log(`  DELETE /api/v1/webhooks/remove`);
  console.log(`  GET    /api/v1/quota/:domain`);
});