import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

const execAsync = promisify(exec);

export class ScreenshotCapture {
  constructor(options = {}) {
    this.outputDir = options.outputDir || './screenshots';
    this.browser = options.browser || 'chromium';
    this.timeout = options.timeout || 30000;
    this.viewportWidth = options.viewportWidth || 1920;
    this.viewportHeight = options.viewportHeight || 1080;
    this.fullPage = options.fullPage !== false;
    this.quality = options.quality || 80;
    this.enabled = options.enabled || false;
    
    this.stats = {
      captured: 0,
      failed: 0,
      totalSize: 0
    };
  }

  async capture(url, options = {}) {
    if (!this.enabled) {
      return {
        success: false,
        reason: 'Screenshot capture is disabled'
      };
    }

    try {
      await this._ensureOutputDir();

      const filename = this._generateFilename(url);
      const filepath = path.join(this.outputDir, filename);

      const puppeteerAvailable = await this._checkPuppeteer();
      
      if (puppeteerAvailable) {
        return await this._captureWithPuppeteer(url, filepath, options);
      } else {
        return await this._captureWithPlaywright(url, filepath, options);
      }

    } catch (error) {
      this.stats.failed++;
      return {
        success: false,
        error: error.message
      };
    }
  }

  async _captureWithPuppeteer(url, filepath, options) {
    try {
      const puppeteer = await import('puppeteer');
      
      const browser = await puppeteer.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu'
        ]
      });

      const page = await browser.newPage();
      
      await page.setViewport({
        width: this.viewportWidth,
        height: this.viewportHeight
      });

      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: this.timeout
      });

      await page.screenshot({
        path: filepath,
        fullPage: this.fullPage,
        quality: this.quality,
        type: 'jpeg'
      });

      await browser.close();

      const stats = await fs.stat(filepath);
      this.stats.captured++;
      this.stats.totalSize += stats.size;

      return {
        success: true,
        filepath: filepath,
        filename: path.basename(filepath),
        size: stats.size,
        url: url,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      throw new Error(`Puppeteer capture failed: ${error.message}`);
    }
  }

  async _captureWithPlaywright(url, filepath, options) {
    try {
      const { chromium } = await import('playwright');
      
      const browser = await chromium.launch({
        headless: true
      });

      const page = await browser.newPage({
        viewport: {
          width: this.viewportWidth,
          height: this.viewportHeight
        }
      });

      await page.goto(url, {
        waitUntil: 'networkidle',
        timeout: this.timeout
      });

      await page.screenshot({
        path: filepath,
        fullPage: this.fullPage,
        quality: this.quality,
        type: 'jpeg'
      });

      await browser.close();

      const stats = await fs.stat(filepath);
      this.stats.captured++;
      this.stats.totalSize += stats.size;

      return {
        success: true,
        filepath: filepath,
        filename: path.basename(filepath),
        size: stats.size,
        url: url,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      throw new Error(`Playwright capture failed: ${error.message}`);
    }
  }

  async _checkPuppeteer() {
    try {
      await import('puppeteer');
      return true;
    } catch (error) {
      return false;
    }
  }

  async _ensureOutputDir() {
    try {
      await fs.access(this.outputDir);
    } catch (error) {
      await fs.mkdir(this.outputDir, { recursive: true });
    }
  }

  _generateFilename(url) {
    const hash = crypto.createHash('md5').update(url).digest('hex');
    const timestamp = Date.now();
    return `screenshot_${timestamp}_${hash.substring(0, 8)}.jpg`;
  }

  async captureMultiple(urls, options = {}) {
    const results = [];

    for (const url of urls) {
      const result = await this.capture(url, options);
      results.push({
        url: url,
        ...result
      });
    }

    return {
      total: urls.length,
      successful: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
      results: results
    };
  }

  async getScreenshot(filename) {
    const filepath = path.join(this.outputDir, filename);
    
    try {
      const buffer = await fs.readFile(filepath);
      return {
        success: true,
        buffer: buffer,
        base64: buffer.toString('base64')
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async deleteScreenshot(filename) {
    const filepath = path.join(this.outputDir, filename);
    
    try {
      const stats = await fs.stat(filepath);
      await fs.unlink(filepath);
      
      this.stats.totalSize -= stats.size;
      
      return {
        success: true,
        deleted: filename
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async listScreenshots() {
    try {
      const files = await fs.readdir(this.outputDir);
      const screenshots = [];

      for (const file of files) {
        if (file.endsWith('.jpg') || file.endsWith('.png')) {
          const filepath = path.join(this.outputDir, file);
          const stats = await fs.stat(filepath);
          
          screenshots.push({
            filename: file,
            size: stats.size,
            created: stats.birthtime,
            modified: stats.mtime
          });
        }
      }

      return {
        success: true,
        count: screenshots.length,
        screenshots: screenshots
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async cleanup(olderThanDays = 7) {
    try {
      const files = await fs.readdir(this.outputDir);
      const cutoff = Date.now() - (olderThanDays * 24 * 60 * 60 * 1000);
      let deleted = 0;
      let freedSpace = 0;

      for (const file of files) {
        const filepath = path.join(this.outputDir, file);
        const stats = await fs.stat(filepath);

        if (stats.mtime.getTime() < cutoff) {
          await fs.unlink(filepath);
          deleted++;
          freedSpace += stats.size;
        }
      }

      this.stats.totalSize -= freedSpace;

      return {
        success: true,
        deleted: deleted,
        freedSpace: freedSpace
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  getStats() {
    return {
      ...this.stats,
      totalSizeMB: Math.round(this.stats.totalSize / (1024 * 1024) * 100) / 100,
      averageSizeKB: this.stats.captured > 0
        ? Math.round((this.stats.totalSize / this.stats.captured) / 1024)
        : 0
    };
  }
}