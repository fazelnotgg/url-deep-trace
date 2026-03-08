import crypto from 'crypto';

export class ReputationCache {
  constructor(options = {}) {
    this.maxAge = options.maxAge || 3600000;
    this.maxSize = options.maxSize || 10000;
    this.cache = new Map();
    this.blacklist = new Map();
    this.whitelist = new Map();
    this.greylist = new Map();
    this.stats = {
      hits: 0,
      misses: 0,
      blacklistHits: 0,
      whitelistHits: 0,
      evictions: 0
    };
  }

  _hash(url) {
    return crypto.createHash('sha256').update(url).digest('hex');
  }

  set(url, data) {
    const hash = this._hash(url);
    
    if (this.cache.has(hash)) {
      this.cache.delete(hash);
    } else if (this.cache.size >= this.maxSize) {
      this._evictOldest();
    }

    this.cache.set(hash, {
      url: url,
      data: data,
      timestamp: Date.now(),
      accessCount: 0
    });
  }

  get(url) {
    const hash = this._hash(url);
    const entry = this.cache.get(hash);

    if (!entry) {
      this.stats.misses++;
      return null;
    }

    if (Date.now() - entry.timestamp > this.maxAge) {
      this.cache.delete(hash);
      this.stats.misses++;
      return null;
    }

    entry.accessCount++;
    entry.lastAccess = Date.now();
    this.cache.delete(hash);
    this.cache.set(hash, entry);
    this.stats.hits++;

    return entry.data;
  }

  addToBlacklist(url, reason = '') {
    const hash = this._hash(url);
    this.blacklist.set(hash, {
      url: url,
      reason: reason,
      addedAt: Date.now()
    });
    this.greylist.set(hash, {
      url: url,
      reason: reason,
      addedAt: Date.now(),
      type: 'blacklist'
    });
  }

  addToWhitelist(url, reason = '') {
    const hash = this._hash(url);
    this.whitelist.set(hash, {
      url: url,
      reason: reason,
      addedAt: Date.now()
    });
    this.greylist.set(hash, {
      url: url,
      reason: reason,
      addedAt: Date.now(),
      type: 'whitelist'
    });
  }

  isBlacklisted(url) {
    const hash = this._hash(url);
    const result = this.blacklist.has(hash);
    if (result) this.stats.blacklistHits++;
    return result;
  }

  isWhitelisted(url) {
    const hash = this._hash(url);
    const result = this.whitelist.has(hash);
    if (result) this.stats.whitelistHits++;
    return result;
  }

  getReputation(url) {
    const hash = this._hash(url);

    if (this.blacklist.has(hash)) {
      return {
        status: 'blacklisted',
        info: this.greylist.get(hash)
      };
    }

    if (this.whitelist.has(hash)) {
      return {
        status: 'whitelisted',
        info: this.greylist.get(hash)
      };
    }

    const cached = this.get(url);
    if (cached) {
      return {
        status: 'cached',
        data: cached
      };
    }

    return {
      status: 'unknown'
    };
  }

  _evictOldest() {
    const oldestEntry = this.cache.entries().next();
    if (!oldestEntry.done) {
      const [oldestHash] = oldestEntry.value;
      this.cache.delete(oldestHash);
      this.stats.evictions++;
    }
  }

  bulkAddBlacklist(urls, reason = '') {
    for (const url of urls) {
      this.addToBlacklist(url, reason);
    }
  }

  bulkAddWhitelist(urls, reason = '') {
    for (const url of urls) {
      this.addToWhitelist(url, reason);
    }
  }

  importBlacklist(data) {
    if (Array.isArray(data)) {
      this.bulkAddBlacklist(data, 'Imported');
    } else if (typeof data === 'object') {
      for (const [url, reason] of Object.entries(data)) {
        this.addToBlacklist(url, reason);
      }
    }
  }

  importWhitelist(data) {
    if (Array.isArray(data)) {
      this.bulkAddWhitelist(data, 'Imported');
    } else if (typeof data === 'object') {
      for (const [url, reason] of Object.entries(data)) {
        this.addToWhitelist(url, reason);
      }
    }
  }

  exportBlacklist() {
    const exported = {};
    for (const [hash, info] of this.greylist.entries()) {
      if (info.type === 'blacklist') {
        exported[info.url] = info.reason;
      }
    }
    return exported;
  }

  exportWhitelist() {
    const exported = {};
    for (const [hash, info] of this.greylist.entries()) {
      if (info.type === 'whitelist') {
        exported[info.url] = info.reason;
      }
    }
    return exported;
  }

  clear() {
    this.cache.clear();
  }

  clearBlacklist() {
    this.blacklist.clear();
    for (const [hash, info] of this.greylist.entries()) {
      if (info.type === 'blacklist') {
        this.greylist.delete(hash);
      }
    }
  }

  clearWhitelist() {
    this.whitelist.clear();
    for (const [hash, info] of this.greylist.entries()) {
      if (info.type === 'whitelist') {
        this.greylist.delete(hash);
      }
    }
  }

  getStats() {
    return {
      ...this.stats,
      cacheSize: this.cache.size,
      blacklistSize: this.blacklist.size,
      whitelistSize: this.whitelist.size,
      hitRate: this.stats.hits > 0 
        ? Math.round((this.stats.hits / (this.stats.hits + this.stats.misses)) * 100) 
        : 0
    };
  }

  pruneExpired() {
    const now = Date.now();
    let pruned = 0;

    for (const [hash, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.maxAge) {
        this.cache.delete(hash);
        pruned++;
      }
    }

    return pruned;
  }
}