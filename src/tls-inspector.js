import tls from 'tls';
import crypto from 'crypto';
import { URL } from 'url';

export class TLSInspector {
  constructor(timeout = 10000) {
    this.timeout = timeout;
  }

  async inspect(urlString) {
    try {
      const parsedUrl = new URL(urlString);
      
      if (parsedUrl.protocol !== 'https:') {
        return null;
      }

      const hostname = parsedUrl.hostname;
      const port = parsedUrl.port || 443;

      return await this._connectAndExtract(hostname, port);
    } catch (error) {
      return {
        error: error.message,
        valid: false
      };
    }
  }

  _connectAndExtract(hostname, port) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: hostname,
          port: port,
          servername: hostname,
          rejectUnauthorized: false
        },
        () => {
          const cert = socket.getPeerCertificate(true);
          
          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return resolve({
              valid: false,
              error: 'No certificate available'
            });
          }

          const certInfo = this._extractCertificateDetails(cert);
          socket.destroy();
          resolve(certInfo);
        }
      );

      socket.setTimeout(this.timeout);

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error(`TLS connection timeout for ${hostname}`));
      });

      socket.on('error', (err) => {
        socket.destroy();
        reject(err);
      });
    });
  }

  _extractCertificateDetails(cert) {
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    const now = new Date();

    const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
    const isExpired = validTo < now;
    const isNotYetValid = validFrom > now;

    const fingerprint = cert.fingerprint256 || this._calculateFingerprint(cert.raw);

    return {
      valid: true,
      subject: this._formatDistinguishedName(cert.subject),
      issuer: this._formatDistinguishedName(cert.issuer),
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      daysRemaining: daysRemaining,
      isExpired: isExpired,
      isNotYetValid: isNotYetValid,
      serialNumber: cert.serialNumber,
      fingerprint: fingerprint,
      subjectAltNames: cert.subjectaltname ? cert.subjectaltname.split(', ') : []
    };
  }

  _calculateFingerprint(rawCert) {
    if (!rawCert) return null;
    return crypto.createHash('sha256').update(rawCert).digest('hex').toUpperCase().match(/.{2}/g).join(':');
  }

  _formatDistinguishedName(dn) {
    if (!dn) return '';
    
    const parts = [];
    if (dn.C) parts.push(`C=${dn.C}`);
    if (dn.ST) parts.push(`ST=${dn.ST}`);
    if (dn.L) parts.push(`L=${dn.L}`);
    if (dn.O) parts.push(`O=${dn.O}`);
    if (dn.OU) parts.push(`OU=${dn.OU}`);
    if (dn.CN) parts.push(`CN=${dn.CN}`);
    
    return parts.join(', ');
  }
}