const crypto = require('crypto');

class EncryptionUtils {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.key = process.env.ENCRYPTION_KEY || this.generateKey();
  }

  generateKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  encrypt(text) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipher(this.algorithm, Buffer.from(this.key, 'hex'));
      
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      return {
        iv: iv.toString('hex'),
        data: encrypted,
        authTag: authTag.toString('hex')
      };
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  decrypt(encryptedData) {
    try {
      const decipher = crypto.createDecipher(
        this.algorithm, 
        Buffer.from(this.key, 'hex')
      );
      
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
      
      let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  hashData(data) {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  validateHash(data, hash) {
    const dataHash = this.hashData(data);
    return crypto.timingSafeEqual(
      Buffer.from(dataHash, 'hex'),
      Buffer.from(hash, 'hex')
    );
  }

  // For sensitive user data encryption
  encryptUserData(userData) {
    const sensitiveFields = ['email', 'firstName', 'lastName'];
    const encryptedData = { ...userData };
    
    sensitiveFields.forEach(field => {
      if (encryptedData[field]) {
        encryptedData[field] = this.encrypt(encryptedData[field]);
      }
    });
    
    return encryptedData;
  }

  decryptUserData(encryptedUserData) {
    const sensitiveFields = ['email', 'firstName', 'lastName'];
    const decryptedData = { ...encryptedUserData };
    
    sensitiveFields.forEach(field => {
      if (decryptedData[field] && typeof decryptedData[field] === 'object') {
        decryptedData[field] = this.decrypt(decryptedData[field]);
      }
    });
    
    return decryptedData;
  }

  // For secure password hashing (complementary to bcrypt)
  generateSalt() {
    return crypto.randomBytes(16).toString('hex');
  }

  // For API key generation
  generateAPIKey() {
    return `ts_${this.generateSecureToken(16)}`;
  }

  // For secure random number generation
  generateSecureRandom(min, max) {
    const range = max - min + 1;
    const bytes = crypto.randomBytes(4);
    const random = bytes.readUInt32BE(0);
    return min + (random % range);
  }
}

module.exports = new EncryptionUtils();