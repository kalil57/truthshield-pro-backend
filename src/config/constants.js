module.exports = {
  // Security Constants
  JWT_SECRET: process.env.JWT_SECRET || 'truthshield_pro_advanced_secret_key_2024',
  JWT_EXPIRES_IN: '30d',
  BCRYPT_ROUNDS: 12,

  // Game Constants
  GAME_DIFFICULTY: {
    EASY: 'easy',
    MEDIUM: 'medium',
    HARD: 'hard',
    EXPERT: 'expert'
  },

  AGE_GROUPS: {
    CHILD: 'child', // 6-12
    TEEN: 'teen', // 13-17
    ADULT: 'adult', // 18+
    SENIOR: 'senior' // 65+
  },

  // Threat Levels
  THREAT_LEVEL: {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
  },

  // Game Types
  GAME_TYPES: {
    SCAM_SPOTTER: 'scam_spotter',
    THREAT_HUNTER: 'threat_hunter',
    FIREWALL_COMMANDER: 'firewall_commander',
    PRIVACY_GUARDIAN: 'privacy_guardian',
    CRYPTO_DEFENDER: 'crypto_defender',
    SOCIAL_SENTINEL: 'social_sentinel'
  },

  // API Rate Limits
  RATE_LIMITS: {
    AUTH: 5, // 5 attempts per 15 minutes
    GAME: 50, // 50 requests per 15 minutes
    THREAT: 100 // 100 requests per 15 minutes
  }
};