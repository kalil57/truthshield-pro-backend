const axios = require('axios');

class HelperUtils {
  // Response formatting
  formatResponse(status, message, data = null, meta = null) {
    const response = {
      status,
      message,
      timestamp: new Date().toISOString()
    };

    if (data !== null) {
      response.data = data;
    }

    if (meta !== null) {
      response.meta = meta;
    }

    return response;
  }

  successResponse(message, data = null, meta = null) {
    return this.formatResponse('success', message, data, meta);
  }

  errorResponse(message, errorCode = null) {
    const response = {
      status: 'error',
      message,
      timestamp: new Date().toISOString()
    };

    if (errorCode) {
      response.errorCode = errorCode;
    }

    return response;
  }

  // Pagination helper
  paginate(array, page = 1, limit = 10) {
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const results = {};

    if (endIndex < array.length) {
      results.next = {
        page: page + 1,
        limit: limit
      };
    }

    if (startIndex > 0) {
      results.previous = {
        page: page - 1,
        limit: limit
      };
    }

    results.total = array.length;
    results.totalPages = Math.ceil(array.length / limit);
    results.currentPage = page;
    results.data = array.slice(startIndex, endIndex);

    return results;
  }

  // Validation helpers
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  isValidURL(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  }

  isStrongPassword(password) {
    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return strongPasswordRegex.test(password);
  }

  // Age group classification
  getAgeGroup(age) {
    if (age >= 6 && age <= 12) return 'child';
    if (age >= 13 && age <= 17) return 'teen';
    if (age >= 18 && age <= 64) return 'adult';
    if (age >= 65) return 'senior';
    return 'unknown';
  }

  // Difficulty calculation based on age and performance
  calculateDifficulty(ageGroup, currentPerformance) {
    const baseDifficulty = {
      'child': 'easy',
      'teen': 'medium',
      'adult': 'hard',
      'senior': 'medium'
    }[ageGroup] || 'medium';

    // Adjust based on performance
    if (currentPerformance > 80) {
      const difficulties = ['easy', 'medium', 'hard', 'expert'];
      const currentIndex = difficulties.indexOf(baseDifficulty);
      return difficulties[Math.min(currentIndex + 1, difficulties.length - 1)];
    } else if (currentPerformance < 40) {
      const difficulties = ['easy', 'medium', 'hard', 'expert'];
      const currentIndex = difficulties.indexOf(baseDifficulty);
      return difficulties[Math.max(currentIndex - 1, 0)];
    }

    return baseDifficulty;
  }

  // Experience points calculation
  calculateXP(score, difficulty, timeSpent) {
    const baseXP = score / 10;
    const difficultyMultiplier = {
      'easy': 1,
      'medium': 1.5,
      'hard': 2,
      'expert': 3
    }[difficulty] || 1;

    const timeBonus = Math.max(0, (300 - timeSpent) / 10); // Bonus for faster completion

    return Math.round(baseXP * difficultyMultiplier + timeBonus);
  }

  // Security score calculation
  calculateSecurityScore(gameProgress) {
    let totalScore = 0;
    let gameCount = 0;

    Object.values(gameProgress).forEach(game => {
      if (game.score > 0) {
        totalScore += game.score;
        gameCount++;
      }
    });

    return gameCount > 0 ? Math.round(totalScore / gameCount) : 0;
  }

  // Threat level classification
  classifyThreatLevel(confidence, impact) {
    if (confidence >= 0.9 && impact === 'high') return 'critical';
    if (confidence >= 0.7 && impact === 'high') return 'high';
    if (confidence >= 0.7 && impact === 'medium') return 'high';
    if (confidence >= 0.5) return 'medium';
    return 'low';
  }

  // Date and time helpers
  formatDate(date) {
    return new Date(date).toISOString().split('T')[0];
  }

  formatDateTime(date) {
    return new Date(date).toISOString();
  }

  isToday(date) {
    const today = new Date();
    const compareDate = new Date(date);
    return today.toDateString() === compareDate.toDateString();
  }

  isThisWeek(date) {
    const today = new Date();
    const compareDate = new Date(date);
    const startOfWeek = new Date(today.setDate(today.getDate() - today.getDay()));
    return compareDate >= startOfWeek;
  }

  // Performance monitoring
  async measurePerformance(fn, ...args) {
    const start = process.hrtime();
    const result = await fn(...args);
    const end = process.hrtime(start);
    
    const executionTime = (end[0] * 1000) + (end[1] / 1000000); // Convert to milliseconds
    
    return {
      result,
      executionTime: `${executionTime.toFixed(2)}ms`
    };
  }

  // Error handling wrapper
  async handleAsync(fn, errorMessage = 'Operation failed') {
    try {
      return await fn();
    } catch (error) {
      console.error(`${errorMessage}:`, error);
      throw new Error(errorMessage);
    }
  }

  // Data sanitization
  sanitizeInput(input) {
    if (typeof input === 'string') {
      return input
        .trim()
        .replace(/[<>]/g, '') // Remove < and >
        .substring(0, 5000); // Limit length
    }
    return input;
  }

  // Deep object cloning
  deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  // Random element from array
  getRandomElement(array) {
    return array[Math.floor(Math.random() * array.length)];
  }

  // Shuffle array
  shuffleArray(array) {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }

  // Delay helper
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // URL parameter extraction
  getURLParams(url) {
    try {
      const urlObj = new URL(url);
      const params = {};
      urlObj.searchParams.forEach((value, key) => {
        params[key] = value;
      });
      return params;
    } catch (error) {
      return {};
    }
  }

  // User agent parsing
  parseUserAgent(userAgent) {
    return {
      browser: this.getBrowser(userAgent),
      platform: this.getPlatform(userAgent),
      isMobile: /Mobile|Android|iPhone/i.test(userAgent)
    };
  }

  getBrowser(userAgent) {
    if (/Chrome/.test(userAgent)) return 'Chrome';
    if (/Firefox/.test(userAgent)) return 'Firefox';
    if (/Safari/.test(userAgent)) return 'Safari';
    if (/Edge/.test(userAgent)) return 'Edge';
    return 'Unknown';
  }

  getPlatform(userAgent) {
    if (/Windows/.test(userAgent)) return 'Windows';
    if (/Macintosh/.test(userAgent)) return 'Mac';
    if (/Linux/.test(userAgent)) return 'Linux';
    if (/Android/.test(userAgent)) return 'Android';
    if (/iPhone|iPad/.test(userAgent)) return 'iOS';
    return 'Unknown';
  }
}

module.exports = new HelperUtils();