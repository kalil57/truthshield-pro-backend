const natural = require('natural');
const axios = require('axios');

// Initialize natural language processing tools
const tokenizer = new natural.WordTokenizer();
const TfIdf = natural.TfIdf;
const tfidf = new TfIdf();

// Threat patterns database
const THREAT_PATTERNS = {
  phishing: {
    keywords: [
      'verify your account', 'password expiration', 'suspended account',
      'urgent action required', 'click here', 'limited time offer',
      'free gift', 'account verification', 'security alert',
      'unauthorized login attempt', 'update your information'
    ],
    domains: ['paypal-security.com', 'apple-verify.net', 'amazon-update.com'],
    patterns: [
      /verify.*account/i,
      /password.*expir/i,
      /suspended.*account/i,
      /urgent.*action/i,
      /click.*here/i,
      /free.*gift/i
    ]
  },
  malware: {
    keywords: [
      'virus detected', 'system infected', 'download now',
      'install update', 'security patch', 'anti-virus',
      'pc scan', 'remove threats', 'system cleaner'
    ],
    patterns: [
      /virus.*detected/i,
      /system.*infected/i,
      /download.*now/i,
      /install.*update/i
    ]
  },
  social_engineering: {
    keywords: [
      'trust me', 'emergency', 'quick money',
      'guaranteed profit', 'no risk', 'limited spots',
      'exclusive offer', 'once in a lifetime'
    ],
    patterns: [
      /trust.*me/i,
      /emergency.*need/i,
      /quick.*money/i,
      /guaranteed.*profit/i
    ]
  },
  financial_scam: {
    keywords: [
      'investment opportunity', 'bitcoin', 'crypto',
      'double your money', 'risk-free', 'get rich quick',
      'stock tips', 'forex trading', 'binary options'
    ],
    patterns: [
      /investment.*opportunity/i,
      /double.*money/i,
      /risk-free/i,
      /get.*rich.*quick/i
    ]
  },
  predator_behavior: {
    keywords: [
      'where do you live', 'how old are you', 'send picture',
      'meet in person', 'keep this secret', 'your parents',
      'alone tonight', 'private chat'
    ],
    patterns: [
      /where.*live/i,
      /how.*old/i,
      /send.*picture/i,
      /meet.*person/i,
      /keep.*secret/i
    ]
  }
};

class AIDetectionEngine {
  constructor() {
    this.confidenceThreshold = 0.7;
    this.initialized = false;
    this.init();
  }

  async init() {
    // Train the TF-IDF model with sample data
    const trainingData = [
      { text: 'verify your account now urgent action required', category: 'phishing' },
      { text: 'your password will expire soon click here', category: 'phishing' },
      { text: 'virus detected on your computer download antivirus', category: 'malware' },
      { text: 'system infected install security update now', category: 'malware' },
      { text: 'investment opportunity double your money fast', category: 'financial_scam' },
      { text: 'bitcoin trading guaranteed profits no risk', category: 'financial_scam' },
      { text: 'where do you live can we meet alone', category: 'predator_behavior' },
      { text: 'how old are you send me your picture', category: 'predator_behavior' }
    ];

    trainingData.forEach(item => {
      tfidf.addDocument(item.text, item.category);
    });

    this.initialized = true;
    console.log('✅ AI Detection Engine initialized');
  }

  async analyzeContent(content, context = {}) {
    if (!this.initialized) {
      await this.init();
    }

    const analysis = {
      threats: [],
      confidence: 0,
      riskLevel: 'low',
      indicators: [],
      recommendations: []
    };

    // Check for each threat type
    for (const [threatType, patterns] of Object.entries(THREAT_PATTERNS)) {
      const threatResult = this.detectThreatType(content, threatType, patterns);
      if (threatResult.detected) {
        analysis.threats.push({
          type: threatType,
          confidence: threatResult.confidence,
          indicators: threatResult.indicators,
          severity: this.calculateSeverity(threatType, threatResult.confidence)
        });
      }
    }

    // Use TF-IDF for additional classification
    const tfidfResults = this.classifyWithTFIDF(content);
    if (tfidfResults.confidence > this.confidenceThreshold) {
      analysis.threats.push({
        type: tfidfResults.category,
        confidence: tfidfResults.confidence,
        indicators: ['AI-pattern-detected'],
        severity: this.calculateSeverity(tfidfResults.category, tfidfResults.confidence)
      });
    }

    // Calculate overall risk level
    analysis.confidence = this.calculateOverallConfidence(analysis.threats);
    analysis.riskLevel = this.determineRiskLevel(analysis.threats);
    analysis.recommendations = this.generateRecommendations(analysis.threats);

    return analysis;
  }

  detectThreatType(content, threatType, patterns) {
    const result = {
      detected: false,
      confidence: 0,
      indicators: []
    };

    const lowerContent = content.toLowerCase();
    let matchCount = 0;
    let totalPatterns = patterns.keywords.length + patterns.patterns.length;

    // Check keywords
    patterns.keywords.forEach(keyword => {
      if (lowerContent.includes(keyword.toLowerCase())) {
        matchCount++;
        result.indicators.push(`keyword: ${keyword}`);
      }
    });

    // Check regex patterns
    patterns.patterns.forEach((pattern, index) => {
      if (pattern.test(content)) {
        matchCount++;
        result.indicators.push(`pattern_${index + 1}`);
      }
    });

    // Check domains if provided
    if (patterns.domains) {
      const urlRegex = /https?:\/\/([^\/\s]+)/g;
      let match;
      while ((match = urlRegex.exec(content)) !== null) {
        const domain = match[1];
        if (patterns.domains.some(badDomain => domain.includes(badDomain))) {
          matchCount += 2; // Higher weight for domain matches
          result.indicators.push(`suspicious_domain: ${domain}`);
        }
      }
    }

    // Calculate confidence
    if (totalPatterns > 0) {
      result.confidence = matchCount / totalPatterns;
      result.detected = result.confidence > this.confidenceThreshold;
    }

    return result;
  }

  classifyWithTFIDF(content) {
    const scores = {};
    let totalScore = 0;

    tfidf.tfidfs(content, (i, measure) => {
      const category = tfidf.documents[i].category;
      scores[category] = (scores[category] || 0) + measure;
      totalScore += Math.abs(measure);
    });

    // Find the highest scoring category
    let maxScore = 0;
    let bestCategory = null;

    for (const [category, score] of Object.entries(scores)) {
      if (score > maxScore) {
        maxScore = score;
        bestCategory = category;
      }
    }

    const confidence = totalScore > 0 ? maxScore / totalScore : 0;

    return {
      category: bestCategory,
      confidence: confidence,
      scores: scores
    };
  }

  calculateSeverity(threatType, confidence) {
    const baseSeverity = {
      phishing: 'high',
      malware: 'high',
      financial_scam: 'medium',
      social_engineering: 'medium',
      predator_behavior: 'critical'
    }[threatType] || 'low';

    // Adjust based on confidence
    if (confidence > 0.9) {
      if (baseSeverity === 'medium') return 'high';
      if (baseSeverity === 'high') return 'critical';
    }

    return baseSeverity;
  }

  calculateOverallConfidence(threats) {
    if (threats.length === 0) return 0;

    const totalConfidence = threats.reduce((sum, threat) => sum + threat.confidence, 0);
    return totalConfidence / threats.length;
  }

  determineRiskLevel(threats) {
    if (threats.length === 0) return 'low';

    const severityWeights = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4
    };

    const weightedScore = threats.reduce((score, threat) => {
      return score + (threat.confidence * severityWeights[threat.severity]);
    }, 0);

    if (weightedScore >= 3) return 'critical';
    if (weightedScore >= 2) return 'high';
    if (weightedScore >= 1) return 'medium';
    return 'low';
  }

  generateRecommendations(threats) {
    const recommendations = [];

    threats.forEach(threat => {
      switch (threat.type) {
        case 'phishing':
          recommendations.push('Do not click any links in this message');
          recommendations.push('Verify the sender through official channels');
          recommendations.push('Report this as phishing to the platform');
          break;
        case 'malware':
          recommendations.push('Do not download any attachments');
          recommendations.push('Run a security scan on your device');
          recommendations.push('Keep your antivirus software updated');
          break;
        case 'predator_behavior':
          recommendations.push('Do not share personal information');
          recommendations.push('Block and report this user immediately');
          recommendations.push('Inform a trusted adult about this interaction');
          break;
        case 'financial_scam':
          recommendations.push('Be cautious of investment opportunities');
          recommendations.push('Research the company through official sources');
          recommendations.push('Never send money to unknown individuals');
          break;
      }
    });

    // Remove duplicates
    return [...new Set(recommendations)];
  }

  async analyzeBehavioralPatterns(userData, context) {
    // Advanced behavioral analysis
    const patterns = {
      unusualTiming: this.checkUnusualTiming(context.timestamp),
      rapidMessages: this.checkRapidMessaging(context.messageHistory),
      informationGathering: this.checkInformationGathering(context.conversation),
      pressureTactics: this.checkPressureTactics(context.content)
    };

    const riskFactors = Object.entries(patterns)
      .filter(([_, isRisky]) => isRisky)
      .map(([pattern, _]) => pattern);

    return {
      behavioralRisks: riskFactors,
      overallBehavioralRisk: riskFactors.length > 2 ? 'high' : riskFactors.length > 0 ? 'medium' : 'low',
      patterns: patterns
    };
  }

  checkUnusualTiming(timestamp) {
    const hour = new Date(timestamp).getHours();
    return hour < 6 || hour > 23; // Unusual if between 11 PM and 6 AM
  }

  checkRapidMessaging(messageHistory) {
    if (!messageHistory || messageHistory.length < 3) return false;
    
    const recentMessages = messageHistory.slice(-3);
    const timeDiff = recentMessages[2].timestamp - recentMessages[0].timestamp;
    return timeDiff < 30000; // 3 messages in 30 seconds
  }

  checkInformationGathering(conversation) {
    const infoQuestions = [
      'where do you live', 'what school', 'how old are you',
      'your parents', 'home alone', 'your address'
    ];
    
    return infoQuestions.some(question => 
      conversation.toLowerCase().includes(question)
    );
  }

  checkPressureTactics(content) {
    const pressureIndicators = [
      'right now', 'immediately', 'hurry',
      'last chance', 'limited time', 'now or never'
    ];
    
    return pressureIndicators.some(indicator => 
      content.toLowerCase().includes(indicator)
    );
  }
}

module.exports = new AIDetectionEngine();