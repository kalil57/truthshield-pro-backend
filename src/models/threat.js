const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: [
      'phishing',
      'malware',
      'social_engineering',
      'privacy_violation',
      'financial_scam',
      'predator_behavior',
      'inappropriate_content',
      'data_breach'
    ]
  },
  severity: {
    type: String,
    required: true,
    enum: ['low', 'medium', 'high', 'critical']
  },
  source: {
    type: String,
    required: true,
    enum: ['email', 'website', 'social_media', 'message', 'app', 'other']
  },
  url: {
    type: String,
    required: function() {
      return this.source === 'website' || this.source === 'social_media';
    }
  },
  domain: String,
  detectedContent: {
    type: String,
    required: true
  },
  indicators: [{
    type: String,
    required: true
  }],
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  ageGroup: {
    type: String,
    required: true,
    enum: ['child', 'teen', 'adult', 'senior']
  },
  actionTaken: {
    type: String,
    enum: ['blocked', 'warned', 'reported', 'ignored'],
    default: 'blocked'
  },
  confidence: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  aiAnalysis: {
    riskFactors: [String],
    behavioralPatterns: [String],
    recommendedAction: String,
    analysisTimestamp: Date
  },
  location: {
    ipAddress: String,
    country: String,
    region: String,
    city: String
  },
  deviceInfo: {
    userAgent: String,
    platform: String,
    browser: String
  },
  isFalsePositive: {
    type: Boolean,
    default: false
  },
  resolved: {
    type: Boolean,
    default: false
  },
  resolvedAt: Date
}, {
  timestamps: true
});

// Indexes for efficient querying
threatSchema.index({ user: 1, createdAt: -1 });
threatSchema.index({ type: 1, severity: 1 });
threatSchema.index({ domain: 1 });
threatSchema.index({ createdAt: -1 });
threatSchema.index({ 'aiAnalysis.riskFactors': 1 });

// Static method to get threat statistics
threatSchema.statics.getThreatStats = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return this.aggregate([
    {
      $match: {
        user: mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate },
        isFalsePositive: false
      }
    },
    {
      $group: {
        _id: '$type',
        count: { $sum: 1 },
        averageConfidence: { $avg: '$confidence' },
        severityBreakdown: {
          $push: '$severity'
        }
      }
    },
    {
      $project: {
        type: '$_id',
        count: 1,
        averageConfidence: { $round: ['$averageConfidence', 2] },
        severityBreakdown: 1,
        _id: 0
      }
    }
  ]);
};

// Static method to get common indicators
threatSchema.statics.getCommonIndicators = async function(limit = 10) {
  return this.aggregate([
    { $unwind: '$indicators' },
    {
      $group: {
        _id: '$indicators',
        count: { $sum: 1 },
        severity: { $avg: { 
          $switch: {
            branches: [
              { case: { $eq: ['$severity', 'low'] }, then: 1 },
              { case: { $eq: ['$severity', 'medium'] }, then: 2 },
              { case: { $eq: ['$severity', 'high'] }, then: 3 },
              { case: { $eq: ['$severity', 'critical'] }, then: 4 }
            ],
            default: 0
          }
        }}
      }
    },
    { $sort: { count: -1 } },
    { $limit: limit },
    {
      $project: {
        indicator: '$_id',
        count: 1,
        averageSeverity: { $round: ['$severity', 2] },
        _id: 0
      }
    }
  ]);
};

module.exports = mongoose.model('Threat', threatSchema);