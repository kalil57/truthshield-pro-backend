const express = require('express');
const Threat = require('../models/Threat');
const User = require('../models/User');
const { protect } = require('../middleware/auth');
const { validateThreatReport, validatePagination } = require('../middleware/validation');
const aiDetectionEngine = require('../utils/ai-detection');
const helperUtils = require('../utils/helpers');

const router = express.Router();

// @desc    Report a new threat
// @route   POST /api/threats/report
// @access  Private
router.post('/report', protect, validateThreatReport, async (req, res) => {
  try {
    const {
      type,
      severity,
      source,
      url,
      domain,
      detectedContent,
      indicators,
      location,
      deviceInfo,
      confidence = 0
    } = req.body;

    // AI Analysis
    const aiAnalysis = await aiDetectionEngine.analyzeContent(detectedContent, {
      timestamp: new Date(),
      user: req.user
    });

    // Create threat record
    const threat = await Threat.create({
      type,
      severity: aiAnalysis.riskLevel || severity,
      source,
      url,
      domain,
      detectedContent: helperUtils.sanitizeInput(detectedContent),
      indicators,
      user: req.user.id,
      ageGroup: req.user.ageGroup,
      confidence: Math.max(confidence, aiAnalysis.confidence * 100),
      aiAnalysis: {
        riskFactors: aiAnalysis.indicators,
        behavioralPatterns: aiAnalysis.threats.map(t => t.type),
        recommendedAction: aiAnalysis.recommendations[0] || 'Review and block if necessary',
        analysisTimestamp: new Date()
      },
      location,
      deviceInfo
    });

    // Update user's security metrics
    await User.findByIdAndUpdate(req.user.id, {
      lastActive: new Date()
    });

    res.status(201).json(
      helperUtils.successResponse('Threat reported successfully', {
        threat,
        aiAnalysis: {
          riskLevel: aiAnalysis.riskLevel,
          confidence: aiAnalysis.confidence,
          recommendations: aiAnalysis.recommendations
        }
      })
    );
  } catch (error) {
    console.error('Report threat error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to report threat')
    );
  }
});

// @desc    Analyze content for threats
// @route   POST /api/threats/analyze
// @access  Private
router.post('/analyze', protect, async (req, res) => {
  try {
    const { content, context = {} } = req.body;

    if (!content) {
      return res.status(400).json(
        helperUtils.errorResponse('Content is required for analysis')
      );
    }

    // Perform AI analysis
    const analysis = await aiDetectionEngine.analyzeContent(content, {
      ...context,
      user: req.user,
      timestamp: new Date()
    });

    // If high risk, automatically create threat record
    let threatRecord = null;
    if (analysis.riskLevel === 'high' || analysis.riskLevel === 'critical') {
      threatRecord = await Threat.create({
        type: analysis.threats[0]?.type || 'social_engineering',
        severity: analysis.riskLevel,
        source: context.source || 'unknown',
        detectedContent: helperUtils.sanitizeInput(content),
        indicators: analysis.indicators,
        user: req.user.id,
        ageGroup: req.user.ageGroup,
        confidence: analysis.confidence * 100,
        aiAnalysis: {
          riskFactors: analysis.indicators,
          behavioralPatterns: analysis.threats.map(t => t.type),
          recommendedAction: analysis.recommendations[0],
          analysisTimestamp: new Date()
        },
        actionTaken: 'warned'
      });
    }

    res.status(200).json(
      helperUtils.successResponse('Content analyzed successfully', {
        analysis,
        threatRecord: threatRecord ? {
          id: threatRecord._id,
          severity: threatRecord.severity,
          actionTaken: threatRecord.actionTaken
        } : null
      })
    );
  } catch (error) {
    console.error('Analyze content error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to analyze content')
    );
  }
});

// @desc    Get user's threat history
// @route   GET /api/threats/history
// @access  Private
router.get('/history', protect, validatePagination, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const { type, severity, resolved } = req.query;

    // Build filter
    const filter = { user: req.user.id };
    if (type) filter.type = type;
    if (severity) filter.severity = severity;
    if (resolved !== undefined) filter.resolved = resolved === 'true';

    const threats = await Threat.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Threat.countDocuments(filter);

    res.status(200).json(
      helperUtils.successResponse('Threat history retrieved', {
        threats,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );
  } catch (error) {
    console.error('Get threat history error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve threat history')
    );
  }
});

// @desc    Get threat statistics
// @route   GET /api/threats/stats
// @access  Private
router.get('/stats', protect, async (req, res) => {
  try {
    const { days = 30 } = req.query;

    const stats = await Threat.getThreatStats(req.user.id, parseInt(days));
    const commonIndicators = await Threat.getCommonIndicators();

    // Overall stats
    const totalThreats = await Threat.countDocuments({
      user: req.user.id,
      isFalsePositive: false
    });
    const blockedThreats = await Threat.countDocuments({
      user: req.user.id,
      actionTaken: 'blocked',
      isFalsePositive: false
    });
    const criticalThreats = await Threat.countDocuments({
      user: req.user.id,
      severity: 'critical',
      isFalsePositive: false
    });

    res.status(200).json(
      helperUtils.successResponse('Threat statistics retrieved', {
        overview: {
          totalThreats,
          blockedThreats,
          criticalThreats,
          protectionRate: totalThreats > 0 ? (blockedThreats / totalThreats * 100).toFixed(1) : 100
        },
        byType: stats,
        commonIndicators,
        timeRange: `${days} days`
      })
    );
  } catch (error) {
    console.error('Get threat stats error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve threat statistics')
    );
  }
});

// @desc    Update threat status
// @route   PUT /api/threats/:threatId
// @access  Private
router.put('/:threatId', protect, async (req, res) => {
  try {
    const { threatId } = req.params;
    const { actionTaken, resolved, isFalsePositive } = req.body;

    const threat = await Threat.findOne({
      _id: threatId,
      user: req.user.id
    });

    if (!threat) {
      return res.status(404).json(
        helperUtils.errorResponse('Threat not found')
      );
    }

    // Update fields
    const updates = {};
    if (actionTaken) updates.actionTaken = actionTaken;
    if (resolved !== undefined) {
      updates.resolved = resolved;
      updates.resolvedAt = resolved ? new Date() : null;
    }
    if (isFalsePositive !== undefined) updates.isFalsePositive = isFalsePositive;

    const updatedThreat = await Threat.findByIdAndUpdate(
      threatId,
      updates,
      { new: true, runValidators: true }
    );

    res.status(200).json(
      helperUtils.successResponse('Threat updated successfully', {
        threat: updatedThreat
      })
    );
  } catch (error) {
    console.error('Update threat error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to update threat')
    );
  }
});

// @desc    Get real-time threat alerts
// @route   GET /api/threats/alerts
// @access  Private
router.get('/alerts', protect, async (req, res) => {
  try {
    const { hours = 24 } = req.query;
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);

    const alerts = await Threat.find({
      user: req.user.id,
      createdAt: { $gte: since },
      severity: { $in: ['high', 'critical'] },
      isFalsePositive: false
    })
    .sort({ createdAt: -1 })
    .limit(50);

    res.status(200).json(
      helperUtils.successResponse('Threat alerts retrieved', {
        alerts,
        timeRange: `last ${hours} hours`
      })
    );
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve threat alerts')
    );
  }
});

// @desc    Get global threat intelligence
// @route   GET /api/threats/intelligence
// @access  Private
router.get('/intelligence', protect, async (req, res) => {
  try {
    // Get recent threats from all users (anonymized)
    const recentThreats = await Threat.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
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
          },
          commonIndicators: { $push: '$indicators' }
        }
      },
      {
        $project: {
          type: '$_id',
          count: 1,
          averageConfidence: { $round: ['$averageConfidence', 2] },
          severityBreakdown: 1,
          commonIndicators: {
            $slice: [
              {
                $reduce: {
                  input: '$commonIndicators',
                  initialValue: [],
                  in: { $concatArrays: ['$$value', '$$this'] }
                }
              },
              10
            ]
          },
          _id: 0
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get trending threats
    const trendingThreats = await Threat.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
          isFalsePositive: false
        }
      },
      {
        $group: {
          _id: {
            type: '$type',
            day: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
          },
          count: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: '$_id.type',
          trend: {
            $push: {
              day: '$_id.day',
              count: '$count'
            }
          },
          total: { $sum: '$count' }
        }
      },
      {
        $project: {
          type: '$_id',
          trend: 1,
          total: 1,
          growth: {
            $cond: {
              if: { $gt: [{ $size: '$trend' }, 1] },
              then: {
                $divide: [
                  {
                    $subtract: [
                      { $arrayElemAt: ['$trend.count', -1] },
                      { $arrayElemAt: ['$trend.count', 0] }
                    ]
                  },
                  { $arrayElemAt: ['$trend.count', 0] }
                ]
              },
              else: 0
            }
          },
          _id: 0
        }
      },
      { $sort: { total: -1 } },
      { $limit: 5 }
    ]);

    res.status(200).json(
      helperUtils.successResponse('Threat intelligence retrieved', {
        recentThreats,
        trendingThreats,
        lastUpdated: new Date().toISOString()
      })
    );
  } catch (error) {
    console.error('Get threat intelligence error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve threat intelligence')
    );
  }
});

module.exports = router;