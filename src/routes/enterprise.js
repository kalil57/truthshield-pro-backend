const express = require('express');
const User = require('../models/User');
const Threat = require('../models/Threat');
const GameSession = require('../models/GameSession');
const { protect } = require('../middleware/auth');
const helperUtils = require('../utils/helpers');

const router = express.Router();

// @desc    Get enterprise dashboard
// @route   GET /api/enterprise/dashboard
// @access  Private
router.get('/dashboard', protect, async (req, res) => {
  try {
    // Check if user is enterprise admin
    if (req.user.persona !== 'enterprise' || !req.user.enterprise.isAdmin) {
      return res.status(403).json(
        helperUtils.errorResponse('Enterprise access required')
      );
    }

    // Get all users in the same company
    const companyUsers = await User.find({
      'enterprise.company': req.user.enterprise.company
    }).select('firstName lastName email department securityScore level lastActive gameProgress');

    // Calculate company statistics
    const totalEmployees = companyUsers.length;
    const averageSecurityScore = companyUsers.reduce((sum, user) => sum + user.securityScore, 0) / totalEmployees;
    const activeUsers = companyUsers.filter(user => 
      new Date(user.lastActive) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    ).length;

    // Get threat statistics
    const companyThreats = await Threat.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: 'user',
          foreignField: '_id',
          as: 'userInfo'
        }
      },
      { $unwind: '$userInfo' },
      {
        $match: {
          'userInfo.enterprise.company': req.user.enterprise.company,
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 },
          severityBreakdown: {
            $push: '$severity'
          }
        }
      }
    ]);

    // Get training completion stats
    const trainingStats = await GameSession.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: 'user',
          foreignField: '_id',
          as: 'userInfo'
        }
      },
      { $unwind: '$userInfo' },
      {
        $match: {
          'userInfo.enterprise.company': req.user.enterprise.company,
          completed: true
        }
      },
      {
        $group: {
          _id: '$gameType',
          totalSessions: { $sum: 1 },
          averageScore: { $avg: '$score' },
          uniqueUsers: { $addToSet: '$user' }
        }
      }
    ]);

    const dashboard = {
      overview: {
        totalEmployees,
        activeUsers,
        activeRate: ((activeUsers / totalEmployees) * 100).toFixed(1),
        averageSecurityScore: Math.round(averageSecurityScore),
        company: req.user.enterprise.company
      },
      threats: {
        byType: companyThreats,
        totalThreats: companyThreats.reduce((sum, threat) => sum + threat.count, 0),
        timeRange: 'last 30 days'
      },
      training: {
        byGame: trainingStats,
        totalSessions: trainingStats.reduce((sum, game) => sum + game.totalSessions, 0),
        uniqueTrainedUsers: new Set(trainingStats.flatMap(game => game.uniqueUsers)).size
      },
      employees: companyUsers.map(user => ({
        id: user._id,
        name: `${user.firstName} ${user.lastName}`,
        department: user.enterprise.department,
        securityScore: user.securityScore,
        level: user.level,
        lastActive: user.lastActive,
        trainingProgress: Object.values(user.gameProgress).filter(game => game.completed).length
      }))
    };

    res.status(200).json(
      helperUtils.successResponse('Enterprise dashboard retrieved', {
        dashboard
      })
    );
  } catch (error) {
    console.error('Get enterprise dashboard error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve enterprise dashboard')
    );
  }
});

// @desc    Get employee security report
// @route   GET /api/enterprise/employees/:employeeId/report
// @access  Private
router.get('/employees/:employeeId/report', protect, async (req, res) => {
  try {
    const { employeeId } = req.params;

    // Verify the employee belongs to the same company and requester is admin
    const employee = await User.findOne({
      _id: employeeId,
      'enterprise.company': req.user.enterprise.company
    });

    if (!employee) {
      return res.status(404).json(
        helperUtils.errorResponse('Employee not found')
      );
    }

    if (!req.user.enterprise.isAdmin) {
      return res.status(403).json(
        helperUtils.errorResponse('Admin access required')
      );
    }

    // Get employee's threat history
    const threatHistory = await Threat.find({ user: employeeId })
      .sort({ createdAt: -1 })
      .limit(50);

    // Get employee's game progress
    const gameProgress = await GameSession.aggregate([
      { $match: { user: employee._id } },
      {
        $group: {
          _id: '$gameType',
          totalSessions: { $sum: 1 },
          completedSessions: { $sum: { $cond: ['$completed', 1, 0] } },
          bestScore: { $max: '$score' },
          averageScore: { $avg: '$score' },
          lastPlayed: { $max: '$createdAt' }
        }
      }
    ]);

    // Calculate risk assessment
    const riskLevel = calculateEmployeeRisk(employee, threatHistory, gameProgress);

    const report = {
      employee: {
        name: `${employee.firstName} ${employee.lastName}`,
        department: employee.enterprise.department,
        email: employee.email,
        securityScore: employee.securityScore,
        level: employee.level,
        lastActive: employee.lastActive
      },
      riskAssessment: riskLevel,
      training: {
        progress: gameProgress,
        completedGames: Object.values(employee.gameProgress).filter(game => game.completed).length,
        totalGames: 6 // Total number of games available
      },
      threats: {
        history: threatHistory.slice(0, 10), // Last 10 threats
        total: threatHistory.length,
        critical: threatHistory.filter(t => t.severity === 'critical').length,
        recent: threatHistory.filter(t => 
          new Date(t.createdAt) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
        ).length
      },
      recommendations: generateEmployeeRecommendations(employee, threatHistory, gameProgress)
    };

    res.status(200).json(
      helperUtils.successResponse('Employee security report generated', {
        report,
        generatedAt: new Date().toISOString()
      })
    );
  } catch (error) {
    console.error('Get employee report error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to generate employee report')
    );
  }
});

// Helper function to calculate employee risk
function calculateEmployeeRisk(employee, threatHistory, gameProgress) {
  let riskScore = 0;

  // Base risk from security score
  riskScore += (100 - employee.securityScore) * 0.5;

  // Risk from recent threats
  const recentThreats = threatHistory.filter(t => 
    new Date(t.createdAt) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
  );
  riskScore += recentThreats.length * 10;

  // Risk from critical threats
  const criticalThreats = threatHistory.filter(t => t.severity === 'critical');
  riskScore += criticalThreats.length * 20;

  // Risk from incomplete training
  const completedGames = gameProgress.filter(game => game.completedSessions > 0).length;
  riskScore += (6 - completedGames) * 5;

  // Risk from inactivity
  const daysSinceActive = Math.floor(
    (new Date() - new Date(employee.lastActive)) / (1000 * 60 * 60 * 24)
  );
  if (daysSinceActive > 30) {
    riskScore += 25;
  }

  if (riskScore >= 70) return 'high';
  if (riskScore >= 40) return 'medium';
  return 'low';
}

// Helper function to generate employee recommendations
function generateEmployeeRecommendations(employee, threatHistory, gameProgress) {
  const recommendations = [];

  if (employee.securityScore < 50) {
    recommendations.push({
      type: 'basic_training',
      priority: 'high',
      message: 'Low security score detected',
      action: 'Complete basic security training games'
    });
  }

  const recentThreats = threatHistory.filter(t => 
    new Date(t.createdAt) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
  );
  if (recentThreats.length > 3) {
    recommendations.push({
      type: 'threat_awareness',
      priority: 'high',
      message: 'High number of recent threats',
      action: 'Review threat patterns and security practices'
    });
  }

  const completedGames = gameProgress.filter(game => game.completedSessions > 0).length;
  if (completedGames < 3) {
    recommendations.push({
      type: 'training_completion',
      priority: 'medium',
      message: 'Incomplete security training',
      action: `Complete ${3 - completedGames} more security games`
    });
  }

  return recommendations;
}

module.exports = router;