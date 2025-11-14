const express = require('express');
const Family = require('../models/Family');
const User = require('../models/User');
const { protect, authorizeFamily } = require('../middleware/auth');
const { validateFamilyCreation, validateObjectId } = require('../middleware/validation');
const helperUtils = require('../utils/helpers');

const router = express.Router();

// @desc    Create a new family
// @route   POST /api/family/create
// @access  Private
router.post('/create', protect, validateFamilyCreation, async (req, res) => {
  try {
    const { familyName, children } = req.body;

    // Check if user already has a family
    const existingFamily = await Family.findOne({ parent: req.user.id });
    if (existingFamily) {
      return res.status(400).json(
        helperUtils.errorResponse('You already have a family group')
      );
    }

    // Verify children users exist and are not already in other families
    if (children && children.length > 0) {
      for (const childData of children) {
        const childUser = await User.findById(childData.childId);
        if (!childUser) {
          return res.status(404).json(
            helperUtils.errorResponse(`Child user with ID ${childData.childId} not found`)
          );
        }

        // Check if child is already in a family
        const childInFamily = await Family.findOne({ 'children.child': childData.childId });
        if (childInFamily) {
          return res.status(400).json(
            helperUtils.errorResponse(`User ${childUser.firstName} is already in a family`)
          );
        }
      }
    }

    // Create family
    const family = await Family.create({
      familyName,
      parent: req.user.id,
      children: children || []
    });

    // Update user persona to parent
    await User.findByIdAndUpdate(req.user.id, {
      persona: 'parent',
      'family.isParent': true
    });

    res.status(201).json(
      helperUtils.successResponse('Family created successfully', {
        family
      })
    );
  } catch (error) {
    console.error('Create family error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to create family')
    );
  }
});

// @desc    Get family dashboard
// @route   GET /api/family/dashboard
// @access  Private
router.get('/dashboard', protect, async (req, res) => {
  try {
    let family;

    // Check if user is a parent
    if (req.user.persona === 'parent') {
      family = await Family.findOne({ parent: req.user.id })
        .populate('parent', 'firstName lastName email ageGroup securityScore level')
        .populate('children.child', 'firstName lastName age ageGroup securityScore level gameProgress lastActive');
    } else {
      // User is a child, find family they belong to
      family = await Family.findOne({ 'children.child': req.user.id })
        .populate('parent', 'firstName lastName email ageGroup securityScore level')
        .populate('children.child', 'firstName lastName age ageGroup securityScore level gameProgress lastActive');
    }

    if (!family) {
      return res.status(404).json(
        helperUtils.errorResponse('Family not found')
      );
    }

    // Update family stats
    await family.updateFamilyStats();

    res.status(200).json(
      helperUtils.successResponse('Family dashboard retrieved', {
        family
      })
    );
  } catch (error) {
    console.error('Get family dashboard error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve family dashboard')
    );
  }
});

// @desc    Add child to family
// @route   POST /api/family/children
// @access  Private
router.post('/children', protect, async (req, res) => {
  try {
    const { childId, relationship, permissions } = req.body;

    // Verify user is a parent
    const family = await Family.findOne({ parent: req.user.id });
    if (!family) {
      return res.status(403).json(
        helperUtils.errorResponse('Only family parents can add children')
      );
    }

    // Verify child user exists
    const childUser = await User.findById(childId);
    if (!childUser) {
      return res.status(404).json(
        helperUtils.errorResponse('Child user not found')
      );
    }

    // Check if child is already in a family
    const existingFamily = await Family.findOne({ 'children.child': childId });
    if (existingFamily) {
      return res.status(400).json(
        helperUtils.errorResponse('This user is already in a family')
      );
    }

    // Add child to family
    await family.addChild(childId, relationship, permissions);

    // Update child's family reference
    await User.findByIdAndUpdate(childId, {
      'family.parent': req.user.id,
      persona: 'child'
    });

    const updatedFamily = await Family.findById(family._id)
      .populate('children.child', 'firstName lastName age ageGroup');

    res.status(200).json(
      helperUtils.successResponse('Child added to family', {
        family: updatedFamily
      })
    );
  } catch (error) {
    console.error('Add child error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to add child to family')
    );
  }
});

// @desc    Remove child from family
// @route   DELETE /api/family/children/:childId
// @access  Private
router.delete('/children/:childId', protect, async (req, res) => {
  try {
    const { childId } = req.params;

    const family = await Family.findOne({ parent: req.user.id });
    if (!family) {
      return res.status(403).json(
        helperUtils.errorResponse('Only family parents can remove children')
      );
    }

    // Remove child from family
    await family.removeChild(childId);

    // Update child's family reference
    await User.findByIdAndUpdate(childId, {
      $unset: {
        'family.parent': '',
        'family.children': ''
      },
      persona: 'individual'
    });

    res.status(200).json(
      helperUtils.successResponse('Child removed from family')
    );
  } catch (error) {
    console.error('Remove child error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to remove child from family')
    );
  }
});

// @desc    Update family settings
// @route   PUT /api/family/settings
// @access  Private
router.put('/settings', protect, async (req, res) => {
  try {
    const { familySettings } = req.body;

    const family = await Family.findOne({
      $or: [
        { parent: req.user.id },
        { 'children.child': req.user.id }
      ]
    });

    if (!family) {
      return res.status(404).json(
        helperUtils.errorResponse('Family not found')
      );
    }

    // Only parent can update settings
    if (family.parent.toString() !== req.user.id.toString()) {
      return res.status(403).json(
        helperUtils.errorResponse('Only family parent can update settings')
      );
    }

    // Update settings
    family.familySettings = { ...family.familySettings, ...familySettings };
    await family.save();

    res.status(200).json(
      helperUtils.successResponse('Family settings updated', {
        familySettings: family.familySettings
      })
    );
  } catch (error) {
    console.error('Update family settings error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to update family settings')
    );
  }
});

// @desc    Get family protection report
// @route   GET /api/family/report
// @access  Private
router.get('/report', protect, async (req, res) => {
  try {
    const family = await Family.findOne({
      $or: [
        { parent: req.user.id },
        { 'children.child': req.user.id }
      ]
    })
    .populate('children.child', 'firstName lastName age securityScore level gameProgress');

    if (!family) {
      return res.status(404).json(
        helperUtils.errorResponse('Family not found')
      );
    }

    // Get threat statistics for all family members
    const Threat = require('../models/Threat');
    const familyMemberIds = [family.parent, ...family.children.map(c => c.child._id)];

    const threatStats = await Threat.aggregate([
      {
        $match: {
          user: { $in: familyMemberIds },
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
          isFalsePositive: false
        }
      },
      {
        $group: {
          _id: '$user',
          totalThreats: { $sum: 1 },
          blockedThreats: {
            $sum: { $cond: [{ $eq: ['$actionTaken', 'blocked'] }, 1, 0] }
          },
          criticalThreats: {
            $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
          },
          recentThreats: {
            $sum: {
              $cond: [
                { $gte: ['$createdAt', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)] },
                1, 0
              ]
            }
          }
        }
      }
    ]);

    // Get gaming activity
    const GameSession = require('../models/GameSession');
    const gamingStats = await GameSession.aggregate([
      {
        $match: {
          user: { $in: familyMemberIds },
          completed: true,
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: '$user',
          totalGames: { $sum: 1 },
          totalPlayTime: { $sum: '$timeSpent' },
          averageScore: { $avg: '$score' },
          lastActivity: { $max: '$createdAt' }
        }
      }
    ]);

    const report = {
      familyOverview: {
        name: family.familyName,
        totalMembers: family.children.length + 1,
        averageSecurityScore: family.familyStats.averageSecurityScore,
        totalThreatsBlocked: family.familyStats.totalThreatsBlocked,
        totalGamingTime: family.familyStats.totalGamingTime
      },
      memberStats: family.children.map(child => {
        const childThreatStats = threatStats.find(stat => stat._id.toString() === child.child._id.toString());
        const childGamingStats = gamingStats.find(stat => stat._id.toString() === child.child._id.toString());

        return {
          name: `${child.child.firstName} ${child.child.lastName}`,
          age: child.child.age,
          securityScore: child.child.securityScore,
          level: child.child.level,
          threats: {
            total: childThreatStats?.totalThreats || 0,
            blocked: childThreatStats?.blockedThreats || 0,
            critical: childThreatStats?.criticalThreats || 0,
            recent: childThreatStats?.recentThreats || 0
          },
          gaming: {
            totalGames: childGamingStats?.totalGames || 0,
            totalPlayTime: childGamingStats?.totalPlayTime || 0,
            averageScore: childGamingStats?.averageScore || 0,
            lastActivity: childGamingStats?.lastActivity || null
          },
          permissions: child.permissions
        };
      }),
      recommendations: generateFamilyRecommendations(family, threatStats, gamingStats)
    };

    res.status(200).json(
      helperUtils.successResponse('Family protection report generated', {
        report,
        generatedAt: new Date().toISOString()
      })
    );
  } catch (error) {
    console.error('Get family report error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to generate family report')
    );
  }
});

// Helper function to generate family recommendations
function generateFamilyRecommendations(family, threatStats, gamingStats) {
  const recommendations = [];

  // Check screen time
  const totalScreenTime = gamingStats.reduce((sum, stat) => sum + (stat.totalPlayTime || 0), 0) / 3600; // Convert to hours
  if (totalScreenTime > 20) { // More than 20 hours per week
    recommendations.push({
      type: 'screen_time',
      priority: 'medium',
      message: 'Consider setting screen time limits for children',
      suggestion: 'Use family settings to enforce reasonable gaming limits'
    });
  }

  // Check security scores
  const lowSecurityMembers = family.children.filter(child => 
    child.child.securityScore < 50
  );
  if (lowSecurityMembers.length > 0) {
    recommendations.push({
      type: 'security_training',
      priority: 'high',
      message: `${lowSecurityMembers.length} family members have low security scores`,
      suggestion: 'Encourage them to complete security training games'
    });
  }

  // Check recent threats
  const recentThreats = threatStats.reduce((sum, stat) => sum + (stat.recentThreats || 0), 0);
  if (recentThreats > 5) {
    recommendations.push({
      type: 'threat_awareness',
      priority: 'high',
      message: 'High number of recent threats detected',
      suggestion: 'Review threat history and enable stricter protection settings'
    });
  }

  return recommendations;
}

module.exports = router;