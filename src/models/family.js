const mongoose = require('mongoose');

const familySchema = new mongoose.Schema({
  familyName: {
    type: String,
    required: [true, 'Family name is required'],
    trim: true,
    maxlength: [100, 'Family name cannot exceed 100 characters']
  },
  parent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  children: [{
    child: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    relationship: {
      type: String,
      enum: ['son', 'daughter', 'ward', 'other']
    },
    permissions: {
      gaming: { type: Boolean, default: true },
      socialMedia: { type: Boolean, default: true },
      webBrowsing: { type: Boolean, default: true },
      maxScreenTime: { type: Number, default: 120 } // in minutes
    }
  }],
  familySettings: {
    overallProtection: {
      type: String,
      enum: ['minimal', 'moderate', 'strict', 'maximum'],
      default: 'moderate'
    },
    contentFiltering: {
      socialMedia: { type: Boolean, default: true },
      gamingSites: { type: Boolean, default: false },
      shoppingSites: { type: Boolean, default: true },
      educationalSites: { type: Boolean, default: false }
    },
    timeRestrictions: {
      bedTime: {
        start: { type: String, default: '22:00' }, // 10:00 PM
        end: { type: String, default: '07:00' }   // 7:00 AM
      },
      weekdays: {
        maxHours: { type: Number, default: 2 }
      },
      weekends: {
        maxHours: { type: Number, default: 4 }
      }
    },
    emergencyContacts: [{
      name: String,
      phone: String,
      relationship: String,
      isPrimary: { type: Boolean, default: false }
    }],
    alertPreferences: {
      threatDetected: { type: Boolean, default: true },
      timeLimitExceeded: { type: Boolean, default: true },
      inappropriateContent: { type: Boolean, default: true },
      newAchievement: { type: Boolean, default: true }
    }
  },
  familyStats: {
    totalThreatsBlocked: { type: Number, default: 0 },
    totalGamingTime: { type: Number, default: 0 }, // in minutes
    averageSecurityScore: { type: Number, default: 0 },
    lastActivity: Date
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Indexes
familySchema.index({ parent: 1 });
familySchema.index({ 'children.child': 1 });

// Instance method to add child
familySchema.methods.addChild = function(childId, relationship = 'other', permissions = {}) {
  this.children.push({
    child: childId,
    relationship,
    permissions: { ...this.children[0].permissions.toObject(), ...permissions }
  });
  
  return this.save();
};

// Instance method to remove child
familySchema.methods.removeChild = function(childId) {
  this.children = this.children.filter(child => 
    child.child.toString() !== childId.toString()
  );
  
  return this.save();
};

// Instance method to update family stats
familySchema.methods.updateFamilyStats = async function() {
  const childIds = this.children.map(child => child.child);
  
  const User = mongoose.model('User');
  const Threat = mongoose.model('Threat');
  const GameSession = mongoose.model('GameSession');
  
  // Get average security score
  const users = await User.find({ _id: { $in: [this.parent, ...childIds] } });
  const totalScore = users.reduce((sum, user) => sum + user.securityScore, 0);
  this.familyStats.averageSecurityScore = Math.round(totalScore / users.length);
  
  // Get total threats blocked
  const threatCount = await Threat.countDocuments({
    user: { $in: [this.parent, ...childIds] },
    actionTaken: 'blocked',
    isFalsePositive: false
  });
  this.familyStats.totalThreatsBlocked = threatCount;
  
  // Get total gaming time
  const gamingSessions = await GameSession.aggregate([
    {
      $match: {
        user: { $in: [this.parent, ...childIds].map(id => mongoose.Types.ObjectId(id)) },
        completed: true
      }
    },
    {
      $group: {
        _id: null,
        totalTime: { $sum: '$timeSpent' }
      }
    }
  ]);
  
  this.familyStats.totalGamingTime = gamingSessions.length > 0 
    ? Math.round(gamingSessions[0].totalTime / 60) 
    : 0;
  
  this.familyStats.lastActivity = new Date();
  
  return this.save();
};

// Static method to get family dashboard data
familySchema.statics.getFamilyDashboard = async function(familyId) {
  return this.aggregate([
    { $match: { _id: mongoose.Types.ObjectId(familyId) } },
    {
      $lookup: {
        from: 'users',
        localField: 'parent',
        foreignField: '_id',
        as: 'parentInfo'
      }
    },
    {
      $lookup: {
        from: 'users',
        localField: 'children.child',
        foreignField: '_id',
        as: 'childrenInfo'
      }
    },
    { $unwind: '$parentInfo' },
    {
      $project: {
        familyName: 1,
        parent: {
          _id: '$parentInfo._id',
          firstName: '$parentInfo.firstName',
          lastName: '$parentInfo.lastName',
          securityScore: '$parentInfo.securityScore',
          level: '$parentInfo.level'
        },
        children: {
          $map: {
            input: '$childrenInfo',
            as: 'child',
            in: {
              _id: '$$child._id',
              firstName: '$$child.firstName',
              lastName: '$$child.lastName',
              age: '$$child.age',
              ageGroup: '$$child.ageGroup',
              securityScore: '$$child.securityScore',
              level: '$$child.level',
              gameProgress: '$$child.gameProgress',
              lastActive: '$$child.lastActive'
            }
          }
        },
        familySettings: 1,
        familyStats: 1,
        createdAt: 1
      }
    }
  ]);
};

module.exports = mongoose.model('Family', familySchema);