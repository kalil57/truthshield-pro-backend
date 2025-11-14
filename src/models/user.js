const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      },
      message: 'Please provide a valid email'
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  age: {
    type: Number,
    required: [true, 'Age is required'],
    min: [6, 'Age must be at least 6'],
    max: [120, 'Age must be reasonable']
  },
  ageGroup: {
    type: String,
    enum: ['child', 'teen', 'adult', 'senior'],
    required: true
  },
  persona: {
    type: String,
    enum: ['individual', 'parent', 'enterprise', 'child'],
    required: true
  },
  securityScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 1000
  },
  level: {
    type: Number,
    default: 1,
    min: 1,
    max: 100
  },
  experience: {
    type: Number,
    default: 0
  },
  achievements: [{
    achievementId: String,
    name: String,
    description: String,
    earnedAt: {
      type: Date,
      default: Date.now
    },
    icon: String
  }],
  gameProgress: {
    scamSpotter: {
      completed: { type: Boolean, default: false },
      score: { type: Number, default: 0 },
      level: { type: Number, default: 1 },
      completedAt: Date
    },
    threatHunter: {
      completed: { type: Boolean, default: false },
      score: { type: Number, default: 0 },
      level: { type: Number, default: 1 },
      completedAt: Date
    },
    firewallCommander: {
      completed: { type: Boolean, default: false },
      score: { type: Number, default: 0 },
      level: { type: Number, default: 1 },
      completedAt: Date
    },
    privacyGuardian: {
      completed: { type: Boolean, default: false },
      score: { type: Number, default: 0 },
      level: { type: Number, default: 1 },
      completedAt: Date
    },
    cryptoDefender: {
      completed: { type: Boolean, default: false },
      score: { type: Number, default: 0 },
      level: { type: Number, default: 1 },
      completedAt: Date
    },
    socialSentinel: {
      completed: { type: Boolean, default: false },
      score: { type: Number, default: 0 },
      level: { type: Number, default: 1 },
      completedAt: Date
    }
  },
  family: {
    isParent: { type: Boolean, default: false },
    children: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }],
    parent: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  },
  enterprise: {
    isAdmin: { type: Boolean, default: false },
    company: String,
    department: String,
    employeeId: String
  },
  settings: {
    notifications: { type: Boolean, default: true },
    realTimeProtection: { type: Boolean, default: true },
    dataCollection: { type: Boolean, default: false },
    theme: { type: String, default: 'light' }
  },
  lastActive: {
    type: Date,
    default: Date.now
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date
}, {
  timestamps: true
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ ageGroup: 1 });
userSchema.index({ 'gameProgress.score': -1 });
userSchema.index({ securityScore: -1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Pre-save middleware to set age group
userSchema.pre('save', function(next) {
  if (this.isModified('age')) {
    if (this.age >= 6 && this.age <= 12) this.ageGroup = 'child';
    else if (this.age >= 13 && this.age <= 17) this.ageGroup = 'teen';
    else if (this.age >= 18 && this.age <= 64) this.ageGroup = 'adult';
    else this.ageGroup = 'senior';
  }
  next();
});

// Instance method to check password
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Instance method to update security score
userSchema.methods.updateSecurityScore = function() {
  let totalScore = 0;
  let gameCount = 0;
  
  Object.values(this.gameProgress).forEach(game => {
    if (game.score > 0) {
      totalScore += game.score;
      gameCount++;
    }
  });
  
  this.securityScore = gameCount > 0 ? Math.round(totalScore / gameCount) : 0;
  return this.securityScore;
};

// Instance method to add achievement
userSchema.methods.addAchievement = function(achievementId, name, description, icon) {
  this.achievements.push({
    achievementId,
    name,
    description,
    icon
  });
  
  // Add experience points for achievement
  this.experience += 100;
  this.checkLevelUp();
};

// Instance method to check level up
userSchema.methods.checkLevelUp = function() {
  const requiredXP = this.level * 100;
  if (this.experience >= requiredXP) {
    this.level += 1;
    this.experience -= requiredXP;
    return true;
  }
  return false;
};

// Static method to get leaderboard
userSchema.statics.getLeaderboard = function(limit = 10) {
  return this.find({})
    .sort({ securityScore: -1, level: -1 })
    .limit(limit)
    .select('firstName lastName securityScore level achievements gameProgress');
};

module.exports = mongoose.model('User', userSchema);