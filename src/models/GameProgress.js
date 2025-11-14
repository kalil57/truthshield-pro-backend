const mongoose = require('mongoose');

const gameSessionSchema = new mongoose.Schema({
  gameType: {
    type: String,
    required: true,
    enum: [
      'scam_spotter',
      'threat_hunter',
      'firewall_commander',
      'privacy_guardian',
      'crypto_defender',
      'social_sentinel'
    ]
  },
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
  difficulty: {
    type: String,
    required: true,
    enum: ['easy', 'medium', 'hard', 'expert']
  },
  score: {
    type: Number,
    default: 0,
    min: 0,
    max: 1000
  },
  timeSpent: {
    type: Number, // in seconds
    default: 0
  },
  correctAnswers: {
    type: Number,
    default: 0
  },
  totalQuestions: {
    type: Number,
    default: 0
  },
  accuracy: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  level: {
    type: Number,
    default: 1,
    min: 1,
    max: 10
  },
  completed: {
    type: Boolean,
    default: false
  },
  achievements: [{
    achievementId: String,
    name: String,
    description: String,
    earnedAt: {
      type: Date,
      default: Date.now
    }
  }],
  challenges: [{
    challengeId: String,
    completed: Boolean,
    score: Number,
    timeTaken: Number
  }],
  sessionData: {
    startTime: Date,
    endTime: Date,
    questions: [{
      questionId: String,
      question: String,
      userAnswer: String,
      correctAnswer: String,
      isCorrect: Boolean,
      timeTaken: Number,
      difficulty: String,
      category: String
    }],
    threatsEncountered: [{
      threatId: String,
      type: String,
      severity: String,
      handledCorrectly: Boolean
    }]
  },
  feedback: {
    rating: {
      type: Number,
      min: 1,
      max: 5
    },
    comments: String,
    difficultyFeedback: String
  }
}, {
  timestamps: true
});

// Indexes for performance
gameSessionSchema.index({ user: 1, gameType: 1 });
gameSessionSchema.index({ user: 1, createdAt: -1 });
gameSessionSchema.index({ gameType: 1, score: -1 });
gameSessionSchema.index({ ageGroup: 1, difficulty: 1 });

// Pre-save middleware to calculate accuracy
gameSessionSchema.pre('save', function(next) {
  if (this.totalQuestions > 0) {
    this.accuracy = Math.round((this.correctAnswers / this.totalQuestions) * 100);
  }
  next();
});

// Instance method to add question result
gameSessionSchema.methods.addQuestionResult = function(questionData) {
  this.sessionData.questions.push(questionData);
  this.totalQuestions++;
  
  if (questionData.isCorrect) {
    this.correctAnswers++;
  }
  
  this.calculateScore();
};

// Instance method to calculate score
gameSessionSchema.methods.calculateScore = function() {
  const baseScore = this.correctAnswers * 10;
  const accuracyBonus = this.accuracy * 2;
  const difficultyMultiplier = {
    'easy': 1,
    'medium': 1.5,
    'hard': 2,
    'expert': 3
  };
  
  const timePenalty = Math.max(0, (this.timeSpent - 300) / 10); // Penalty after 5 minutes
  
  this.score = Math.max(0, 
    (baseScore + accuracyBonus) * difficultyMultiplier[this.difficulty] - timePenalty
  );
  
  return this.score;
};

// Instance method to complete session
gameSessionSchema.methods.completeSession = function() {
  this.completed = true;
  this.sessionData.endTime = new Date();
  this.timeSpent = Math.round(
    (this.sessionData.endTime - this.sessionData.startTime) / 1000
  );
  this.calculateScore();
};

// Static method to get user progress
gameSessionSchema.statics.getUserProgress = async function(userId, gameType = null) {
  const matchStage = { user: mongoose.Types.ObjectId(userId) };
  if (gameType) matchStage.gameType = gameType;

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: '$gameType',
        totalSessions: { $sum: 1 },
        completedSessions: { $sum: { $cond: ['$completed', 1, 0] } },
        averageScore: { $avg: '$score' },
        bestScore: { $max: '$score' },
        totalTimeSpent: { $sum: '$timeSpent' },
        averageAccuracy: { $avg: '$accuracy' },
        levelsCompleted: { $sum: '$level' }
      }
    },
    {
      $project: {
        gameType: '$_id',
        totalSessions: 1,
        completedSessions: 1,
        averageScore: { $round: ['$averageScore', 2] },
        bestScore: 1,
        totalTimeSpent: 1,
        averageAccuracy: { $round: ['$averageAccuracy', 2] },
        levelsCompleted: 1,
        _id: 0
      }
    }
  ]);
};

// Static method to get leaderboard for a game
gameSessionSchema.statics.getGameLeaderboard = async function(gameType, limit = 10) {
  return this.aggregate([
    { 
      $match: { 
        gameType: gameType,
        completed: true 
      } 
    },
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
      $group: {
        _id: '$user',
        bestScore: { $max: '$score' },
        user: { $first: '$userInfo' },
        totalSessions: { $sum: 1 },
        lastPlayed: { $max: '$createdAt' }
      }
    },
    { $sort: { bestScore: -1 } },
    { $limit: limit },
    {
      $project: {
        'user.password': 0,
        'user.email': 0,
        'user.settings': 0
      }
    }
  ]);
};

module.exports = mongoose.model('GameSession', gameSessionSchema);