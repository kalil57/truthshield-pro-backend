const express = require('express');
const GameSession = require('../models/GameSession');
const User = require('../models/User');
const { protect } = require('../middleware/auth');
const { validateGameSession, validatePagination } = require('../middleware/validation');
const helperUtils = require('../utils/helpers');

const router = express.Router();

// Game questions database (in production, this would be in MongoDB)
const GAME_QUESTIONS = {
  scam_spotter: {
    easy: [
      {
        id: 'ss_easy_1',
        question: 'You receive an email saying "Your account will be suspended unless you click here immediately." What should you do?',
        options: [
          'Click the link to save your account',
          'Ignore and delete the email',
          'Forward to all your friends',
          'Reply with your password'
        ],
        correctAnswer: 'Ignore and delete the email',
        explanation: 'This is a common phishing tactic. Legitimate companies never ask for immediate action via email.',
        category: 'urgency_tactics'
      }
    ],
    medium: [
      {
        id: 'ss_medium_1',
        question: 'An email from "Netflix Support" asks you to update payment information with a link to netflix-security.com. What do you do?',
        options: [
          'Click the link and update information',
          'Check the official Netflix website',
          'Forward to Netflix',
          'Ignore it completely'
        ],
        correctAnswer: 'Check the official Netflix website',
        explanation: 'Always verify through official websites. Netflix uses netflix.com, not netflix-security.com.',
        category: 'domain_spoofing'
      }
    ]
  },
  threat_hunter: {
    easy: [
      {
        id: 'th_easy_1',
        question: 'A popup says "Virus detected! Download our antivirus now!" What is this?',
        options: [
          'A real virus warning',
          'A helpful security alert',
          'A scam to install malware',
          'A system notification'
        ],
        correctAnswer: 'A scam to install malware',
        explanation: 'Legitimate antivirus software doesn\'t use alarming popups. This is scareware.',
        category: 'malware_tactics'
      }
    ]
  }
  // Add more questions for all games...
};

// @desc    Start a new game session
// @route   POST /api/games/start
// @access  Private
router.post('/start', protect, validateGameSession, async (req, res) => {
  try {
    const { gameType, difficulty } = req.body;

    // Create new game session
    const gameSession = await GameSession.create({
      gameType,
      difficulty,
      user: req.user.id,
      ageGroup: req.user.ageGroup,
      sessionData: {
        startTime: new Date(),
        questions: []
      }
    });

    // Get questions for the game
    const questions = GAME_QUESTIONS[gameType]?.[difficulty] || [];
    const selectedQuestions = helperUtils.shuffleArray(questions).slice(0, 5); // Select 5 random questions

    res.status(201).json(
      helperUtils.successResponse('Game session started', {
        sessionId: gameSession._id,
        questions: selectedQuestions,
        difficulty,
        gameType
      })
    );
  } catch (error) {
    console.error('Start game error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to start game session')
    );
  }
});

// @desc    Submit game answer
// @route   POST /api/games/:sessionId/answer
// @access  Private
router.post('/:sessionId/answer', protect, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { questionId, userAnswer, timeTaken } = req.body;

    // Find game session
    const gameSession = await GameSession.findOne({
      _id: sessionId,
      user: req.user.id
    });

    if (!gameSession) {
      return res.status(404).json(
        helperUtils.errorResponse('Game session not found')
      );
    }

    if (gameSession.completed) {
      return res.status(400).json(
        helperUtils.errorResponse('Game session already completed')
      );
    }

    // Find the question
    const question = Object.values(GAME_QUESTIONS)
      .flatMap(difficulty => Object.values(difficulty).flat())
      .find(q => q.id === questionId);

    if (!question) {
      return res.status(404).json(
        helperUtils.errorResponse('Question not found')
      );
    }

    // Check if answer is correct
    const isCorrect = userAnswer === question.correctAnswer;

    // Add question result to session
    gameSession.addQuestionResult({
      questionId: question.id,
      question: question.question,
      userAnswer,
      correctAnswer: question.correctAnswer,
      isCorrect,
      timeTaken,
      difficulty: gameSession.difficulty,
      category: question.category
    });

    await gameSession.save();

    res.status(200).json(
      helperUtils.successResponse('Answer submitted', {
        isCorrect,
        correctAnswer: question.correctAnswer,
        explanation: question.explanation,
        currentScore: gameSession.score,
        accuracy: gameSession.accuracy
      })
    );
  } catch (error) {
    console.error('Submit answer error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to submit answer')
    );
  }
});

// @desc    Complete game session
// @route   POST /api/games/:sessionId/complete
// @access  Private
router.post('/:sessionId/complete', protect, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { feedback } = req.body;

    // Find game session
    const gameSession = await GameSession.findOne({
      _id: sessionId,
      user: req.user.id
    });

    if (!gameSession) {
      return res.status(404).json(
        helperUtils.errorResponse('Game session not found')
      );
    }

    if (gameSession.completed) {
      return res.status(400).json(
        helperUtils.errorResponse('Game session already completed')
      );
    }

    // Complete session
    gameSession.completeSession();
    if (feedback) {
      gameSession.feedback = feedback;
    }

    await gameSession.save();

    // Update user progress
    const user = await User.findById(req.user.id);
    const gameProgress = user.gameProgress[gameSession.gameType];
    
    if (gameSession.score > gameProgress.score) {
      gameProgress.score = gameSession.score;
      gameProgress.level = Math.max(gameProgress.level, gameSession.level);
    }

    if (gameSession.correctAnswers === gameSession.totalQuestions) {
      gameProgress.completed = true;
      gameProgress.completedAt = new Date();
    }

    // Add experience points
    const xpGained = helperUtils.calculateXP(
      gameSession.score,
      gameSession.difficulty,
      gameSession.timeSpent
    );
    user.experience += xpGained;

    // Check for level up
    const leveledUp = user.checkLevelUp();

    // Update security score
    user.updateSecurityScore();

    await user.save();

    // Check for achievements
    const achievements = await checkAchievements(user, gameSession);

    res.status(200).json(
      helperUtils.successResponse('Game completed successfully', {
        finalScore: gameSession.score,
        accuracy: gameSession.accuracy,
        timeSpent: gameSession.timeSpent,
        xpGained,
        newLevel: user.level,
        leveledUp,
        achievements,
        securityScore: user.securityScore
      })
    );
  } catch (error) {
    console.error('Complete game error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to complete game session')
    );
  }
});

// @desc    Get user game progress
// @route   GET /api/games/progress
// @access  Private
router.get('/progress', protect, async (req, res) => {
  try {
    const progress = await GameSession.getUserProgress(req.user.id);

    res.status(200).json(
      helperUtils.successResponse('Progress retrieved successfully', {
        progress,
        overallStats: {
          totalGames: progress.reduce((sum, game) => sum + game.totalSessions, 0),
          completedGames: progress.reduce((sum, game) => sum + game.completedSessions, 0),
          averageScore: helperUtils.calculateSecurityScore(
            progress.reduce((acc, game) => {
              acc[game.gameType] = { score: game.averageScore };
              return acc;
            }, {})
          )
        }
      })
    );
  } catch (error) {
    console.error('Get progress error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve progress')
    );
  }
});

// @desc    Get game leaderboard
// @route   GET /api/games/leaderboard/:gameType
// @access  Private
router.get('/leaderboard/:gameType', protect, async (req, res) => {
  try {
    const { gameType } = req.params;
    const { limit = 10 } = req.query;

    const leaderboard = await GameSession.getGameLeaderboard(gameType, parseInt(limit));

    res.status(200).json(
      helperUtils.successResponse('Leaderboard retrieved successfully', {
        gameType,
        leaderboard
      })
    );
  } catch (error) {
    console.error('Get leaderboard error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve leaderboard')
    );
  }
});

// @desc    Get game statistics
// @route   GET /api/games/stats
// @access  Private
router.get('/stats', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const totalSessions = await GameSession.countDocuments({ user: req.user.id });
    const completedSessions = await GameSession.countDocuments({ 
      user: req.user.id, 
      completed: true 
    });
    const totalTimeSpent = await GameSession.aggregate([
      { $match: { user: user._id, completed: true } },
      { $group: { _id: null, totalTime: { $sum: '$timeSpent' } } }
    ]);

    const stats = {
      totalGamesPlayed: totalSessions,
      completedGames: completedSessions,
      totalPlayTime: totalTimeSpent[0]?.totalTime || 0,
      securityScore: user.securityScore,
      level: user.level,
      experience: user.experience,
      achievementsCount: user.achievements.length
    };

    res.status(200).json(
      helperUtils.successResponse('Game statistics retrieved', { stats })
    );
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve game statistics')
    );
  }
});

// Achievement checking function
async function checkAchievements(user, gameSession) {
  const achievements = [];
  const userAchievementIds = user.achievements.map(a => a.achievementId);

  // First Game Achievement
  if (!userAchievementIds.includes('first_game')) {
    achievements.push({
      achievementId: 'first_game',
      name: 'First Steps',
      description: 'Complete your first security game',
      icon: '🎮'
    });
  }

  // Perfect Score Achievement
  if (gameSession.accuracy === 100 && !userAchievementIds.includes('perfect_score')) {
    achievements.push({
      achievementId: 'perfect_score',
      name: 'Flawless Victory',
      description: 'Get a perfect score in any game',
      icon: '⭐'
    });
  }

  // Speed Runner Achievement
  if (gameSession.timeSpent < 60 && !userAchievementIds.includes('speed_runner')) {
    achievements.push({
      achievementId: 'speed_runner',
      name: 'Speed Runner',
      description: 'Complete a game in under 1 minute',
      icon: ''
    });
  }

  // Add achievements to user
  achievements.forEach(achievement => {
    user.addAchievement(
      achievement.achievementId,
      achievement.name,
      achievement.description,
      achievement.icon
    );
  });

  if (achievements.length > 0) {
    await user.save();
  }

  return achievements;
}

module.exports = router;