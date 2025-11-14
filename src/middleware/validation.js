const { body, validationResult, param, query } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

// User validation rules
const validateUserRegistration = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters'),
  body('age')
    .isInt({ min: 6, max: 120 })
    .withMessage('Age must be between 6 and 120'),
  body('persona')
    .isIn(['individual', 'parent', 'enterprise', 'child'])
    .withMessage('Persona must be one of: individual, parent, enterprise, child'),
  handleValidationErrors
];

const validateUserLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

// Game validation rules
const validateGameSession = [
  body('gameType')
    .isIn([
      'scam_spotter',
      'threat_hunter',
      'firewall_commander',
      'privacy_guardian',
      'crypto_defender',
      'social_sentinel'
    ])
    .withMessage('Invalid game type'),
  body('difficulty')
    .isIn(['easy', 'medium', 'hard', 'expert'])
    .withMessage('Difficulty must be one of: easy, medium, hard, expert'),
  body('score')
    .optional()
    .isInt({ min: 0, max: 1000 })
    .withMessage('Score must be between 0 and 1000'),
  handleValidationErrors
];

// Threat validation rules
const validateThreatReport = [
  body('type')
    .isIn([
      'phishing',
      'malware',
      'social_engineering',
      'privacy_violation',
      'financial_scam',
      'predator_behavior',
      'inappropriate_content',
      'data_breach'
    ])
    .withMessage('Invalid threat type'),
  body('severity')
    .isIn(['low', 'medium', 'high', 'critical'])
    .withMessage('Severity must be one of: low, medium, high, critical'),
  body('source')
    .isIn(['email', 'website', 'social_media', 'message', 'app', 'other'])
    .withMessage('Invalid threat source'),
  body('detectedContent')
    .trim()
    .isLength({ min: 1, max: 5000 })
    .withMessage('Detected content must be between 1 and 5000 characters'),
  body('indicators')
    .isArray({ min: 1 })
    .withMessage('At least one indicator is required'),
  body('indicators.*')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Each indicator must be between 1 and 200 characters'),
  handleValidationErrors
];

// Family validation rules
const validateFamilyCreation = [
  body('familyName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Family name must be between 1 and 100 characters'),
  body('children')
    .optional()
    .isArray()
    .withMessage('Children must be an array'),
  handleValidationErrors
];

// Query validation rules
const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  handleValidationErrors
];

// ID validation rules
const validateObjectId = [
  param('id')
    .isMongoId()
    .withMessage('Invalid ID format'),
  handleValidationErrors
];

module.exports = {
  validateUserRegistration,
  validateUserLogin,
  validateGameSession,
  validateThreatReport,
  validateFamilyCreation,
  validatePagination,
  validateObjectId,
  handleValidationErrors
};