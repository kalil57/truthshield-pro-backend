const jwt = require('jsonwebtoken');
const User = require('../models/User');
const constants = require('../config/constants');

const protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.headers['x-truthshield-token']) {
      token = req.headers['x-truthshield-token'];
    }

    if (!token) {
      return res.status(401).json({
        status: 'error',
        message: 'Not authorized to access this route'
      });
    }

    try {
      // Verify token
      const decoded = jwt.verify(token, constants.JWT_SECRET);
      
      // Get user from token
      const user = await User.findById(decoded.id).select('+password');
      
      if (!user) {
        return res.status(401).json({
          status: 'error',
          message: 'User no longer exists'
        });
      }

      // Check if user changed password after token was issued
      if (user.changedPasswordAfter(decoded.iat)) {
        return res.status(401).json({
          status: 'error',
          message: 'User recently changed password. Please log in again.'
        });
      }

      req.user = user;
      next();
    } catch (error) {
      return res.status(401).json({
        status: 'error',
        message: 'Not authorized to access this route'
      });
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Server error in authentication'
    });
  }
};

// Optional auth - doesn't throw error if no token
const optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.headers['x-truthshield-token']) {
      token = req.headers['x-truthshield-token'];
    }

    if (token) {
      const decoded = jwt.verify(token, constants.JWT_SECRET);
      const user = await User.findById(decoded.id);
      req.user = user;
    }

    next();
  } catch (error) {
    // Continue without user if token is invalid
    next();
  }
};

// Role-based authorization
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        message: `User role ${req.user.role} is not authorized to access this route`
      });
    }
    next();
  };
};

// Family authorization - check if user can access family data
const authorizeFamily = async (req, res, next) => {
  try {
    const familyId = req.params.familyId || req.body.familyId;
    
    if (!familyId) {
      return res.status(400).json({
        status: 'error',
        message: 'Family ID is required'
      });
    }

    const Family = require('../models/Family');
    const family = await Family.findOne({
      _id: familyId,
      $or: [
        { parent: req.user._id },
        { 'children.child': req.user._id }
      ]
    });

    if (!family) {
      return res.status(403).json({
        status: 'error',
        message: 'Not authorized to access this family data'
      });
    }

    req.family = family;
    next();
  } catch (error) {
    console.error('Family auth error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Server error in family authorization'
    });
  }
};

module.exports = {
  protect,
  optionalAuth,
  authorize,
  authorizeFamily
};