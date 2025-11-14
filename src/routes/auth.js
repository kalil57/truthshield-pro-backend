const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { protect } = require('../middleware/auth');
const { validateUserRegistration, validateUserLogin } = require('../middleware/validation');
const helperUtils = require('../utils/helpers');
const constants = require('../config/constants');

const router = express.Router();

// Generate JWT Token
const signToken = (id) => {
  return jwt.sign({ id }, constants.JWT_SECRET, {
    expiresIn: constants.JWT_EXPIRES_IN
  });
};

// Create and send token
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json(
    helperUtils.successResponse('Authentication successful', {
      token,
      user
    })
  );
};

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
router.post('/register', validateUserRegistration, async (req, res) => {
  try {
    const { email, password, firstName, lastName, age, persona } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json(
        helperUtils.errorResponse('User with this email already exists', 'USER_EXISTS')
      );
    }

    // Create new user
    const newUser = await User.create({
      email,
      password,
      firstName,
      lastName,
      age,
      persona,
      ageGroup: helperUtils.getAgeGroup(age)
    });

    createSendToken(newUser, 201, res);
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Registration failed. Please try again.')
    );
  }
});

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
router.post('/login', validateUserLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email and password exist
    if (!email || !password) {
      return res.status(400).json(
        helperUtils.errorResponse('Please provide email and password', 'MISSING_CREDENTIALS')
      );
    }

    // Check if user exists and password is correct
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json(
        helperUtils.errorResponse('Incorrect email or password', 'INVALID_CREDENTIALS')
      );
    }

    // Update last active
    user.lastActive = new Date();
    await user.save();

    createSendToken(user, 200, res);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Login failed. Please try again.')
    );
  }
});

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
router.get('/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    res.status(200).json(
      helperUtils.successResponse('User retrieved successfully', { user })
    );
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to retrieve user information')
    );
  }
});

// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
router.put('/profile', protect, async (req, res) => {
  try {
    const { firstName, lastName, age, settings } = req.body;
    
    // Filter allowed fields
    const allowedUpdates = {};
    if (firstName) allowedUpdates.firstName = firstName;
    if (lastName) allowedUpdates.lastName = lastName;
    if (age) {
      allowedUpdates.age = age;
      allowedUpdates.ageGroup = helperUtils.getAgeGroup(age);
    }
    if (settings) allowedUpdates.settings = { ...req.user.settings, ...settings };

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      allowedUpdates,
      { new: true, runValidators: true }
    );

    res.status(200).json(
      helperUtils.successResponse('Profile updated successfully', { user: updatedUser })
    );
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to update profile')
    );
  }
});

// @desc    Change password
// @route   PUT /api/auth/change-password
// @access  Private
router.put('/change-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json(
        helperUtils.errorResponse('Current password and new password are required')
      );
    }

    // Get user with password
    const user = await User.findById(req.user.id).select('+password');

    // Check if current password is correct
    if (!(await user.correctPassword(currentPassword, user.password))) {
      return res.status(401).json(
        helperUtils.errorResponse('Current password is incorrect')
      );
    }

    // Update password
    user.password = newPassword;
    await user.save();

    createSendToken(user, 200, res);
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to change password')
    );
  }
});

// @desc    Logout user (client-side token removal)
// @route   POST /api/auth/logout
// @access  Private
router.post('/logout', protect, async (req, res) => {
  try {
    // Update last active before logout
    await User.findByIdAndUpdate(req.user.id, { lastActive: new Date() });

    res.status(200).json(
      helperUtils.successResponse('Logged out successfully')
    );
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Logout failed')
    );
  }
});

// @desc    Delete user account
// @route   DELETE /api/auth/account
// @access  Private
router.delete('/account', protect, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user.id);

    res.status(200).json(
      helperUtils.successResponse('Account deleted successfully')
    );
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json(
      helperUtils.errorResponse('Failed to delete account')
    );
  }
});

module.exports = router;