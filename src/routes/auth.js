const express = require('express');
const router = express.Router();
const {
  authRateLimit,
  authSlowDown,
  authenticateJWT
} = require('../middleware/authentication');
const {
  registerWithEmail,
  registerWithPhone,
  googleAuth,
  login,
  verifyEmail,
  verifyPhone,
  refreshToken,
  logout,
  enableTwoFactor,
  verifyTwoFactorSetup,
  disableTwoFactor,
  loginWithTwoFactor
} = require('../controllers/authController');

// Apply rate limiting to all auth routes
router.use(authSlowDown);
router.use(authRateLimit);

// Registration routes
router.post('/register/email', registerWithEmail);
router.post('/register/phone', registerWithPhone);

// Authentication routes
router.post('/google', googleAuth);
router.post('/login', login);
router.post('/login/2fa', loginWithTwoFactor); // Separate endpoint for 2FA login
router.post('/refresh', refreshToken);
router.post('/logout', authenticateJWT, logout);

// Verification routes
router.post('/verify/email', verifyEmail);
router.post('/verify/phone', verifyPhone);

// Two-factor authentication routes
router.post('/2fa/enable', authenticateJWT, enableTwoFactor);
router.post('/2fa/verify', authenticateJWT, verifyTwoFactorSetup);
router.post('/2fa/disable', authenticateJWT, disableTwoFactor);

module.exports = router;