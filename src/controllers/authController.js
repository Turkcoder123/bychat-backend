const { 
  validatePassword, 
  validateEmail, 
  validatePhoneNumber, 
  hashPassword, 
  verifyPassword, 
  generateToken, 
  generateRefreshToken,
  verifyGoogleToken,
  generateTwoFactorSecret,
  verifyTwoFactorCode
} = require('../middleware/authentication');
const User = require('../models/User');
const db = require('../config/database');
const redis = require('../config/redis');
const crypto = require('crypto');

// Initialize User model
const userModel = new User(db);

// Register with email and password
const registerWithEmail = async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;

    // Validate inputs
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ error: passwordValidation.message });
    }

    // Check if user already exists
    const existingUser = await userModel.findByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create user
    const user = await userModel.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      verificationToken
    });

    // In a real application, send verification email here
    console.log(`Verification token for ${email}: ${verificationToken}`);

    // Generate tokens
    const accessToken = generateToken({ 
      userId: user.id, 
      email: user.email,
      type: 'access'
    }, '1h');

    const refreshToken = generateRefreshToken({ 
      userId: user.id, 
      email: user.email,
      type: 'refresh'
    });

    // Store refresh token in Redis with expiration
    await redis.setex(`refresh_token:${user.id}`, 7 * 24 * 60 * 60, refreshToken); // 7 days

    res.status(201).json({
      message: 'User registered successfully. Please verify your email.',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        createdAt: user.created_at
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Register with phone number
const registerWithPhone = async (req, res) => {
  try {
    const { phone, password, firstName, lastName } = req.body;

    // Validate inputs
    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone number and password are required' });
    }

    if (!validatePhoneNumber(phone)) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ error: passwordValidation.message });
    }

    // Check if user already exists
    const existingUser = await userModel.findByPhone(phone);
    if (existingUser) {
      return res.status(409).json({ error: 'User with this phone number already exists' });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code

    // Create user
    const user = await userModel.create({
      phone,
      password: hashedPassword,
      firstName,
      lastName,
      phoneVerificationCode: verificationCode
    });

    // In a real application, send SMS with verification code here
    console.log(`Verification code for ${phone}: ${verificationCode}`);

    // Generate tokens
    const accessToken = generateToken({ 
      userId: user.id, 
      phone: user.phone,
      type: 'access'
    }, '1h');

    const refreshToken = generateRefreshToken({ 
      userId: user.id, 
      phone: user.phone,
      type: 'refresh'
    });

    // Store refresh token in Redis with expiration
    await redis.setex(`refresh_token:${user.id}`, 7 * 24 * 60 * 60, refreshToken); // 7 days

    res.status(201).json({
      message: 'User registered successfully. Please verify your phone number.',
      user: {
        id: user.id,
        phone: user.phone,
        firstName: user.first_name,
        lastName: user.last_name,
        createdAt: user.created_at
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Phone registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Google OAuth registration/login
const googleAuth = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ error: 'Google ID token is required' });
    }

    let googleUser;
    try {
      googleUser = await verifyGoogleToken(idToken);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid Google token' });
    }

    const { email, given_name, family_name, picture, sub: googleId } = googleUser;

    // Check if user already exists
    let user = await userModel.findByGoogleId(googleId);
    
    if (!user) {
      // New user - create account
      user = await userModel.create({
        email,
        firstName: given_name,
        lastName: family_name,
        googleId,
        avatar: picture,
        verified: true
      });
    } else {
      // Existing user - update last login
      await userModel.updateLastLogin(user.id);
    }

    // Generate tokens
    const accessToken = generateToken({ 
      userId: user.id, 
      email: user.email,
      type: 'access'
    }, '1h');

    const refreshToken = generateRefreshToken({ 
      userId: user.id, 
      email: user.email,
      type: 'refresh'
    });

    // Store refresh token in Redis with expiration
    await redis.setex(`refresh_token:${user.id}`, 7 * 24 * 60 * 60, refreshToken); // 7 days

    res.status(200).json({
      message: 'Successfully authenticated with Google',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        verified: user.verified,
        createdAt: user.created_at
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Login
const login = async (req, res) => {
  try {
    const { email, phone, password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    let userData;

    if (email) {
      // Login with email
      if (!validateEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      userData = await userModel.findByEmail(email);
    } else if (phone) {
      // Login with phone
      if (!validatePhoneNumber(phone)) {
        return res.status(400).json({ error: 'Invalid phone number format' });
      }
      userData = await userModel.findByPhone(phone);
    } else {
      return res.status(400).json({ error: 'Email or phone number is required' });
    }

    if (!userData) {
      // To prevent user enumeration, use the same delay as for password verification
      await hashPassword('dummy'); // This adds a delay to make timing attacks harder
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await verifyPassword(password, userData.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is verified (for email/phone registered accounts)
    if (!userData.verified) {
      return res.status(401).json({ error: 'Account not verified' });
    }

    // Check if user is banned
    const banStatus = await userModel.isBanned(userData.id);
    if (banStatus.isBanned) {
      return res.status(401).json({ 
        error: 'Account is banned', 
        reason: banStatus.reason,
        expiresAt: banStatus.expiresAt 
      });
    }

    // Generate tokens
    const accessToken = generateToken({ 
      userId: userData.id, 
      email: userData.email || userData.phone,
      type: 'access'
    }, '1h');

    const refreshToken = generateRefreshToken({ 
      userId: userData.id, 
      email: userData.email || userData.phone,
      type: 'refresh'
    });

    // Store refresh token in Redis with expiration
    await redis.setex(`refresh_token:${userData.id}`, 7 * 24 * 60 * 60, refreshToken); // 7 days

    // Update last login
    await userModel.updateLastLogin(userData.id);

    res.status(200).json({
      message: 'Login successful',
      user: {
        id: userData.id,
        email: userData.email,
        phone: userData.phone,
        firstName: userData.first_name,
        lastName: userData.last_name,
        verified: userData.verified
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Verify email
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Verification token is required' });
    }

    // Verify email using the token
    const user = await userModel.verifyEmail(token);

    if (!user) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    res.status(200).json({
      message: 'Email verified successfully'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Verify phone
const verifyPhone = async (req, res) => {
  try {
    const { phone, code } = req.body;

    if (!phone || !code) {
      return res.status(400).json({ error: 'Phone number and verification code are required' });
    }

    // Find user with this phone and verification code
    const user = await db.query('SELECT id FROM users WHERE phone = $1 AND phone_verification_code = $2', [phone, code]);

    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid phone number or verification code' });
    }

    const userId = user.rows[0].id;

    // Update user as verified and clear the verification code
    await db.query(`
      UPDATE users 
      SET verified = true, phone_verification_code = NULL, phone_verified_at = NOW()
      WHERE id = $1
    `, [userId]);

    res.status(200).json({
      message: 'Phone verified successfully'
    });
  } catch (error) {
    console.error('Phone verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Refresh token
const refreshToken = async (req, res) => {
  try {
    const { refreshToken: refreshTokenBody } = req.body;

    if (!refreshTokenBody) {
      return res.status(401).json({ error: 'Refresh token is required' });
    }

    let decoded;
    try {
      decoded = require('../middleware/authentication').verifyRefreshToken(refreshTokenBody);
    } catch (error) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    // Check if refresh token exists in Redis
    const storedToken = await redis.get(`refresh_token:${decoded.userId}`);
    if (storedToken !== refreshTokenBody) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    // Generate new tokens
    const newAccessToken = generateToken({ 
      userId: decoded.userId, 
      email: decoded.email,
      type: 'access'
    }, '1h');

    const newRefreshToken = generateRefreshToken({ 
      userId: decoded.userId, 
      email: decoded.email,
      type: 'refresh'
    });

    // Update refresh token in Redis
    await redis.setex(`refresh_token:${decoded.userId}`, 7 * 24 * 60 * 60, newRefreshToken);

    res.status(200).json({
      tokens: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Logout
const logout = async (req, res) => {
  try {
    const userId = req.user?.userId;

    if (userId) {
      // Remove refresh token from Redis
      await redis.del(`refresh_token:${userId}`);
    }

    res.status(200).json({
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Enable 2FA
const enableTwoFactor = async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Generate a new 2FA secret for the user
    const secret = generateTwoFactorSecret();
    
    // Store the secret temporarily in the database
    await db.query('UPDATE users SET temp_two_factor_secret = $1 WHERE id = $2', [secret.base32, userId]);
    
    // Generate QR code for authenticator app
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);
    
    res.status(200).json({
      secret: secret.base32,
      qrCode: qrCode,
      message: 'Scan the QR code with your authenticator app and verify the code'
    });
  } catch (error) {
    console.error('Enable 2FA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Verify 2FA setup
const verifyTwoFactorSetup = async (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.userId;
    
    if (!code) {
      return res.status(400).json({ error: 'Verification code is required' });
    }
    
    // Get the temporary secret from the database
    const userResult = await db.query('SELECT temp_two_factor_secret FROM users WHERE id = $1', [userId]);
    const tempSecret = userResult.rows[0]?.temp_two_factor_secret;
    
    if (!tempSecret) {
      return res.status(400).json({ error: 'No 2FA setup in progress' });
    }
    
    // Verify the code
    const verified = verifyTwoFactorCode(tempSecret, code);
    
    if (!verified) {
      return res.status(400).json({ error: 'Invalid 2FA code' });
    }
    
    // Move the temporary secret to the permanent secret and enable 2FA
    await db.query('UPDATE users SET two_factor_secret = $1, two_factor_enabled = true, temp_two_factor_secret = NULL WHERE id = $2', [tempSecret, userId]);
    
    res.status(200).json({
      message: '2FA enabled successfully'
    });
  } catch (error) {
    console.error('Verify 2FA setup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Disable 2FA
const disableTwoFactor = async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Disable 2FA
    await db.query('UPDATE users SET two_factor_secret = NULL, two_factor_enabled = false WHERE id = $1', [userId]);
    
    res.status(200).json({
      message: '2FA disabled successfully'
    });
  } catch (error) {
    console.error('Disable 2FA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Login with 2FA
const loginWithTwoFactor = async (req, res) => {
  try {
    const { email, phone, password, twoFactorCode } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    let user;
    let identifier;

    if (email) {
      // Login with email
      if (!validateEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      identifier = email;
      user = await db.query(`
        SELECT id, email, password, first_name, last_name, verified, two_factor_enabled, two_factor_secret 
        FROM users 
        WHERE email = $1
      `, [email]);
    } else if (phone) {
      // Login with phone
      if (!validatePhoneNumber(phone)) {
        return res.status(400).json({ error: 'Invalid phone number format' });
      }
      identifier = phone;
      user = await db.query(`
        SELECT id, phone, password, first_name, last_name, verified, two_factor_enabled, two_factor_secret 
        FROM users 
        WHERE phone = $1
      `, [phone]);
    } else {
      return res.status(400).json({ error: 'Email or phone number is required' });
    }

    if (user.rows.length === 0) {
      // To prevent user enumeration, use the same delay as for password verification
      await hashPassword('dummy'); // This adds a delay to make timing attacks harder
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userData = user.rows[0];
    const isValidPassword = await verifyPassword(password, userData.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is verified (for email/phone registered accounts)
    if (!userData.verified) {
      return res.status(401).json({ error: 'Account not verified' });
    }

    // Check if 2FA is enabled
    if (userData.two_factor_enabled) {
      if (!twoFactorCode) {
        return res.status(401).json({ error: '2FA code is required' });
      }

      // Verify the 2FA code
      const verified = verifyTwoFactorCode(userData.two_factor_secret, twoFactorCode);
      
      if (!verified) {
        return res.status(401).json({ error: 'Invalid 2FA code' });
      }
    }

    // Generate tokens
    const accessToken = generateToken({ 
      userId: userData.id, 
      email: userData.email || userData.phone,
      type: 'access'
    }, '1h');

    const refreshToken = generateRefreshToken({ 
      userId: userData.id, 
      email: userData.email || userData.phone,
      type: 'refresh'
    });

    // Store refresh token in Redis with expiration
    await redis.setex(`refresh_token:${userData.id}`, 7 * 24 * 60 * 60, refreshToken); // 7 days

    // Update last login
    await userModel.updateLastLogin(userData.id);

    res.status(200).json({
      message: 'Login successful',
      user: {
        id: userData.id,
        email: userData.email,
        phone: userData.phone,
        firstName: userData.first_name,
        lastName: userData.last_name,
        verified: userData.verified
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('2FA login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = {
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
};