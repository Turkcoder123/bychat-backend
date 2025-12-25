const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const helmet = require('helmet');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

// Security headers middleware
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", "https://*.googleapis.com"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  crossOriginEmbedderPolicy: false, // May need to be adjusted based on your needs
});

// CORS configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
};

// Sanitize data to prevent MongoDB operator injection
const sanitize = mongoSanitize();

// Prevent XSS attacks
const xssClean = xss();

// Rate limiting for general API endpoints
const apiRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Slow down requests after multiple attempts
const apiSlowDown = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // Begin slowing down after 50 requests
  delayMs: (hits) => hits * 100, // Add 100ms per request after 50th request
});

// Rate limiting for sensitive endpoints
const sensitiveEndpointRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs for sensitive endpoints
  message: {
    error: 'Too many requests to sensitive endpoint from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Input validation middleware
const validateInput = (validations) => {
  return [
    validations,
    (req, res, next) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ 
          error: 'Validation failed', 
          details: errors.array() 
        });
      }
      next();
    }
  ];
};

// Prevent brute force attacks by tracking failed attempts
const failedAttempts = new Map(); // In production, use Redis for distributed tracking

const bruteForceProtection = (req, res, next) => {
  const ip = req.ip;
  const currentTime = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes

  if (!failedAttempts.has(ip)) {
    failedAttempts.set(ip, { count: 0, firstAttempt: currentTime });
  }

  const attemptData = failedAttempts.get(ip);

  // Reset counter if window has passed
  if (currentTime - attemptData.firstAttempt > windowMs) {
    attemptData.count = 0;
    attemptData.firstAttempt = currentTime;
  }

  // Check if limit exceeded
  if (attemptData.count >= 5) { // Max 5 failed attempts
    const timeLeft = Math.ceil((windowMs - (currentTime - attemptData.firstAttempt)) / 1000);
    return res.status(429).json({ 
      error: `Too many failed attempts. Please try again in ${timeLeft} seconds.` 
    });
  }

  // If request is successful, reset counter
  const originalSend = res.send;
  res.send = function (body) {
    if (res.statusCode < 400) { // Successful request
      attemptData.count = 0;
    } else if (res.statusCode === 401 || res.statusCode === 403) { // Failed auth attempt
      attemptData.count++;
    }
    originalSend.call(this, body);
  };

  next();
};

// Check request size to prevent large payload attacks
const checkPayloadSize = (req, res, next) => {
  const contentLength = req.get('Content-Length');
  
  if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) { // 10MB limit
    return res.status(413).json({ 
      error: 'Payload too large. Maximum allowed size is 10MB.' 
    });
  }
  
  // For JSON requests, check body size
  let received = 0;
  req.on('data', (chunk) => {
    received += chunk.length;
    if (received > 10 * 1024 * 1024) { // 10MB limit
      req.destroy();
      res.status(413).json({ 
        error: 'Payload too large. Maximum allowed size is 10MB.' 
      });
    }
  });
  
  next();
};

// Prevent session fixation by rotating session IDs
const rotateSessionId = (req, res, next) => {
  // This is a simplified version - in a real app with sessions, 
  // you would regenerate session IDs after login
  next();
};

module.exports = {
  securityHeaders,
  corsOptions,
  sanitize,
  xssClean,
  apiRateLimit,
  apiSlowDown,
  sensitiveEndpointRateLimit,
  validateInput,
  bruteForceProtection,
  checkPayloadSize,
  rotateSessionId
};