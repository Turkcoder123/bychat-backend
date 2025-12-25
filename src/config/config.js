require('dotenv').config();

const config = {
  // Application
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  CLIENT_URL: process.env.CLIENT_URL || 'http://localhost:3000',
  
  // Database
  DB_HOST: process.env.DB_HOST || 'localhost',
  DB_PORT: process.env.DB_PORT || 5432,
  DB_NAME: process.env.DB_NAME || 'social_media_db',
  DB_USER: process.env.DB_USER || 'postgres',
  DB_PASSWORD: process.env.DB_PASSWORD || 'password',
  
  // Redis
  REDIS_HOST: process.env.REDIS_HOST || 'localhost',
  REDIS_PORT: process.env.REDIS_PORT || 6379,
  
  // JWT
  JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
  REFRESH_TOKEN_SECRET: process.env.REFRESH_TOKEN_SECRET || 'your-refresh-token-secret',
  REFRESH_TOKEN_EXPIRES_IN: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d',
  
  // Socket.IO
  SOCKET_IO_CORS: process.env.SOCKET_IO_CORS || 'http://localhost:3000',
  
  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX || 100, // limit each IP to 100 requests per windowMs
  
  // Performance
  MAX_CONNECTION_POOL: process.env.MAX_CONNECTION_POOL || 20,
  DB_QUERY_TIMEOUT: process.env.DB_QUERY_TIMEOUT || 30000, // 30 seconds
  
  // Security
  BCRYPT_SALT_ROUNDS: process.env.BCRYPT_SALT_ROUNDS || 12,
  
  // File Upload
  MAX_FILE_SIZE: process.env.MAX_FILE_SIZE || 10 * 1024 * 1024, // 10MB
  ALLOWED_FILE_TYPES: process.env.ALLOWED_FILE_TYPES || 'image/jpeg,image/png,image/gif,video/mp4,video/quicktime,audio/mpeg,audio/wav'
};

module.exports = config;