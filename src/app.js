const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const redis = require('redis');
const { createAdapter } = require('@socket.io/redis-adapter');

const config = require('./config/config');
const { setupWebSocket } = require('./websocket/server');

const app = express();
const server = http.createServer(app);

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.CLIENT_URL,
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Initialize Redis client for Socket.IO adapter
const redisClient = redis.createClient({
  url: `redis://${config.REDIS_HOST}:${config.REDIS_PORT}`
});

redisClient.on('error', (err) => {
  console.error('Redis Client Error', err);
});

redisClient.connect().then(async () => {
  console.log('Connected to Redis');

  // Create Redis adapter for Socket.IO
  const pubClient = redisClient;
  const subClient = pubClient.duplicate();

  await Promise.all([pubClient.connect(), subClient.connect()]);

  const io = new Server(server, {
    cors: {
      origin: config.CLIENT_URL,
      methods: ["GET", "POST"]
    }
  });

  // Set up Redis adapter for Socket.IO
  io.adapter(createAdapter(pubClient, subClient));

  // Setup WebSocket handlers
  setupWebSocket(io);

  // Basic route
  app.get('/', (req, res) => {
    res.json({ message: 'Social Media & Messaging Backend API' });
  });

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.status(200).json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      service: 'Backend API'
    });
  });

  // Handle server startup
  const PORT = config.PORT || 3000;
  server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Environment: ${config.NODE_ENV}`);
  });

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await redisClient.quit();
    server.close(() => {
      console.log('Process terminated');
    });
  });
}).catch(err => {
  console.error('Could not connect to Redis', err);
});

module.exports = { app, server };