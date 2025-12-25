const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const connectDB = require('./src/config/database');
const redis = require('./src/config/redis');

// Import routes
const authRoutes = require('./src/routes/auth');
const messageRoutes = require('./src/routes/messages');
const userRoutes = require('./src/routes/users');

// Import security middleware
const {
  securityHeaders,
  corsOptions,
  sanitize,
  xssClean,
  apiRateLimit,
  apiSlowDown,
  sensitiveEndpointRateLimit,
  validateInput,
  bruteForceProtection,
  checkPayloadSize
} = require('./src/middleware/security');

// Import authentication middleware
const { authenticateJWT } = require('./src/middleware/authentication');

// Initialize Express app
const app = express();

// Security middleware
app.use(securityHeaders); // Security headers
app.use(cors(corsOptions)); // CORS configuration

// Rate limiting
app.use(apiSlowDown);
app.use(apiRateLimit);

// Body parsing middleware with size check
app.use(checkPayloadSize);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Data sanitization
app.use(sanitize);
app.use(xssClean);

// Database connections
connectDB();
redis.connect();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/messages', authenticateJWT, messageRoutes);
app.use('/api/users', authenticateJWT, userRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Create HTTP server
const PORT = process.env.PORT || 5000;
const server = createServer(app);

// Setup Socket.IO with Redis adapter for horizontal scaling
const io = new Server(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ["http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  }
});

// Use Redis adapter for Socket.IO to support multiple server instances
const redisAdapter = require('@socket.io/redis-adapter');
const { createAdapter } = redisAdapter;
const pubClient = require('./src/config/redis').duplicate();
const subClient = require('./src/config/redis').duplicate();

io.adapter(createAdapter(pubClient, subClient));

// Socket.IO connection handling
io.use((socket, next) => {
  // Here you can implement Socket.IO authentication if needed
  // For example, extracting and verifying JWT from query parameters
  const token = socket.handshake.auth.token || socket.handshake.query.token;
  if (token) {
    // Verify token and attach user data to socket
    // This is a simplified version - implement proper token verification
    try {
      // Attach user data to socket after token verification
      // socket.user = verifyToken(token);
      next();
    } catch (err) {
      next(new Error('Authentication error'));
    }
  } else {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  // Handle user joining a room
  socket.on('join-room', (roomId) => {
    socket.join(roomId);
    console.log(`Socket ${socket.id} joined room ${roomId}`);
  });

  // Handle user leaving a room
  socket.on('leave-room', (roomId) => {
    socket.leave(roomId);
    console.log(`Socket ${socket.id} left room ${roomId}`);
  });

  // Handle private messaging
  socket.on('private-message', (data) => {
    // Send message to specific user
    socket.to(data.recipientId).emit('private-message', {
      senderId: socket.id,
      message: data.message,
      timestamp: new Date()
    });
  });

  // Handle group messaging
  socket.on('group-message', (data) => {
    // Broadcast message to room except sender
    socket.to(data.roomId).emit('group-message', {
      senderId: socket.id,
      message: data.message,
      timestamp: new Date()
    });
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
});