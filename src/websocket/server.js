const { handleUserConnection } = require('./handlers');

const setupWebSocket = (io) => {
  io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // Handle user authentication
    socket.on('authenticate', (token) => {
      // Here we would verify the JWT token and associate the socket with a user
      // For now, we'll just emit an authenticated event
      socket.emit('authenticated', { success: true, socketId: socket.id });
    });

    // Handle user connection and setup
    handleUserConnection(socket, io);

    // Handle disconnection
    socket.on('disconnect', (reason) => {
      console.log(`User disconnected: ${socket.id} - Reason: ${reason}`);
    });

    // Handle error
    socket.on('error', (error) => {
      console.error(`Socket error: ${socket.id}`, error);
    });
  });
};

module.exports = { setupWebSocket };