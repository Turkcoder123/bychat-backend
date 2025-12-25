// WebSocket event handlers

const handleUserConnection = (socket, io) => {
  // Handle sending a message
  socket.on('sendMessage', (data) => {
    const { recipientId, content, type = 'text' } = data;
    
    // Create message object
    const message = {
      id: generateId(),
      senderId: socket.userId, // This would be set after authentication
      recipientId,
      content,
      type,
      timestamp: new Date().toISOString(),
      status: 'sent'
    };

    // Emit message to recipient (if they're connected)
    // In a real implementation, we would check if recipient is online
    // and store the message in the database for offline users
    socket.to(recipientId).emit('newMessage', message);
    
    // Also emit to sender to confirm
    socket.emit('messageSent', { ...message, status: 'delivered' });
    
    // In a real app, we would save the message to the database here
    console.log('Message sent:', message);
  });

  // Handle joining a room
  socket.on('joinRoom', (roomId) => {
    socket.join(roomId);
    socket.emit('joinedRoom', { roomId });
  });

  // Handle leaving a room
  socket.on('leaveRoom', (roomId) => {
    socket.leave(roomId);
    socket.emit('leftRoom', { roomId });
  });

  // Handle user typing indicator
  socket.on('typing', (data) => {
    const { recipientId, isTyping } = data;
    socket.to(recipientId).emit('userTyping', {
      senderId: socket.userId,
      isTyping
    });
  });

  // Handle user online status
  socket.on('setOnlineStatus', (status) => {
    // Update user's online status in database/cache
    // Emit to friends/contacts that user is online/offline
    socket.broadcast.emit('userStatusChanged', {
      userId: socket.userId,
      status
    });
  });
};

// Helper function to generate unique IDs
const generateId = () => {
  return require('uuid').v4();
};

module.exports = { handleUserConnection };