const onConnection = (socket) => {
  const roomId = socket.handshake.query.roomId;
  console.log("User connected successfully to socket with roomId:", roomId);

  if (roomId) {
    socket.join(roomId);
  }

  socket.on("disconnect", (reason) => {
    console.log("User disconnected to socket. Reason:", reason);
  });
  socket.on("error", (error) => {
    console.error("Socket IO error", error);
  });
};

module.exports = {
  onConnection,
};
