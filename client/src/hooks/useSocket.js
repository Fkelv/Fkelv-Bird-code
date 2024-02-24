import { useEffect, useRef } from "react";
import { io } from "socket.io-client";

const API_URL = `${import.meta.env.VITE_API_URL}`;

export const useSocket = (userId) => {
  const socketRef = useRef();

  useEffect(() => {
    socketRef.current = io(API_URL, {
      query: {
        roomId: userId,
      },
    });

    socketRef.current.on("connect", () => {
      console.log("User connected");
    });

    socketRef.current.on("disconnect", () => {
      console.log("User disconnected");
    });
    return () => {
      socketRef.current.disconnect();
    };
  }, [userId]);

  return socketRef.current;
};
