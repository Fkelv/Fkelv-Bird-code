/* eslint-disable no-unused-vars */
const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const { Server } = require("socket.io");
const http = require("http");
const placesRoutes = require("./routes/places-routes");
const usersRoutes = require("./routes/user.routes");
const postRoutes = require("./routes/post.routes");
const authRoutes = require("./routes/auth.routes");
const fileRoutes = require("./files/file.router");
const videoRoutes = require("./routes/video.routes");
const notificationRoutes = require("./routes/notification.routes");
const HttpError = require("./models/http-error");
const morgan = require("morgan");
const { onConnection } = require("./sockets/socket");
require("dotenv").config();

const app = express();
const FRONTEND_URL = process.env.FRONTEND_URL;
cors;
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
    exposedHeaders: ["Authorization", "Refresh-token"],
  })
);
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", process.env.FRONTEND_URL);
  next();
});

const server = http.createServer(app);
app.use(bodyParser.json());
app.use(express.static("uploads"));

const io = new Server(server, {
  cors: { origin: process.env.FRONTEND_URL },
});

io.on("connection", onConnection);

app.use((req, res, next) => {
  req.io = io;
  next();
});

// const accessLogStream = fs.createWriteStream(
//   path.join(__dirname, "logs/access.log"),
//   { flags: "a" }
// );

// // Use Morgan middleware to log HTTP requests to the file
// app.use(morgan("combined", { stream: accessLogStream }));

app.use("/api/posts", postRoutes);
app.use("/api/places", placesRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/notifications", notificationRoutes);
app.use("/api/videos", videoRoutes);

app.use((req, res, next) => {
  const error = new HttpError("Could not find this route.", 404);
  throw error;
});

app.use((error, req, res, next) => {
  console.log(error);
  if (req.file) {
    fs.unlink(req.file.path, (err) => {
      console.log(err);
    });
  }
  if (res.headerSent) {
    return next(error);
  }
  res.status(error.code || 500);
  res.json({ message: error.message || "An unknown error occurred!" });
});

const mongo_DB_URI = process.env.DATABASE_URI;

mongoose
  .connect(mongo_DB_URI, { useNewUrlParser: true, useUnifiedTopology: true, dbName: "twitterClone" })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.log(err);
  });

//messages
app.use(express.static(__dirname + "/public"));

//video player

app.use((req, res, next) => {
  req.io = io;
  req.brr = { essst: "ree" };
  next();
});

app.get("/video", (req, res) => {
  res.sendFile(path.join(__dirname + "/public/video.html"));
});

app.get("/video/:filename", (req, res) => {
  res.sendFile(path.join(__dirname + "/public/videos/" + req.params.filename));
});

server.listen(8000, () => {
  console.log("listening on *:8000");
});

let viewerCount = 0;

// io.on("connection", (socket) => {
//   console.log("a user connected");
//   viewerCount++;
//   io.emit("viewer count", viewerCount);

//   socket.on("disconnect", () => {
//     console.log("user disconnected");
//     viewerCount--;
//     io.emit("viewer count", viewerCount);
//   });
// });
