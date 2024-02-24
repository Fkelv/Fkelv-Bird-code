const Video = require("../models/videos");
const User = require("../models/user");
const { validationResult } = require("express-validator");
const { ObjectId } = require("mongodb");
const path = require('path');
const fs = require('fs')

const getURL = (full) => {
  const parts = full.split("/");
  return parts.slice(parts.length - 2).join("/");
};

const handleCreateVideo = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Invalid inputs passed" });
    }
    const userId = req.user.userId;

    const { title, description, category, visibility, duration = 0 } = req.body;

    const thumbnailURL = getURL(req.files["thumbnail"][0].path);
    const videoURL = getURL(req.files["video"][0].path);
    const newVideo = new Video({
      title,
      description,
      category,
      visibility,
      duration,
      uploadDate: Date.now(),
      thumbnailURL,
      videoURL,
      user: userId,
    });

    const saveVideo = await newVideo.save();

    return res.status(201).json(saveVideo);
  } catch (e) {
    console.error("handleCreateVideo error", e);
    return res.status(500).json({ message: "Try again next time!" });
  }
};

const handleGetById = async (req, res) => {
  try {
    const videoId = req.params.videoId;
    const video = await Video.findById(videoId).populate(
      "user",
      "_id name username avatar"
    );

    if (!video) {
      console.log("Video not found");
      return res.status(404).json({ message: "Could not find video." });
    }

    return res.status(200).json(video);
  } catch (e) {
    console.error("handleGetById error", e);
    return res.status(500).json({ message: "Server error" });
  }
};


const handleGetUserVideos = async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId);


    if (!user) {
      return res.status(404).json({ message: "Could not find user" });
    }
    const videos = await Video.find({ user: new ObjectId(userId) }).sort({ createdAt: -1 }) 

    const userIds = videos.map((e) => e.user);

    const userPromises = userIds.map(async (userId) => {
      const user = await User.findById(userId);
      return user ? user.avatar : null; // Return null if user not found
    });
    
    const avatars = await Promise.all(userPromises);
    
    const newData = videos.map((video, index) => {
      return {
        ...video.toObject(),
        avatar: avatars[index], // Add the name property to each video object
      };
    });
  
    return res.status(200).json(newData);
  } catch (e) {
    console.error("handlegetuservideos error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const handleGetFollowingVideos = async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "Could not find user" });
    }

    const videos = await Video.find({
      user: { $in: user.following },
    })
      .populate("user", "_id name username avatar")
      .sort("-uploadDate");

    return res.status(200).json(videos);
  } catch (e) {
    console.error("handleGetFollowingVideos", e);
    return res.status(500).json({ message: "server error." });
  }
};
const handleDeleteVideo = async (req, res) => {
  try {
    const userId = req.user.userId;
    const videoId = req.params.videoId;

    const user = await User.findById(userId);

    const video = await Video.findById(videoId);

    if (!user | !video) {
      console.error("could not find user/video");
      return res.status(404).json({ message: "Could not find user" });
    }

    if (video.user._id !== user._id) {
      return res.status(403).json({ message: "Unauthorized action" });
    }

    await Video.deleteOne({ _id: videoId });
    return res.status(200).json({ message: "Video deleted successfully" });
  } catch (e) {
    console.error("could not delete video", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const fileGet =(req, res)=>{
  const filename = req.params.filename;
  const filePath = path.join(__dirname,"..", 'uploads', 'images', filename );

  // Check if the file exists
  if (fs.existsSync(filePath)) {
    // Stream the video file to the response
    res.sendFile(filePath);
  } else {
    // File not found, send a 404 status code
    res.status(404).json({ error: 'File not found' });
  }
}

const similarvideos =async(req, res)=>{
      const videoId = req.params.videoId
      const data =  await  Video.find({ _id: { $ne: videoId } }).limit(10)
 
      const userIds = data.map((e) => e.user);

const userPromises = userIds.map(async (userId) => {
  const user = await User.findById(userId);
  return user ? user.name : null; // Return null if user not found
});

const names = await Promise.all(userPromises);

const newData = data.map((video, index) => {
  return {
    ...video.toObject(),
    name: names[index], // Add the name property to each video object
  };
});
 
      
      
      return res.status(200).json(newData)
}

module.exports = {
  handleCreateVideo,
  handleGetById,
  handleGetUserVideos,
  handleGetFollowingVideos,
  handleDeleteVideo,
  fileGet,
  similarvideos 
};
