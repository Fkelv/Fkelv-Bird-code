/* eslint-disable no-undef */
const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const VideoSchema = new Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  tags: [{ type: String }],
  category: { type: String, required: false },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  views: { type: Number, required: false, default: 0 },
  likes: { type: Number, required: false, default: 0 },
  dislikes: { type: Number, required: false, default: 0 },
  duration: { type: Number, required: false },
  visibility: {
    type: String,
    enum: ["private", "public"],
    required: true,
    default: "public",
  },
  thumbnailURL: { type: String, required: false },
  videoURL: { type: String, required: true },
},{timestamps:true});

module.exports = mongoose.model("Video", VideoSchema);
