/* eslint-disable no-undef */
const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const notificationSchema = new Schema(
  {
    user: { type: mongoose.Types.ObjectId, ref: "User" },
    sender: { type: mongoose.Types.ObjectId, ref: "User" },
    post: { type: mongoose.Types.ObjectId, ref: "Post" },
    content: { type: String },
    timestamp: { type: Date, default: Date.now },
    type: {
      type: String,
      enum: ["like", "repost", "follow", "comment", "post"],
      required: true,
    },
    read: { type: Boolean, default: false },
  },
  { strict: false }
);

module.exports = mongoose.model("Notification", notificationSchema);
