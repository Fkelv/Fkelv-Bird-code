/* eslint-disable no-undef */
const mongoose = require("mongoose");

const Schema = mongoose.Schema;
const userInteractionSchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  post: {
    type: Schema.Types.ObjectId,
    ref: "Post",
    required: true,
  },
  interactionType: {
    type: String,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("UserInteraction", userInteractionSchema);
