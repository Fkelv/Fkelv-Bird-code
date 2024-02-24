/* eslint-disable no-undef */
const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const retweetSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: "User" },
    post: { type: Schema.Types.ObjectId, ref: "Post" },
  },
  { strict: false }
);

module.exports = mongoose.model("Retweet", retweetSchema);
