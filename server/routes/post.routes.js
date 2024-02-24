/* eslint-disable no-undef */
const express = require("express");
const { check } = require("express-validator");
const postsController = require("../controllers/post.controller");
const { checkSignature } = require("../middleware/authentication.middleware");
const { tempUpload, fileUpload } = require("../middleware/file-upload");
const {
  handleCreatePost,
  handlePostComment,
  listNewsFeed,
  listComments,
  handleLikePost,
  unlikePost,
  handlePinPost,
  handleUnpinPost,
  handleUnretweetPost,
  getUserPosts,
  getPost,
  handleDeletePost,
  search,
  handleFollowingFeed,
  handleRepost,
} = require("../controllers/post.controller");
const {
  videoDurationLimit,
} = require("../middleware/videoDuration.middleware");

const router = express.Router();

router.post(
  "/new",
  checkSignature,
  fileUpload.single("media"),
  [
    check("content")
      .trim()
      .isString()
      .withMessage("Content must be a string")
      .isLength({ max: 280 }),
  ],
  handleCreatePost
);

router.get("/following", checkSignature, handleFollowingFeed);

router.get("/feed/:uid", checkSignature, listNewsFeed);

router.get("/:pid/comments/", checkSignature, listComments);

router.post("/likes/:pid", checkSignature, handleLikePost);

// Unlike a post
router.delete("/likes/:pid", checkSignature, unlikePost);

// Get likes for a post
router.get(
  "/posts/likes/:pid",
  checkSignature,
  postsController.getLikesForPost
);

router.post("/retweets/:pid", checkSignature, handleRepost);

router.delete("/retweets/:pid", checkSignature, handleUnretweetPost);

router.post(
  "/:pid/comments",
  checkSignature,
  fileUpload.single("media"),
  handlePostComment
);
router.get("/posts/search", checkSignature, search);

router.get("/posts/search/suggestions", checkSignature, search);

router.get("/users/:uid", checkSignature, getUserPosts);

router.get("/:pid", checkSignature, getPost);

router.delete("/:pid", checkSignature, handleDeletePost);

router.put("pin/:pid", checkSignature, handlePinPost);

router.put("unpin/:pid", checkSignature, handleUnpinPost);

module.exports = router;
