/* eslint-disable no-undef */
const express = require("express");
const { check } = require("express-validator");

const { checkSignature } = require("../middleware/authentication.middleware");

const usersController = require("../controllers/user.controllers");
const {
  handleFollow,
  handleUnfollow,
  handleCurrentUser,
  handleGetFollowers,
  handleGetFollowing,
  handleGetUserReplies,
  handleGetUserMedia,
  handleBlockUser,
  handleMuteUser,
  handleUnblockUser,
  handleUnmuteUser,
} = require("../controllers/user.controllers");
const { handleGetPinnedPost } = require("../controllers/post.controller");
// const fileUpload = require("../middleware/file-upload");
// Configure multer for file uploads

const router = express.Router();

router.get("/", usersController.getUsers);

router.get("/me", checkSignature, handleCurrentUser);

router.get("/:uid", checkSignature, usersController.getUser);

router.put("/:uid", checkSignature, usersController.updateUserById);

router.post("/logout", usersController.logout);

router.post("/bookmark/:pid/:uid", usersController.bookmarkPost);

router.post(
  "/notification/:uid/:event",
  checkSignature,
  usersController.addNotifications
);

router.delete(
  "/notification/:uid",
  checkSignature,
  usersController.clearNotifications
);

router.post("/verify/:uid", checkSignature, usersController.verifyAccount);

router.post(
  "/saveVerificationDetails/:uid",
  checkSignature,
  usersController.saveVerificationDetails
);

router.post("/users/pay", checkSignature, usersController.makePayment);

router.post(
  "/users/subscribe/:uid/:planId",
  checkSignature,
  usersController.subscribeUser
);

router.post("/users/message", checkSignature, usersController.sendMessage);

router.get("/users/message", checkSignature, usersController.getMessage);

router.post("/block/:userId", checkSignature, handleBlockUser);

router.post("/unblock/:userId", checkSignature, handleUnblockUser);

router.post("/mute/:userId", checkSignature, handleMuteUser);

router.post("/unmute/:userId", checkSignature, handleUnmuteUser);

router.post("/users/report/:uid", checkSignature, usersController.reportUser);

router.post(
  "/addPaymentMethod/:uid",
  checkSignature,
  usersController.addPaymentMethod
);

router.get(
  "/getAccessRights/:uid",
  checkSignature,
  usersController.getAccessRights
);

router.get(
  "/getUserByString/:subName",
  checkSignature,
  usersController.getUserByString
);

router.post("/follow/:followId", checkSignature, handleFollow);

router.post("/unfollow/:followId", checkSignature, handleUnfollow);

router.get("/:userId/following", checkSignature, handleGetFollowing);

router.get("/:userId/followers", checkSignature, handleGetFollowers);

router.get("/:userId/replies", checkSignature, handleGetUserReplies);

router.get("/:userId/media", checkSignature, handleGetUserMedia);

router.get("/:userId/posts/pinned", checkSignature, handleGetPinnedPost);

module.exports = router;
