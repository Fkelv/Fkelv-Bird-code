const express = require("express");
const { checkSignature } = require("../middleware/authentication.middleware");
const {
  handleCreateVideo,
  handleGetById,
  handleGetUserVideos,
  handleGetFollowingVideos,
  handleDeleteVideo,
  fileGet,
  similarvideos 
} = require("../controllers/video.controller");
const { fileUpload } = require("../middleware/file-upload");
const router = express.Router();

router.post(
  "/new",
  checkSignature,
  fileUpload.fields([
    { name: "thumbnail", maxCount: 1 },
    { name: "video", maxCount: 1 },
  ]),
  handleCreateVideo
);
router.get('/images/:filename', fileGet)
router.get("/:videoId", handleGetById);
router.get("/users/:userId", handleGetUserVideos);
router.get("/users/:userId/following", handleGetFollowingVideos);
router.delete("/:videoId", checkSignature, handleDeleteVideo);
router.get('/similarvideos/:videoId',similarvideos )
module.exports = router;
