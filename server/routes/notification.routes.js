const { Router } = require("express");
const { checkSignature } = require("../middleware/authentication.middleware");
const {
  handleGetNotifications,
  handleReadNotification,
  handleGetUnreadNotifications,
  handleDeleteNotification,
  handleClearNotifications,
} = require("../controllers/notification.controller");

const router = Router();

router.get("/", checkSignature, handleGetNotifications);

router.get("/unread", checkSignature, handleGetUnreadNotifications);

router.post("/clear", checkSignature, handleClearNotifications);

router.post("/:notifId/read", checkSignature, handleReadNotification);

router.delete("/:notifId", checkSignature, handleDeleteNotification);

module.exports = router;
