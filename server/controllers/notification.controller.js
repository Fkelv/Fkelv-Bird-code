const { ObjectId } = require("mongodb");
const Notification = require("../models/notification");

const createNotification = async (io, payload) => {
  try {
    const user = payload.user;
    const sender = payload.sender;

    if (
      user.blockedUsers.includes(sender._id) ||
      user.mutedUsers.includes(sender._id)
    ) {
      console.log("User is muted/blocked");
      return;
    }
    const notification = new Notification(payload);
    await notification.save();
    io.to(payload.user._id.toString()).emit("notification", "new");
  } catch (e) {
    console.error("HandleCreateNotification error", e);
    throw Error("Error in creating notifications");
  }
};

const handleGetNotifications = async (req, res) => {
  try {
    const userId = req.user.userId;
    const notifications = await Notification.find({
      user: new ObjectId(userId),
    }).sort("-timestamp");
    return res.status(200).json(notifications);
  } catch (e) {
    console.log("error in getting notifications", e);
    return res.status(500).json({ message: "Error retrieving notifications" });
  }
};

const handleReadNotification = async (req, res) => {
  try {
    const notificationId = req.params.notifId;
    const notification = await Notification.findOneAndUpdate(
      { _id: notificationId },
      {
        read: true,
      },
      {
        new: true,
      }
    );

    return res.status(200).json(notification);
  } catch (e) {
    console.log("handleReadNotification error", e);
    return res
      .status(500)
      .json({ message: "Error while reading notifications" });
  }
};

const handleGetUnreadNotifications = async (req, res) => {
  try {
    const userId = req.user.userId;

    const notifications = await Notification.find({
      user: userId,
      read: false,
    }).sort("-timestamp");

    return res.status(200).json(notifications);
  } catch (e) {
    console.error("HandleGetUnreadNotifications error", e);
    return res.status(500).json({ message: "Error has occurred." });
  }
};

const handleClearNotifications = async (req, res) => {
  try {
    const userId = req.user.userId;
    await Notification.updateMany({ user: userId }, { read: true });
    return res.status(200).json({ message: "notifications cleared" });
  } catch (e) {
    console.error("handleClearNotification error", e);
    return res.status(500).json({ message: "Error has occurred" });
  }
};

const handleDeleteNotification = async (req, res) => {
  try {
    const notificationId = req.params.notifId;
    const userId = req.user.userId;

    const notification = await Notification.findById(notificationId);

    if (notification.user.toString() !== userId) {
      return res.status(403).json({ message: "Unauthorized operation" });
    }

    await Notification.findByIdAndDelete(notificationId);

    return res
      .status(200)
      .json({ message: "notification deleted successfully" });
  } catch (e) {
    console.error("handleDeleteNotification", e);
    return res.status(500).json({ message: "Error has occurred" });
  }
};
module.exports = {
  createNotification,
  handleReadNotification,
  handleGetNotifications,
  handleGetUnreadNotifications,
  handleClearNotifications,
  handleDeleteNotification,
};
