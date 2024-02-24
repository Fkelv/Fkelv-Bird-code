/* eslint-disable no-undef */
const { validationResult } = require("express-validator");

const HttpError = require("../models/http-error");
const User = require("../models/user");
const Post = require("../models/post");
const Subscription = require("../models/subscriptions");
const Message = require("../models/messages");
const Plan = require("../models/plan");
const { ObjectId } = require("mongodb");
const { createNotification } = require("./notification.controller");
// // Set the default access level for all users
// access.setDefaultLevel(ACCESS_LEVELS.GUEST);
// access.grant(ACCESS_LEVELS.ADMIN, '/admin/*');

const Secret_Key = "";

const stripe = require("stripe")(Secret_Key);

const getUsers = async (req, res, next) => {
  let users;
  try {
    users = await User.find({}, "-password");
  } catch (err) {
    const error = new HttpError(
      "Fetching users failed, please try again later.",
      500
    );
    return next(error);
  }
  res.json({ users: users.map((user) => user.toObject({ getters: true })) });
};

const getUser = async (req, res) => {
  try {
    const userId = req.params.uid;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "Could not find user" });
    }

    return res.json(user);
  } catch (err) {
    console.error("getUser error", err);
    return res
      .status(500)
      .json({ message: "Something went wrong, could not find a user." });
  }
};

const logout = async (req, res) => {
  res.status(200).json({ success: true, message: "Logout successful" });
};

const bookmarkPost = async (req, res, next) => {
  const placeId = req.params.pid;
  const userId = req.params.uid;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  user.bookmarks.push(placeId);

  try {
    await user.save();
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not add bookmark.",
      500
    );
    return next(error);
  }

  res.status(200).json({ user: user.toObject({ getters: true }) });
};

const addNotifications = async (req, res, next) => {
  const interactorId = req.params.interactor;
  const userId = req.params.uid;
  const event = req.params.event;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  let interactor;
  try {
    interactor = await User.findById(interactorId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  if (event == "like") {
    user.notifications.push(interactor.name + " liked your post");
  } else if (event == "message") {
    user.notifications.push("Message from " + interactor.name);
  } else if (event == "commented") {
    user.notifications.push(interactor.name + " commented on your post");
  } else if (event == "share") {
    user.notifications.push(interactor.name + " shared on your post");
  } else {
    user.notifications.push("Notification from " + interactor.name);
  }

  try {
    await user.save();
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not add bookmark.",
      500
    );
    return next(error);
  }

  res.status(200).json({ user: user.toObject({ getters: true }) });
};

const clearNotifications = async (req, res, next) => {
  const userId = req.params.uid;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  user.notifications = [];

  try {
    await user.save();
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not add bookmark.",
      500
    );
    return next(error);
  }

  res.status(200).json({ user: user.toObject({ getters: true }) });
};

const verifyAccount = async (req, res, next) => {
  const userId = req.params.uid;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  let today = new Date();

  if (
    user.newsArticles != [] &&
    user.verificationDetails.website != "" &&
    user.verificationDetails.document != "" &&
    user.verificationDetails.officialEmail != "" &&
    user.verificationDetails.googleTrendsProfile != "" &&
    user.verificationDetails.wikipediaLink != "" &&
    user.verificationDetails.instagramLink != "" &&
    user.contact != 0 &&
    user.username != "" &&
    user.image != "" &&
    user.email != "" &&
    user.lastLogin > today.setMonth(today.getMonth() - 6)
  ) {
    user.verified = true;
  } else {
    user.verified = false;
  }

  try {
    await user.save();
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not verify account.",
      500
    );
    return next(error);
  }

  res.status(200).json({ user: user.toObject({ getters: true }) });
};

const saveVerificationDetails = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(
      new HttpError("Invalid inputs passed, please check your data.", 422)
    );
  }

  const {
    website,
    document,
    officialEmail,
    newsArticles,
    googleTrendsProfile,
    wikipediaLink,
    instagramLink,
  } = req.body;

  const userId = req.params.uid;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  user.verificationDetails.website = website;
  user.verificationDetails.document = document;
  user.verificationDetails.newsArticles = [newsArticles];
  user.verificationDetails.googleTrendsProfile = googleTrendsProfile;
  user.verificationDetails.wikipediaLink = wikipediaLink;
  user.verificationDetails.instagramLink = instagramLink;

  let today = new Date();

  if (
    user.verificationDetails.newsArticles != [] &&
    user.verificationDetails.website != "" &&
    user.verificationDetails.document != "" &&
    user.verificationDetails.officialEmail != "" &&
    user.verificationDetails.googleTrendsProfile != "" &&
    user.verificationDetails.wikipediaLink != "" &&
    user.verificationDetails.instagramLink != "" &&
    user.contact != 0 &&
    user.username != "" &&
    user.image != "" &&
    user.email != "" &&
    user.lastLogin > today.setMonth(today.getMonth() - 6)
  ) {
    user.verified = true;
  } else {
    user.verified = false;
  }

  try {
    await createdUser.save();
  } catch (err) {
    const error = new HttpError(
      "Verification request failed, please try again later." + err,
      500
    );
    return next(error);
  }

  res.status(200).json({ user: user.toObject({ getters: true }) });
};

const makePayment = async (req, res, next) => {
  const userId = req.body.uid;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  if (user.customerId == "") {
    stripe.customers
      .create({
        email: user.email,
        //source: req.body.stripeToken,
        name: user.name,
      })
      .then(async (customer) => {
        user.customerId = customer.id;
        try {
          await createdUser.save();
        } catch (err) {
          const error = new HttpError(
            "Customer creation failed, please try again later.",
            500
          );
          return next(error);
        }

        return stripe.charges.create({
          amount: req.body.amount,
          description: "Payment",
          currency: "USD",
          customer: customer.id,
        });
      })
      .then((charge) => {
        res.send("Success"); // If no error occurs
      })
      .catch((err) => {
        res.send(err); // If some error occurs
      });
  } else {
    return stripe.charges
      .create({
        amount: req.body.amount,
        description: "Payment",
        currency: "USD",
        customer: user.customerId,
      })
      .then((charge) => {
        res.send("Success"); // If no error occurs
      })
      .catch((err) => {
        res.send(err); // If some error occurs
      });
  }
};

const subscribeUser = async (req, res, next) => {
  const userId = req.params.uid;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  const reqPlanId = req.params.planId;
  user.planId = reqPlanId;
  let plan;
  try {
    plan = await Plan.findById(reqPlanId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find plan.",
      500
    );
    return next(error);
  }

  let currDate = new Date();

  const newSubscription = new Subscription({
    title: plan.title,
    description: plan.description,
    date: currDate,
    expireMonth: currDate.setMonth(currDate.getMonth + plan.duration),
    expireYear: currDate.getFullYear(),
    planId: reqPlanId,
    userId: user.id,
  });

  try {
    await newSubscription.save();
  } catch (err) {
    const error = new HttpError(
      "Subscription failed, please try again later." + err,
      500
    );
    return next(error);
  }

  try {
    await user.save();
  } catch (err) {
    const error = new HttpError(
      "User updation failed, please try again later.",
      500
    );
    return next(error);
  }

  res
    .status(200)
    .json({ newSubscription: newSubscription.toObject({ getters: true }) });
};

const sendMessage = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(
      new HttpError("Invalid inputs passed, please check your data.", 422)
    );
  }

  let user;
  try {
    user = await User.findById(sender);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  const { text, sender, recepient } = req.body;

  const newMessage = new Message({
    text: text,
    datetime: new Date(),
    sent: true,
    seen: false,
    sender: sender,
    recepient: recepient,
  });

  try {
    await newMessage.save();
  } catch (err) {
    const error = new HttpError("Message could not be sent.", 500);
    return next(error);
  }

  sender.messages.push({ message_id: newMessage.id, seen: false });

  try {
    await sender.save();
  } catch (err) {
    const error = new HttpError("Message could not be sent.", 500);
    return next(error);
  }

  res.status(201).json({ messageId: newMessage.id });
};

const getMessage = async (req, res, next) => {
  const userId = req.body.userId;

  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find message.",
      500
    );
    return next(error);
  }

  res.json({ messages: user.messages });
};

const handleBlockUser = async (req, res) => {
  try {
    const blockedUserId = req.params.userId;
    const userId = req.user.userId;
    const blockedUser = await User.findById(blockedUserId);

    const user = await User.findById(userId);
    if (!user || !blockedUser) {
      return res.status(404).json({ message: "Could not find user" });
    }
    user.followers.pull(new ObjectId(blockedUserId));
    user.following.pull(new ObjectId(blockedUserId));
    blockedUser.following.pull(new ObjectId(userId));
    user.blockedUsers.push(new ObjectId(blockedUser));
    await blockedUser.save();
    const updatedUser = await user.save();
    return res.status(200).json(updatedUser);
  } catch (e) {
    console.error("handleBlockUser error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const handleUnblockUser = async (req, res) => {
  try {
    const blockedUserId = req.params.userId;
    const userId = req.user.userId;
    const blockedUser = await User.findById(blockedUserId);
    const user = await User.findById(userId);
    if (!user || !blockedUser) {
      return res
        .status(404)
        .json({ message: "handleUnblockUser: Could not find user" });
    }

    user.blockedUsers.pull(new ObjectId(blockedUserId));
    const updatedUser = await user.save();

    return res.status(200).json(updatedUser);
  } catch (e) {
    console.error("handleUnblock user error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const reportUser = async (req, res, next) => {
  const reportedUserId = req.body.bUserId;
  const userId = req.params.uid;

  let user;
  let reportedUser;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  try {
    reportedUser = await User.findById(reportedUserId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  user.reportedUsers.push(reportedUser);
  try {
    await user.save();
  } catch (err) {
    const error = new HttpError("User could not be saved", 500);
    return next(error);
  }

  res.status(200).json({ user: user.toObject({ getters: true }) });
};

const handleMuteUser = async (req, res) => {
  try {
    const muteUserId = req.params.userId;
    const userId = req.user.userId;

    const user = await User.findById(userId);
    const muteUser = await User.findById(muteUserId);

    if (!user || !muteUser) {
      return res.status(404).json({ message: "Could not find user." });
    }
    user.mutedUsers.push(muteUser);
    const updatedUser = await user.save();
    return res.status(200).json(updatedUser);
  } catch (e) {
    console.error("handleMuteUser error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const handleUnmuteUser = async (req, res) => {
  try {
    const unmuteUserId = req.params.userId;
    const userId = req.user.userId;

    const user = await User.findById(userId);
    const unmuteUser = await User.findById(unmuteUserId);

    if (!user || !unmuteUser) {
      return res.status(404).json({ message: "Could not find user" });
    }

    user.mutedUsers.pull(new ObjectId(unmuteUserId));
    const updatedUser = await user.save();

    return res.status(200).json(updatedUser);
  } catch (e) {
    console.error("handleUnmuteUser error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const addPaymentMethod = async (req, res, next) => {
  const paymentMethodObject = req.body.paymentMethod;
  const userId = req.params.uid;

  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }

  user.paymentMethods.push(paymentMethodObject);

  try {
    await user.save();
  } catch (err) {
    const error = new HttpError("User could not be saved", 500);
    return next(error);
  }

  try {
    // Collect the payment method details from the request
    const payMethod = req.body.paymentMethod;
    const customer = user.customerId;

    // Attach the payment method to the customer
    const paymentMethod = await stripe.paymentMethods.attach(paymentMethod, {
      customer: customer,
    });

    res.send({ paymentMethod });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
};

const getAccessRights = async (req, res, next) => {
  const userId = req.params.uid;
  let user;
  try {
    user = await User.findById(userId);
  } catch (err) {
    const error = new HttpError(
      "Something went wrong, could not find user.",
      500
    );
    return next(error);
  }
  res.status(201).json({ accessRight: user.accessRight });
};

const getUserByString = async (req, res, next) => {
  const subName = req.params.subName;

  User.find(
    { name: { $regex: subName, $options: "i" } },
    function (err, results) {
      res.status(201).json({ users: results });
    }
  );
};

const updateUserById = async (req, res) => {
  const token = req.user;
  const userId = req.params.uid;

  if (token.userId !== userId) {
    console.error(
      `User ${token.userId} tried to update user ${userId} information`
    );
    return res
      .status(403)
      .send({ message: "Cannot update another user's information" });
  }

  try {
    const body = req.body;
    console.log("body:", body);
    const updatedUser = await User.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      body,
      { new: true }
    );
    console.log("updae", updatedUser);
    return res.status(200).send(updatedUser);
  } catch (e) {
    console.error("HandleUpdateUserById error", e.message);
    return res
      .status(500)
      .send({ message: "An error ocurred while updating user" });
  }
};

const handleFollow = async (req, res) => {
  try {
    const userId = req.user.userId;
    const followId = req.params.followId;
    const io = req.io;
    const followedUser = await User.findById(followId);
    if (followedUser.blockedUsers.includes(userId)) {
      return res
        .status(403)
        .json({ message: "Failed!This user has blocked you" });
    }
    if (followedUser.followers.includes(userId)) {
      return res.status(400).json({ message: "already followed" });
    }

    followedUser.followers.push(new ObjectId(userId));
    await followedUser.save();
    const currentUser = await User.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $push: { following: followId } },
      { new: true }
    );

    const notificationMessage = `${currentUser.name} has followed you.`;

    await createNotification(io, {
      content: notificationMessage,
      user: followedUser,
      sender: currentUser,
      type: "follow",
    });
    return res.status(200).json({ message: "followed successfully" });
  } catch (e) {
    console.error("HandleFollow error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const handleUnfollow = async (req, res) => {
  try {
    const userId = req.user.userId;
    const followId = req.params.followId;

    const followedUser = await User.findOneAndUpdate(
      { _id: followId },
      { $pull: { followers: userId } },
      { new: true }
    );
    const currentUser = await User.findOneAndUpdate(
      { _id: userId },
      { $pull: { following: followId } },
      { new: true }
    );

    return res.status(200).json({ message: "unfollowed successful" });
  } catch (e) {
    console.error("handleUnfollow error", e);
    return res.status(500).json({ message: "server error" });
  }
};

const handleCurrentUser = async (req, res) => {
  try {
    const userId = req.user.userId;
    console.log("user", userId);
    const user = await User.findById(userId);

    return res.status(200).json(user);
  } catch (e) {
    console.error("Error in handleCurrentUser", e);
    return res
      .status(500)
      .json({ message: "something happened at the server" });
  }
};

const handleGetFollowers = async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId).populate(
      "followers",
      "id name avatar username followers following"
    );
    return res.status(200).json(user.followers);
  } catch (e) {
    console.log("handlegetfollowers error");
    return res.status(500).json({ message: "Server error" });
  }
};

const handleGetFollowing = async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId).populate(
      "following",
      "id name username avatar followers following"
    );

    return res.status(200).json(user.following);
  } catch (e) {
    console.log("HandleGetFollowers error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const handleGetUserReplies = async (req, res) => {
  try {
    const userId = req.params.userId;
    const posts = await Post.find({
      user: new ObjectId(userId),
      parentPost: { $ne: null },
    })
      .populate("user", "_id name username avatar")
      .populate({
        path: "parentPost",
        populate: {
          path: "user",
          model: "User",
        },
      })
      .sort({ timestamp: -1 });
    const filteredPosts = posts.filter((post) => !!post.parentPost);
    return res.status(200).send(filteredPosts);
  } catch (e) {
    console.error("HandleGetUserReplies error", e);
    return res
      .status(500)
      .json({ message: "Something's wrong. Try again later" });
  }
};

const handleGetUserMedia = async (req, res) => {
  try {
    const userId = req.params.userId;
    const posts = await Post.find({
      user: new ObjectId(userId),
      media: { $ne: null },
    })
      .populate("user", "_id name username avatar")
      .sort({ timestamp: -1 });
    return res.status(200).json(posts);
  } catch (e) {
    console.error("handleGetUserMedia error", e);
    return res.status(500).json({ message: "Server error" });
  }
};

module.exports = {
  getUsers,
  getUser,
  logout,
  bookmarkPost,
  addNotifications,
  clearNotifications,
  verifyAccount,
  saveVerificationDetails,
  makePayment,
  subscribeUser,
  getMessage,
  sendMessage,
  handleBlockUser,
  handleMuteUser,
  handleUnmuteUser,
  reportUser,
  addPaymentMethod,
  getAccessRights,
  getUserByString,
  updateUserById,
  handleFollow,
  handleUnfollow,
  handleCurrentUser,
  handleGetFollowers,
  handleGetFollowing,
  handleGetUserReplies,
  handleGetUserMedia,
  handleUnblockUser,
};
exports.getUsers = getUsers;
exports.getUser = getUser;
exports.logout = logout;
exports.bookmarkPost = bookmarkPost;
exports.addNotifications = addNotifications;
exports.clearNotifications = clearNotifications;
exports.verifyAccount = verifyAccount;
exports.saveVerificationDetails = saveVerificationDetails;
exports.makePayment = makePayment;
exports.subscribeUser = subscribeUser;
exports.getMessage = getMessage;
exports.sendMessage = sendMessage;
exports.reportUser = reportUser;
exports.addPaymentMethod = addPaymentMethod;
exports.getAccessRights = getAccessRights;
exports.getUserByString = getUserByString;
exports.updateUserById = updateUserById;
