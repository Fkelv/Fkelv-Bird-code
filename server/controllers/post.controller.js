/* eslint-disable no-unreachable */
/* eslint-disable no-inner-declarations */
/* eslint-disable no-undef */
const { validationResult } = require("express-validator");

const HttpError = require("../models/http-error");
//const natural = require("natural");
const axios = require("axios").default;

const Post = require("../models/post");
const User = require("../models/user");
const UserInteraction = require("../models/userInteration");
const { ObjectId } = require("mongodb");
const { createNotification } = require("./notification.controller");

const endpointUrl = "https://api.edenai.run/v2/text/topic_extraction";

const config = {
  headers: {
    Authorization: `Bearer ${process.env.EDEN_AI_API_KEY}`,
  },
};

const getURL = (full) => {
  const parts = full.split("/");
  return parts.slice(parts.length - 2).join("/");
};

const handleCreatePost = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return next(
        new HttpError("Invalid inputs passed, please check your data.", 422)
      );
    }
    const io = req.io;
    const userId = req.user.userId;
    const { content } = req.body;
    const { path, mimetype } = req.file || {};
    const mediaFile = req.file ? getURL(path) : null;
    const mediaType = req.file ? mimetype : null;

    let keywords;

    if (content !== "") {
      const postData = {
        providers: "openai",
        text: content,
        language: "en",
      };

      const response = await axios.post(endpointUrl, postData, config);

      keywords = response.data.openai.items[0].category;
    }
    const newPost = new Post({
      user: userId,
      content: content,
      mediaType: mediaType,
      media: mediaFile,
      keywords: {
        content: keywords,
      },
    });
    const savePost = await newPost.save();
    notifyFollowers(savePost._id, userId, io);
    return res.status(201).json(savePost);
  } catch (err) {
    console.error("handlecreatepost", err);
    const error = new HttpError("Error Creating tweet", 500);
    return next(error);
  }
};

const notifyFollowers = async (postId, userId, io) => {
  console.log("done", postId);
  const user = await User.findById(userId);
  const followers = user.followers.map((follower) => follower.toString());
  followers.forEach((follower) => {
    if (io.sockets.adapter.rooms.has(follower)) {
      io.to(follower).emit("feedUpdate", {
        userId,
        postId,
      });
    }
  });
};

const listNewsFeed = async (req, res, next) => {
  const userID = req.params.uid;
  const existingUser = await User.findOne({ _id: userID });
  try {
    let relatedPosts;
    const userLikedPosts = await Post.find({ likes: userID }).exec();

    const userCommentedPosts = await Post.find({
      "comments[0].postedBy": userID,
    });

    if (userLikedPosts.length == 0 && userCommentedPosts.length == 0) {
      // User has liked posts, so retrieve all posts
      relatedPosts = await Post.find({})
        .populate("comments.postedBy", "_id name username")
        .populate("user", "_id name username")
        .sort("-timestamp")
        .exec();
    } else {
      const keywordTexts = userLikedPosts.flatMap(
        (post) => post.keywords[0].content
      );

      const commentKeywordTexts = userCommentedPosts.flatMap(
        (post) => post.keywords[0].content
      );

      const userKeywords = [...new Set(keywordTexts, commentKeywordTexts)];
      relatedPosts = await Post.find({
        $and: [
          {
            $or: [
              {
                "keywords.content": {
                  $in: userKeywords,
                },
              },
              {
                "user.places": {
                  $eq: existingUser.places,
                },
              },
            ],
          },
          {
            parentPost: null,
          },
        ],
      })
        .populate("comments.postedBy", "_id name")
        .populate("user", "_id name username avatar")
        .sort("-timestamp")
        .exec();
    }
    return res.status(200).json(relatedPosts);
  } catch (err) {
    const error = new HttpError("Error listing new posts " + err, 500);
    return next(error);
  }
};

const comment = async (req, res, next) => {
  const { content, userID, postID } = req.body;

  try {
    const post = await Post.findById(postID);

    if (!post) {
      const error = new HttpError("Post not found", 404);
      return next(error);
    }
    const newComment = {
      content: content,
      postedBy: userID,
    };
    post.comments.push(newComment);

    // Save the updated Post document
    const result = await post.save();
    res.json(result);
  } catch (err) {
    const error = new HttpError("Error making comments " + err, 400);
    return next(error);
  }
};

const listComments = async (req, res, next) => {
  const postId = req.params.pid;

  try {
    const posts = await Post.findById(postId).populate({
      path: "comments1",
      populate: {
        path: "user",
        model: "User",
      },
      options: { sort: { timestamp: -1 } },
    });

    res.json(posts.comments1);
  } catch (err) {
    const error = new HttpError("Error listing comments " + err, 400);
    return next(error);
  }
};

const handleLikePost = async (req, res) => {
  const postId = req.params.pid;
  const userId = req.user.userId;
  const io = req.io;
  try {
    const post = await Post.findById(postId);
    const user = await User.findById(userId);

    if (post.likes.includes(userId)) {
      return res
        .status(400)
        .json({ message: "You have already liked this post" });
    }
    const updatedPost = await Post.findByIdAndUpdate(
      postId,
      { $push: { likes: userId } },
      { new: true }
    ).populate("user", "_id username blockedUsers mutedUsers");

    const like = new UserInteraction({
      user: userId,
      post: postId,
      interactionType: "likes",
    });

    await like.save();

    if (userId !== updatedPost.user._id.toString()) {
      const notificationMessage = `${user.name} liked your post.`;
      await createNotification(io, {
        content: notificationMessage,
        user: updatedPost.user,
        post: updatedPost,
        sender: user,
        type: "like",
      });
    }
    return res.status(200).json(updatedPost);
  } catch (error) {
    console.error("Error liking post:", error);
    return res
      .status(500)
      .json({ message: "An error occurred while liking the post" });
  }
};

// Unlike a post
const unlikePost = async (req, res) => {
  const postId = req.params.pid;
  const userId = req.user.userId;

  try {
    await Post.findByIdAndUpdate(
      postId,
      { $pull: { likes: userId } },
      { new: true }
    );
    await UserInteraction.deleteOne({
      user: userId,
      post: postId,
      interactionType: "likes",
    });
    res.json({ message: "Post unliked successfully" });
  } catch (error) {
    console.error("Error unliking post:", error);
    res
      .status(500)
      .json({ message: "An error occurred while unliking the post" });
  }
};

// Get likes for a post
const getLikesForPost = async (req, res) => {
  const postID = req.params.pid;

  try {
    const likes = await Post.findById(postID).populate("likes", "_id name");
    res.json(likes);
  } catch (error) {
    console.error("Error fetching likes:", error);
    res.status(500).json({ message: "An error occurred while fetching likes" });
  }
};

const search = async (req, res) => {
  try {
    const query = req.query.query;
    const posts = await Post.find({
      content: { $regex: query, $options: "i" },
    })
      .populate("user", "_id name image")
      .sort({
        timestamp: -1,
      });
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const suggestions = async (req, res) => {
  try {
    const query = req.query.query;
    // Implement auto-suggestions logic here
    // Example: You can search for keywords that match the query and return them as suggestions
    const suggestions = await Post.distinct("keywords.content", {
      "keywords.content": new RegExp(query, "i"),
    });
    res.json(suggestions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const getUserPosts = async (req, res) => {
  try {
    const userId = req.params.uid;
    const posts = await Post.find({
      user: userId,
      parentPost: { $exists: false },
    })
      .populate("user", "_id name username avatar")
      .sort({ timestamp: -1 });
    const reposts = await UserInteraction.aggregate([
      {
        $match: {
          user: new ObjectId(userId),
          interactionType: "repost",
        },
      },
      {
        $lookup: {
          from: "posts",
          localField: "post",
          foreignField: "_id",
          as: "repostedPost",
        },
      },
      {
        $unwind: "$repostedPost",
      },
      {
        $lookup: {
          from: "users",
          localField: "repostedPost.user",
          foreignField: "_id",
          as: "repostedUser",
        },
      },
      {
        $unwind: "$repostedUser",
      },
    ]);
    const combinedPosts = [...posts, ...reposts].sort(
      (a, b) => b.timestamp - a.timestamp
    );
    return res.status(200).send(combinedPosts);
  } catch (e) {
    console.log(e);
    return res.status(500).send({ message: "Server error" });
  }
};

const handleRepost = async (req, res) => {
  try {
    const postId = req.params.pid;
    const userId = req.user.userId;
    const io = req.io;

    const post = await Post.findById(postId);
    const user = await User.findById(userId);

    if (!post) {
      return res.status(404).json({ message: "Could not find post" });
    }
    if (!user) {
      return res.status(404).json({ message: "Could not find user" });
    }

    const updatedPost = await Post.findByIdAndUpdate(postId, {
      $push: { retweets: userId },
    }).populate("user", "_id blockedUsers mutedUsers");

    const repost = new UserInteraction({
      user: userId,
      post: postId,
      interactionType: "repost",
    });

    await repost.save();
    if (userId !== updatedPost.user._id.toString()) {
      const notificationMessage = `${user.name} reposted your post.`;
      await createNotification(io, {
        content: notificationMessage,
        user: updatedPost.user,
        post: updatedPost,
        sender: user,
        type: "repost",
      });
    }
    return res.status(200).json(updatedPost);
  } catch (e) {
    console.log(e);
    return res.status(500).json({ message: "Server error" });
  }
};

const handleUnretweetPost = async (req, res) => {
  const postId = req.params.pid;
  const userId = req.user.userId;

  try {
    await Post.findByIdAndUpdate(
      postId,
      { $pull: { retweets: userId } },
      { new: true }
    );
    await UserInteraction.deleteOne({
      user: userId,
      post: postId,
      interactionType: "retweets",
    });
    return res.json({ message: "Post unliked successfully" });
  } catch (e) {
    console.error("error unretweeting post", e);
    return res
      .status(500)
      .json({ message: "An error occurred while unreposting post" });
  }
};

const handlePostComment = async (req, res) => {
  try {
    const postId = req.params.pid;
    const userId = req.user.userId;
    const content = req.body.content;
    const io = req.io;
    let mediaFile;
    let mediaType;
    if (req.file) {
      const { path, mimetype } = req.file;
      mediaFile = getURL(path); // Contains the uploaded file data
      mediaType = mimetype;
    } else {
      // Handle the case when media is not provided
      mediaFile = null;
      mediaType = null;
    }
    let keywords;
    if (content.length > 0) {
      const postData = {
        providers: "openai",
        text: content,
        language: "en",
      };

      const response = await axios.post(endpointUrl, postData, config);
      keywords = response.data.openai.items[0].category;
    }

    const post = await Post.findById(postId);
    const user = await User.findById(userId);
    if (!post || !user) {
      throw new Error("Could not find user or post");
    }

    const newPost = new Post({
      user: userId,
      content,
      media: mediaFile,
      mediaType,
      keywords: {
        content: keywords,
      },
      parentPost: postId,
    });

    const savePost = await newPost.save();
    const updatedPost = await Post.findOneAndUpdate(
      { _id: new ObjectId(postId) },
      {
        $push: { comments1: savePost._id },
      },
      { new: true }
    ).populate("user", "_id blockedUsers mutedUsers");

    await savePost.populate("user");
    console.log("user", user);
    if (userId !== updatedPost.user._id.toString()) {
      const notificationMessage = `${user.name} commented on your post.`;
      await createNotification(io, {
        content: notificationMessage,
        user: updatedPost.user,
        post: savePost,
        sender: user,
        type: "comment",
      });
    }
    return res.status(201).json(savePost);
  } catch (e) {
    console.log("HandlePostComment error", e);
    return res.status(500).json({ message: "Failed to post comment." });
  }
};

const getPost = async (req, res) => {
  try {
    const postId = req.params.pid;
    const post = await Post.findById(postId)
      .populate("user")
      .populate({
        path: "comments1",
        populate: {
          path: "user",
          model: "User",
        },
      });
    if (!post) {
      console.log("Post not found");
      return res.status(404).json({ message: "Could not find post" });
    }
    return res.status(200).json(post);
  } catch (e) {
    console.error("Server error on get post", e);
    return res.status(500).json({ message: "Server error" });
  }
};

const handleDeletePost = async (req, res) => {
  try {
    const postId = req.params.pid;
    const post = await Post.findById(postId);

    if (!post) {
      console.log("Could not find post");
      return res.status(404).json({ message: "Post not found" });
    }

    await Post.deleteOne({ _id: postId });
    return res.status(200).json({ message: "Post deleted successfully" });
  } catch (e) {
    console.log("could not delete post", e);
    return res
      .status(500)
      .json({ message: "Error occurred while deleting post" });
  }
};

const handlePinPost = async (req, res) => {
  try {
    const postId = req.params.pid;

    const post = await Post.findByIdAndUpdate(
      postId,
      { isPinned: true },
      { new: true }
    );

    return res.status(200).json(post);
  } catch (e) {
    console.log("handlepinpost error", e);
    return res.status(500).json({ error: "Error on server" });
  }
};

const handleUnpinPost = async (req, res) => {
  try {
    const postId = req.params.pid;

    const post = await Post.findByIdAndUpdate(
      postId,
      { isPinned: false },
      { new: true }
    );

    return res.status(200).json(post);
  } catch (e) {
    console.log("handleUnpinPost error", e);
    return res.status(500).json({ error: "Error on server" });
  }
};

const handleFollowingFeed = async (req, res) => {
  try {
    const userId = req.user.userId;

    const currentUser = await User.findById(userId);

    const following = [...currentUser.following, userId];

    const blockedUsers = currentUser.blockedUsers;
    const mutedUsers = currentUser.mutedUsers;

    const posts = await Post.find({
      $and: [
        {
          user: { $in: following },
        },
        {
          parentPost: null,
        },
        {
          "user.blockedUsers": { $nin: blockedUsers },
        },
      ],
    })
      .populate("user", "_id name username avatar blockedUsers mutedUsers")
      .sort("-timestamp");

    const filteredPosts = posts.filter((post) => {
      const isBlocked = post.user.blockedUsers.includes(userId);
      const isMuted = post.user.mutedUsers.includes(userId);

      return (isBlocked || isMuted) === false;
    });

    return res.status(200).json(filteredPosts);
  } catch (e) {
    console.error("error message", e);
  }
};

const handleGetPinnedPost = async (req, res) => {
  try {
    const userId = req.params.userId;

    const post = await Post.findOne({
      user: new ObjectId(userId),
      isPinned: true,
    });

    if (!post) {
      return res.status(404).json({ message: "Pinned Post not found" });
    }

    return res.status(200).json(post);
  } catch (e) {
    console.error("error has occurred on fetching pinned post", e);
    return res.status(500).json({ message: "Could not fetch pinned post" });
  }
};

module.exports = {
  handleCreatePost,
  handlePostComment,
  handleFollowingFeed,
  listNewsFeed,
  listComments,
  handleLikePost,
  unlikePost,
  handlePinPost,
  handleRepost,
  handleUnpinPost,
  handleUnretweetPost,
  search,
  getPost,
  getUserPosts,
  getLikesForPost,
  handleDeletePost,
  handleGetPinnedPost,
};
