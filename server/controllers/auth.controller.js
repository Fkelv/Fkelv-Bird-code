const bcrypt = require("bcrypt");
const { validationResult } = require("express-validator");
const User = require("../models/user");
const HttpError = require("../models/http-error");
const tokenUtil = require("../util/token");
const sendgridService = require("../services/sendgrid");
const usernameUtil = require("../util/generateUsername");

// Constants
const AUTHORIZATION_HEADER_NAME = "Authorization";
const REFRESH_TOKEN_HEADER_NAME = "Refresh-Token";
const ACCESS_LEVELS = { ADMIN: 0, USER: 1, GUEST: 2 };

// Helper Functions
const setAuthorizationHeaders = (res, userId) => {
  console.log('Set auth ' , {userId});
  const { refreshToken, accessToken } = tokenUtil.generateAuthTokens({ userId });
  res.setHeader(AUTHORIZATION_HEADER_NAME, `Bearer ${accessToken}`);
  res.setHeader(REFRESH_TOKEN_HEADER_NAME, refreshToken);
};

const handleValidationErrors = (req, next) => {
  
  

  const errors = validationResult(req);
  
  
  if (!errors.isEmpty()) {
    throw new HttpError("Invalid input passed", 422);
  }
};


const signup = async (req, res, next) => {
  try {
    handleValidationErrors(req);

    const { fullName, email, password } = req.body;
    console.log({email})
    
    const existingUser = await User.findOne({ email });
    
    
    
    
    if (existingUser) {
      throw new HttpError("User already exists", 422);
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    console.log({hashedPassword})
    
    const defaultUsername = await usernameUtil.generateUniqueUsername(fullName);

    console.log(defaultUsername)

  let newUserDetails = new User({
    name: fullName,
    email: email,
    contact: null,
    username: defaultUsername,
    password: hashedPassword,
    places: [],
    bookmarks: [],
    verificationDetails: {
      website: null,
      document: null,
      officialEmail: null,
      newsArticles: [],
      googleTrendsProfile: null, 
      wikipediaLink: null,
      instagramLink: null,
    },
    verified: false,
    followers: [],
    following: [],
    lastLogin: new Date(),
    customerId: null,
    planId: null,
    subscriptionId: null,
    paymentMethods: [],
    mutedUsers: [],
    blockedUsers: [],
    reportedUsers: [],
    accessRight: ACCESS_LEVELS.USER,
  });

  console.log(newUserDetails)
  const newUser = new User(newUserDetails);

  await newUser.save();

  console.log(newUser);

    setAuthorizationHeaders(res, { userId: newUser._id.toHexString() });
    res.status(201).json(newUser);
  } catch (error) {
    // Ensure error is an instance of HttpError before passing it to next
    if (!(error instanceof HttpError)) {
      error = new HttpError("Signing up failed, please try again later.", 500);
    }
    next(error);
  }
};

const signin = async (req, res, next) => {
  try {
    // Check for input validation errors
    handleValidationErrors(req);

    const { email, password } = req.body;
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      throw new HttpError("Invalid credentials, could not log you in.", 403);
    }

    // Check if password matches
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw new HttpError("Invalid credentials, could not log you in.", 403);
    }

    // Set authorization headers and log user in
    setAuthorizationHeaders(res, { userId: user._id.toHexString() });
    
    res.status(200).json(user); // Changed send to json for consistency
  } catch (error) {
    // Handle known and unknown errors uniformly
    next(error instanceof HttpError ? error : new HttpError("Logging in failed, please try again later.", 500));
  }
};

const handleRefreshToken = async (req, res) => {
  try {
    const oldRefreshToken = req.header(REFRESH_TOKEN_HEADER_NAME);
    const decodedToken = tokenUtil.verifyToken(oldRefreshToken);
    console.log({decodedToken})
    setAuthorizationHeaders(res, { userId: decodedToken.userId });
console.log(decodedToken.userId)
    return res.status(200).send({ userId: decodedToken.userId });
  } catch (e) {
    if (e instanceof Error) {
      console.error("HandleRefreshToken:", e.message);
    }
    if (e instanceof tokenUtil.InvalidTokenError) {
      return res
        .status(401)
        .send({ message: "The refresh token provided was invalid" });
    } else {
      return res.status(500).send({
        message: "An error ocurred while trying to refresh the access token",
      });
    }
  }
};

const handleForgetPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty) { 
      return res.status(400).send({ message: "invalid input passed" });
    }
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      console.error("HandleForgetPassword: email not found");
      return res
        .status(404)
        .send({ message: "The email provided does not have an account" });
    }
    const resetToken = generateResetToken({ userId: user._id.toHexString() });

    const payload = generatePasswordResetPayload(
      resetToken,
      user.name.split(" ")[0]
    );

    await sendMail(EmailType.PasswordReset, {
      to: email,
      dynamicTemplateData: payload,
    });

    return res.status(200).send({ message: "Reset Password mail sent" });
  } catch (e) {
    return res.status(500).send({ message: "Token has expired" });
  }
};

const handleResetPassword = async (req, res) => {
  try {
    const token = req.params.token;
    const { password } = req.body;

    const decodedToken = verifyToken(token);
    const user = await User.findById(decodedToken.userId);

    if (!user) {
      return res.status(404).send({ message: "could not find user" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    user.password = hashedPassword;

    await user.save();
    res.status(200).send({ message: "Password reset successful" });
  } catch (err) {
    console.log("reset password error", err);
    return res.status(401).send({ message: "Token has expired" });
  }
};

module.exports = {
  setAuthorizationHeaders,
  signup,
  signin,
  handleRefreshToken,
  handleForgetPassword,
  handleResetPassword,
};
