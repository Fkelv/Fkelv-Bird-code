const express = require("express");
const { check } = require("express-validator");

const authController = require("../controllers/auth.controller");

const router = express.Router();

router.post(
  "/signin",
  [
    check("email").isEmail().normalizeEmail(),
    check("password").isLength({ min: 6 }),
  ],
  authController.signin
);

router.post(
  "/signup",
  [
    check("fullName").trim().escape(),
    check("email").isEmail().normalizeEmail(),
    check("password").isLength({ min: 6 }),
  ],
  authController.signup
);
router.post(
  "/password/forget",
  [check("email").isEmail().normalizeEmail()],
  authController.handleForgetPassword
);

router.post(
  "/password/reset/:token",
  [check("password").isLength({ min: 6 })],
  authController.handleResetPassword
);

router.get("/refresh", authController.handleRefreshToken);

module.exports = router;
