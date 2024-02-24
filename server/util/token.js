const jwt = require("jsonwebtoken");
const REFRESH_TOKEN_DURATION = "30d";
const ACCESS_TOKEN_DURATION = "15min";
const RESET_TOKEN_DURATION = "1h";

const TOKEN_TYPE = {
  Auth: "auth",
  Reset: "reset",
  EmailConfirmation: "email_confirmation",
};

const generateAuthTokens = (tokenBody) => {
  try {
    console.log({tokenBody})
    const payload = { ...tokenBody, type: TOKEN_TYPE.Auth };
    const refreshToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: REFRESH_TOKEN_DURATION,
    });
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: ACCESS_TOKEN_DURATION,
    });

    console.log("Generated tokens for user ", tokenBody.userId);
    return { refreshToken, accessToken };
  } catch (e) {
    if (e instanceof Error) {
      console.log("Generated tokens error", e.message);
      throw new TokenGenerationError();
    }
  }
};

const verifyToken = (serializedToken) => {
  try {
    console.log({serializedToken});
    const token = jwt.verify(serializedToken, process.env.JWT_SECRET);
    
    console.log("Successfully verified token for user ", token.userId.userId.userId);
    return {userId : token.userId.userId.userId};
  } catch (e) {
    if (e instanceof Error) {
      throw new InvalidTokenError(serializedToken);
    } else {
      throw new Error("Unexpected Error");
    }
  }
};

const generateResetToken = (tokenBody) => {
  try {
    const payload = { ...tokenBody, type: TOKEN_TYPE.Reset };
    const resetToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: RESET_TOKEN_DURATION,
    });
    console.log("generated reset token for user ", tokenBody.userId);
    return resetToken;
  } catch (e) {
    if (e instanceof Error) {
      console.error("Generate token error: ", e.message);
      throw new TokenGenerationError();
    } else {
      throw new Error("unexpected error");
    }
  }
};

class TokenGenerationError extends Error {
  constructor() {
    super("An error ocurred while generating the access and refresh tokens");
    Object.setPrototypeOf(this, TokenGenerationError.prototype);
  }
}

class InvalidTokenError extends Error {
  constructor(token) {
    super(`The provided token is invalid. Provided ${token}`);
    Object.setPrototypeOf(this, InvalidTokenError.prototype);
  }
}

module.exports = {
  generateAuthTokens,
  generateResetToken,
  verifyToken,
  InvalidTokenError,
};
