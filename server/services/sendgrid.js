const sendgrid = require("@sendgrid/mail");

sendgrid.setApiKey(process.env.SENDGRID_API_KEY);

const EmailType = {
  PasswordReset: "PasswordReset",
  EmailConfirmation: "EmailConfirmation",
};

const passwordResetTemplateId = "d-2d1d4dbe6e984fc596d0b1709bc50f5a";
const emailConfirmationTemplateId = "";

const templateById = {
  [EmailType.PasswordReset]: passwordResetTemplateId,
  [EmailType.EmailConfirmation]: emailConfirmationTemplateId,
};

const generatePasswordResetPayload = (resetToken, username) => {
  return {
    link: `${process.env.FRONTEND_URL}/auth/password/reset/${resetToken}`,
    username,
  };
};

const generateEmailConfirmationPayload = (confirmToken, username) => {
  return {
    link: `${process.env.FRONTEND_URL}/auth/email/confirm/${confirmToken}`,
    username,
  };
};

const sendMail = async (type, ...messages) => {
  const sender = process.env.SENDGRID_SENDER_EMAIL;
  const templateId = templateById[type];
  const message = {
    from: sender,
    templateId,
    personalizations: messages,
  };
  try {
    console.log("About to send mail");
    await sendgrid.send(message);
  } catch (err) {
    console.log("Sending mail error", err);
    throw new Error("An error occurred while sending mail");
  }
};

module.exports = {
  generateEmailConfirmationPayload,
  generatePasswordResetPayload,
  sendMail,
  EmailType,
};
