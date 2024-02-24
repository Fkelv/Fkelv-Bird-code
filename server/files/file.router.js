const { Router } = require("express");

const { checkSignature } = require("../middleware/authentication.middleware");
const { fileUpload } = require("../middleware/file-upload");
const { handleFileUpload } = require("./file.controller");

const router = Router();

router.post(
  "/upload",
  checkSignature,
  fileUpload.array("files", 10),
  handleFileUpload
);

module.exports = router;
