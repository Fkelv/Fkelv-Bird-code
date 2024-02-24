const getURL = (full) => {
  const parts = full.split("/");
  return parts.slice(parts.length - 2).join("/");
};

const handleFileUpload = (req, res) => {
  const files = req.files;

  if (!files) {
    console.error("Error while uploading the file");

    return res.status(500).send({ message: "Unable to upload files" });
  }
  const documentURLs = files.map((file) => ({
    url: getURL(file.path),
    name: file.originalname,
  }));

  if (documentURLs.length === 0) {
    console.error("Error ocurred while upload files. No document URLs found.");

    return res
      .status(500)
      .send({ message: "Unable to upload files. Try again later" });
  }
  try {
    return res.status(200).send({ files: documentURLs });
  } catch (error) {
    console.error("%o", error);
    return res
      .status(500)
      .send({ message: "Unable to upload files. Try again later" });
  }
};

module.exports = {
  handleFileUpload,
};
