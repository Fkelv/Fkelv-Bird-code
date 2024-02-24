const ffmpeg = require("fluent-ffmpeg");
const streamifier = require("streamifier");
const ffmpegInstaller = require("@ffmpeg-installer/ffmpeg");
const { getVideoDurationInSeconds } = require("get-video-duration");
const { resolve } = require("path");

const videoDurationLimit = (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({ error: "No video file uploaded." });
  }
  console.log("dir", __dirname, __filename);
  const outputPath = resolve(__dirname, "../uploads/videos/output.mp4");
  const videoBuffer = req.file.buffer;
  const readableStream = streamifier.createReadStream(videoBuffer);
  ffmpeg()
    .input(readableStream)
    .setFfmpegPath(ffmpegInstaller.path)
    .output(outputPath)
    .ffprobe((err, data) => {
      if (err) {
        console.error("Error getting video information:", err);
        return res.status(500).json({ error: "Internal Server Error." });
      }
      const durationInSeconds = data.format.duration;

      // Check if the duration exceeds the limit (5 seconds in this example)
      if (durationInSeconds > 5) {
        return res
          .status(400)
          .json({ error: "Video duration exceeds the limit of 5 seconds." });
      }
      next();
    });
  // .on("end", function () {
  //   // Get the duration in seconds
  //   const durationInSeconds = this.ffprobeData.format.duration;

  //   // Check if the duration exceeds the limit (2 minutes = 120 seconds)
  //   if (durationInSeconds > 5) {
  //     return res
  //       .status(400)
  //       .json({ error: "Video duration exceeds the limit of 2 minutes." });
  //   }

  //   // Continue with the next middleware or route handler
  //   next();
  // })
  // .on("error", function (err) {
  //   console.error("Error getting video duration:", err);
  //   return res.status(500).json({ error: "Internal Server Error." });
  // })
  // .run();
};

module.exports = {
  videoDurationLimit,
};
