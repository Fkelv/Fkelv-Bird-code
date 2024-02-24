import React, { useRef, useState } from "react";
import videoFile from "../../../assets/video.mp4";
import { FaPlay } from "../../../constant/icons";

export function VideoPlayer() {
  const videoRef = useRef(null);
  const [hideThumbnail, setHideThumbnail] = useState(false);
  const handleClick = () => {
    videoRef.current.play();
    setHideThumbnail(true);
  };
  return (
    <div className="relative overflow-hidden">
      <video ref={videoRef} width="100%" controls>
        <track kind="captions" />
        <source src={videoFile} type="video/mp4" />
      </video>
    </div>
  );
}
