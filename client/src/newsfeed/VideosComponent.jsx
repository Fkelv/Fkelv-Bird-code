import React, { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { FiMoreHorizontal } from "../constant/icons";
import CommentField from "../components/comments/CommentField";
import { DotsOptions } from "./DotsOptions";

export const VideosComponent = ({ videoProp, singlePage }) => {
  const { _id, description, videoURL, views, time, userName } = videoProp;
  const [showMore, setShowMore] = useState(false);

  const handleMore = () => {
    setShowMore(() => !showMore);
  };

  const videoRef = useRef(null);
  

  return (
    <div className="video mt-10">
      {videoURL && (
        <>
          <div className="">
            <div className="flex items-center justify-between">
              {/* name and username */}
              <Link
                to={`/users/${videoProp.user}`}
                className="flex items-start -mt-[2px] mb-1 leading-3 flex-col"
              >
                <img
                  src={`http://localhost:8000/api/videos/${videoProp.avatar}`}
                  alt="n"
                  className="h-12 w-12 rounded-full"
                />
                <div>
                  {/* <h2 className="font-bold text-lg hover:underline"></h2> */}
                  <p className="text-gray-500 text-sm mt-[-4px]">
                    {userName}
                    <span> · </span>
                    {time}
                  </p>
                </div>
              </Link>

              <div className="flex mt-[-10px] items-center gap-2 group relative cursor-pointer">
                <div
                  className="ml-auto p-2 hover:bg-gray-100 grid place-content-center rounded-full"
                  onClick={handleMore}
                >
                  <FiMoreHorizontal fontSize={23} />
                </div>
                <DotsOptions showMore={showMore} existingUser={""} />
              </div>
            </div>

            <Link to={`/watch/${_id}`}>
              <video
                controls
                ref={videoRef}
                height="100%"
                width="100%"
                className="rounded-2xl"
                src={`http://localhost:8000/api/videos/${videoURL}`}
              >
                <track kind="captions" />
              </video>
              <div className="flex items-start video-section">
                <h3 className="font-bold text-xl basis-4/5">{description}</h3>
                <span className="text-black text-sm mr-1 mt-1">
                  {views} Views
                </span>
              </div>
            </Link>
          </div>

          {/* comment input box */}
          {singlePage && <CommentField />}
        </>
      )}
    </div>
  );
};
