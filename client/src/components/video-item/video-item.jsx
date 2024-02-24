import { useState } from "react";
import { DotsOptions } from "../../newsfeed/DotsOptions";
import { FiMoreHorizontal } from "react-icons/fi";
import { Link } from "react-router-dom";
import { getTimeAgo } from "../../libraries/getTimeAgo";

export const VideoItem = ({ video }) => {
  const { _id, description, user, uploadDate, views, title } = video;

  const [showMore, setShowMore] = useState(false);

  const handleMore = () => {
    setShowMore(() => !showMore);
  };

  const avatarURL = user.avatar
    ? `${import.meta.env.VITE_API_URL}/${user.avatar}`
    : "/assets/blank-profile-picture.png";

  const videoURL = `${import.meta.env.VITE_API_URL}/${video.videoURL}`;
  const uploadTimeAgo = getTimeAgo(uploadDate);
  return (
    <div>
      <div className="flex relative justify-end">
        <div
          className="p-2 hover:bg-gray-100 rounded-full"
          onClick={handleMore}
        >
          <FiMoreHorizontal fontSize={23} />
        </div>
        {/* <DotsOptions showMore={showMore}  /> */}
      </div>
      <Link to={`/watch/${_id}`} className="p-2 gap-2 flex flex-col">
        <video
          controls
          height="100%"
          width="100%"
          className="rounded-2xl"
          src={videoURL}
        />
        <div className="flex justify-between p-px">
          <div className="flex flex-col gap-px">
            <Link to={`/watch/${_id}`} className="text-xl font-bold">
              {title}
            </Link>
            <p>{uploadTimeAgo}</p>
          </div>
          <div className="flex flex-col">
            <p>{views} views</p>
          </div>
        </div>
      </Link>
    </div>
  );
};
