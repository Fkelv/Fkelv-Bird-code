import { Link } from "react-router-dom";
import { getTimeAgo } from "../../../libraries/getTimeAgo";

export const VideoPreview = ({ video }) => {
  const { _id, user, views, title, uploadDate } = video;
  const avatarURL = user.avatar
    ? `${import.meta.env.VITE_API_URL}/${user.avatar}`
    : "/assets/blank-profile-picture.png";

  const thumbnailURL = `${import.meta.env.VITE_API_URL}/${video.thumbnailURL}`;

  const uploadTimeAgo = getTimeAgo(uploadDate);
  return (
    <Link to={`/watch/${_id}`} className="flex gap-3 flex-col">
      <div className="h-[193px] w-full">
        <img
          className="rounded-md object-cover h-full w-full"
          src={thumbnailURL}
          alt="sea"
        />
      </div>
      <div className="flex items-start gap-3">
        <div className="h-10 w-10 overflow-hidden">
          <img
            className="w-full h-full object-cover rounded-full"
            src={avatarURL}
            alt="user"
          />
        </div>
        <div>
          <h2 className="text-lg roboto leading-5 font-semibold">{title}</h2>
          <h3 className="text-[14px] roboto mt-[3px] font-medium text-gray-700">
            {user.name}
          </h3>
          <p className="text-[13px] roboto font-medium text-gray-700">
            {views} views · {uploadTimeAgo}
          </p>
        </div>
      </div>
    </Link>
  );
};
