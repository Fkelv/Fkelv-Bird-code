import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useGetUserQuery, useReadNotificationMutation } from "../../../store";
import { getTimeAgo } from "../../../libraries/getTimeAgo";

const notificationType = {
  repost: "reposted your post.",
  like: "liked your post.",
  comment: "commented on your post.",
  follow: "followed you.",
};
export default function Notification({ notification }) {
  const { _id, sender, post, type, timestamp } = notification;
  const navigate = useNavigate();
  const { data: userData } = useGetUserQuery(sender, {
    skip: sender === undefined,
  });

  const [readNotification, {}] = useReadNotificationMutation();
  const avatar = userData?.avatar
    ? `${import.meta.env.VITE_API_URL}/${userData?.avatar}`
    : "/assets/avatar.png";

  const link = post ? `/posts/${post}` : `/users/${sender}`;

  const handleClick = async () => {
    await readNotification(_id);
    navigate(link);
  };

  return (
    <div className="w-max max-w-full rounded-sm hover:bg-gray-50 pb-2 pt-4 px-6 border-b">
      <div className="text-black text-lg flex items-center gap-2">
        <div className="flex items-start">
          <div className="min-w-[50px]">
            <div className="h-10 w-10 overflow-hidden">
              <img
                className="w-full h-full object-cover rounded-full"
                src={avatar}
                alt="user"
              />
            </div>
          </div>
          <div>
            <p className="text-[17px] leading-[20px]">
              <Link to={`/users/${sender}`} className="font-medium">
                {userData?.name}
              </Link>
              <button onClick={handleClick}>
                &nbsp;{notificationType[type]}
              </button>
            </p>
            <p className="text-[13px] font-medium text-gray-500 -mt-[2px]">
              {getTimeAgo(timestamp)}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
