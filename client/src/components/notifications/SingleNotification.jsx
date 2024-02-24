import React, { useState } from "react";
import { Link } from "react-router-dom";
import DotsOptions from "./DotsOptions";
import { useGetUserQuery } from "../../store";
import { getTimeAgo } from "../../libraries/getTimeAgo";

const notificationType = {
  repost: "reposted your post.",
  like: "liked your post.",
  comment: "commented on your post.",
  follow: "followed you.",
};

export const SingleNotification = ({ notification }) => {
  const { sender, post } = notification;

  const { data: userData } = useGetUserQuery(notification.sender);

  const avatar = userData?.avatar
    ? `${import.meta.env.VITE_API_URL}/${userData?.avatar}`
    : "/assets/avatar.png";
  const link = post ? `/posts/${post}` : `/users/${sender}`;

  return (
    <div className="rounded-sm hover:bg-gray-50 pb-2 group pt-4 px-2 border-b">
      <div className="text-black text-lg flex items-center gap-2">
        <div className="flex items-start gap-2">
          <Link to={`/users/${sender}`} className="min-w-[50px]">
            <div className="h-10 w-10 overflow-hidden">
              <img
                className="h-full w-full object-cover rounded-full"
                src={avatar || "/assets/avatar.png"}
                alt="user"
              />
            </div>
          </Link>
          <div>
            <p className="text-base">
              <Link
                to={`/users/${sender}`}
                className="font-medium hover:underline"
              >
                {userData?.name}
              </Link>
              &nbsp;
              <Link to={link} className="hover:underline">
                {notificationType[notification?.type]}
              </Link>
            </p>
            <p className="text-[12.5px] text-g text-opacity-70 font-medium -mt-[8px]">
              {getTimeAgo(notification?.timestamp)}
            </p>
          </div>
        </div>
        <DotsOptions notifId={notification?._id} />
      </div>
    </div>
  );
};
