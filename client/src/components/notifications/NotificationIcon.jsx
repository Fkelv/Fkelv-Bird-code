import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { FiSettings, MdOutlineNotifications } from "../../constant/icons";
import Notification from "./DropDown/Notification";
import { useGetUnreadNotificationsQuery } from "../../store";
import { useSocket } from "../../hooks/useSocket";

export const NotificationIcon = ({ watchPage, userId }) => {
  const [dropDown, setDropDown] = useState(false);
  const { data, refetch } = useGetUnreadNotificationsQuery();

  const handleClick = () => {
    setDropDown(() => !dropDown);
  };
  const socket = useSocket(userId);
  useEffect(() => {
    if (socket) {
      socket.on("notification", (data) => {
        console.log("dta", data);
        if (data === "new") {
          refetch();
        }
      });
    }
  }, [socket]);
  const displayedNotifications = data?.slice(0, 5);
  return (
    <div
      className={`p-2 rounded-full cursor-pointer relative mr-[2px] ${
        watchPage ? "text-white" : "hover:bg-gray-100"
      }`}
      onClick={handleClick}
    >
      <MdOutlineNotifications fontSize={27} />
      {data?.length > 0 && (
        <span className="absolute w-4 h-4 top-[8px] right-[6px] bg-red-500 rounded-full text-[10px] font-semibold grid place-content-center text-white">
          {data?.length}
        </span>
      )}
      <div
        className={`absolute top-[109%] min-w-[300px] max-w-[400px] hover:scale-100 right-0 ${
          dropDown ? "flex opacity-100 z-20" : "hidden opacity-0"
        } flex-col  bg-white shadow-sm shadow-gray-300 opacity-1`}
      >
        <div
          className={`py-3 px-6 flex items-center justify-between cursor-default border-b ${
            watchPage ? "text-black" : ""
          }`}
        >
          <p className="font-semibold text-lg">Notifications</p>
          <FiSettings fontSize={21} className="cursor-pointer hover:rotate-6" />
        </div>
        {displayedNotifications?.length === 0 && (
          <div className="w-full h-28 flex justify-center items-center">
            <p>You've already caught up!</p>
          </div>
        )}
        {displayedNotifications?.map((item) => (
          <Notification notification={item} key={item?._id} />
        ))}
        <div className="pb-4 pt-3 px-6 border-t cursor-default">
          <Link
            to="notifications"
            className="text-blue-600 hover:text-blue-500 cursor-pointer"
          >
            View all notifications
          </Link>
        </div>
      </div>
    </div>
  );
};
