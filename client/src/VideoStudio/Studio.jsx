/* eslint-disable react/prop-types */
/* eslint-disable no-unused-vars */
import React from "react";
import { Link, Navigate, useLocation, Outlet } from "react-router-dom";
import { AiOutlineCloudUpload } from "react-icons/ai";
import { BsBarChart } from "react-icons/bs";
import { MdContentPaste, MdMonitor } from "react-icons/md";
import { CgMediaLive } from "react-icons/cg";
import { CiStreamOn } from "react-icons/ci";

export const Studio = () => {
  const location = useLocation();
  const studioItems = [
    { path: "go-live", title: "Go Live", icon: <CgMediaLive fontSize={23} /> },
    {
      path: "upload-video",
      title: "Upload Video",
      icon: <AiOutlineCloudUpload fontSize={23} />,
    },
    {
      path: "analytics",
      title: "Analytics",
      icon: <BsBarChart fontSize={23} />,
    },
    {
      path: "monetization",
      title: "Monetized Content",
      icon: <MdMonitor fontSize={23} />,
    },
  ];

  return (
    <div
      className={`${
        location.pathname === "/studio/stream-manager" &&
        "bg-[#161616] min-h-[calc(100vh_-_76px)]"
      }`}
    >
      <div className="max-w-[1340px] mx-auto flex items-start">
        <div className="py-9 pl-9 basis-[300px]">
          <Link
            to="/studio/content"
            className={`flex items-center gap-3 py-2 px-3 mb-1 rounded-sm cursor-pointer hover:bg-gray-50 ${
              location.pathname === "/studio/content" ? "bg-gray-100" : ""
            } ${
              location.pathname === "/studio/stream-manager"
                ? "text-white hover:bg-g"
                : ""
            }`}
          >
            <div>
              <MdContentPaste fontSize={23} />
            </div>
            Content
          </Link>
          <Link
            to="/studio/stream-manager"
            className={`flex items-center gap-3 py-2 px-3 mb-1 rounded-sm cursor-pointer hover:bg-gray-50 ${
              location.pathname === "/studio/stream-manager"
                ? "bg-[#1f1f1f] hover:bg-g text-white"
                : ""
            }`}
          >
            <div>
              <CiStreamOn fontSize={23} />
            </div>
            Stream Manager
          </Link>
          {studioItems.map((item) => (
            <Link
              to={`/studio/${item.path}`}
              key={item.path}
              className={`flex items-center gap-3 py-2 px-3 mb-1 rounded-sm cursor-pointer hover:bg-gray-50 ${
                location.pathname === `/studio/${item.path}`
                  ? "bg-gray-100"
                  : ""
              } ${
                location.pathname === "/studio/stream-manager"
                  ? "text-white hover:bg-g"
                  : ""
              }`}
            >
              <div>{item.icon}</div>
              {item.title}
            </Link>
          ))}
        </div>
        <div className="flex-1 p-9">
          <Outlet />
        </div>
      </div>
    </div>
  );
};
