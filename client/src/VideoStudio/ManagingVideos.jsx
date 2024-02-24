import React, { useState } from "react";
import { useSelector } from "react-redux";
import { useGetUserVideosQuery } from "../store";
import "./managingVideos.css";
import TableBodyRow from "./TableBodyRow";
import { selectCurrentUser } from "../store/authSlice";
import { VideoRow } from "./video-row/video-row";

export const ManagingVideos = () => {
  const [active, setActive] = useState("Videos");
  const userId = useSelector(selectCurrentUser);
  const { data, isLoading } = useGetUserVideosQuery(userId, {
    skip: userId === null,
  });
  console.log("data", data);
  return (
    <>
      <div
        className={`${
          location.pathname === "/studio/stream-manager" &&
          "bg-[#161616] min-h-[calc(100vh_-_76px)]"
        }`}
      >
        <div className="max-w-[1340px] mx-auto flex items-start flex-col">
          <div className="flex items-center gap-6 px-[10px] mb-3 border-bottom font-bold">
            <div
              className={`cursor-pointer border-b-4 py-2 ${
                active === "Videos" ? "border-black" : "border-[#ffffff00]"
              }`}
              onClick={() => setActive("Videos")}
            >
              Videos
            </div>
            <div
              className={`border-b-4 cursor-pointer py-2 ${
                active === "Playlists" ? "border-black" : "border-[#ffffff00]"
              }`}
              onClick={() => setActive("Playlists")}
            >
              Playlists
            </div>
          </div>
          {active === "Videos" && (
            <table className="table-auto w-full">
              <thead>
                <tr>
                  <th>Video</th>
                  <th>Visibility</th>
                  <th>Upload Date</th>
                  <th>Views</th>
                  <th>Comments</th>
                  <th>Likes</th>
                  <th>DisLikes</th>
                </tr>
              </thead>
              <tbody>
                {!isLoading && (
                  <>
                    {data.map((item) => (
                      <VideoRow video={item} />
                    ))}
                  </>
                )}
              </tbody>
            </table>
          )}
          {active === "Playlists" && (
            <table className="table-auto w-full">
              <thead>
                <tr>
                  <th>Playlist</th>
                  <th>Visibility</th>
                  <th>Last Updated</th>
                  <th>Video count</th>
                </tr>
              </thead>
              <tbody>
                <TableBodyRow playlists />
                <TableBodyRow playlists />
                <TableBodyRow playlists />
                <TableBodyRow playlists />
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
};
