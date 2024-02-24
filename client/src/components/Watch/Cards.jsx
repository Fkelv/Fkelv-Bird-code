/* eslint-disable react/no-array-index-key */
import React from "react";
import videos from "../../constant/videos";
import Card from "./Card";
import { FollowingVideos } from "./following-videos/following-videos";

export default function Cards() {
  return (
    <div className="px-6">
      {["Recommended for you", "News", "Trending", "Followed"].map(
        (item, i) => (
          <div className="mb-10" key={i}>
            <h1 className="mb-3 font-bold text-xl malgun">{item}</h1>
            <div className="grid grid-cols-4 gap-4">
              {videos.map((video) => (
                <Card video={video} key={video.id} />
              ))}
            </div>
          </div>
        )
      )}
      <div className="flex flex-col gap-2">
        <h2 className="font-bold text-xl">Following</h2>
        <FollowingVideos />
      </div>
    </div>
  );
}
