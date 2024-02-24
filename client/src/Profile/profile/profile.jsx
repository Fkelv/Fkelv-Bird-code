import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { useParams } from "react-router-dom";
import { ToastContainer } from "react-toastify";
import { useGetUserQuery } from "../../store";
import { selectCurrentUser } from "../../store/authSlice";
import { ProfileHeader } from "./profile-header/profile-header";
import { ProfileImages } from "./profile-images/profile-images";
import { ProfilePosts } from "./profile-posts/profile-posts";
import { ProfileReplies } from "./profile-replies/profile-replies";
import { ProfileVideos } from "./profile-videos/profile-videos";

export const Profile = () => {
  const { id } = useParams();
  const { data: userData, isLoading: userLoading } = useGetUserQuery(id);
  const userId = useSelector(selectCurrentUser);
  const { data: currentUserData, isLoading: currentUserLoading } =
    useGetUserQuery(userId, {
      skip: userId === null,
    });

  const blockedStatus = currentUserData?.blockedUsers?.includes(id);
  const mutedStatus = currentUserData?.mutedUsers?.includes(id);
  const isBlocked = userData?.blockedUsers?.includes(userId);
  return (
    <div className="max-w-[700px] mx-auto border-x border-gray-200">
      {userData && (
        <ProfileHeader
          existingUser={userData}
          blockedStatus={blockedStatus}
          mutedStatus={mutedStatus}
        />
      )}
      <div className="bg-w">
        {!userLoading && !currentUserLoading && isBlocked && (
          <BlockedSection username={userData?.username} />
        )}
        {!userLoading && !currentUserLoading && !isBlocked && (
          <PostsSection
            blockedStatus={blockedStatus}
            userId={id}
            username={userData?.username}
          />
        )}
      </div>
      <ToastContainer position="bottom-center" />
    </div>
  );
};

const PostsSection = ({ blockedStatus, userId, username }) => {
  const [hidePosts, setHidePosts] = useState(blockedStatus);

  const [active, setActive] = useState("posts");
  useEffect(() => {
    setHidePosts(blockedStatus);
  }, [blockedStatus]);
  return (
    <>
      {hidePosts ? (
        <div className="w-full h-40 flex justify-center items-center">
          <div className="flex flex-col gap-2 w-[300px]">
            <p className="text-2xl font-bold">@{username} is blocked</p>
            <p className="">Are you sure you want to view these posts?</p>
            <div className="flex">
              <button
                className="py-2 px-6 font-bold text-white bg-blue-500 rounded-full"
                type="button"
                onClick={() => setHidePosts(false)}
              >
                View Posts
              </button>
            </div>
          </div>
        </div>
      ) : (
        <>
          <div className="flex items-center pt-4 px-4 font-medium gap-5 border-b-[0.5px] ">
            {["posts", "replies", "media", "videos"].map((item) => (
              <button
                key={item}
                className={` border-b-4 ${
                  active === item ? "border-blue-500" : "border-white"
                }  pb-[2px]`}
                type="button"
                onClick={() => setActive(item)}
              >
                {item.charAt(0).toUpperCase() + item.slice(1)}
              </button>
            ))}
          </div>
          <>
            {active === "posts" && <ProfilePosts userId={userId} />}
            {active === "replies" && <ProfileReplies userId={userId} />}
            {active === "media" && <ProfileImages userId={userId} />}
            {active === "videos" && <ProfileVideos userId={userId} />}
          </>
        </>
      )}
    </>
  );
};

const BlockedSection = ({ username }) => {
  return (
    <div className="w-full h-40 flex justify-center items-center">
      <div className="flex flex-col gap-2 w-[350px]">
        <p className="text-2xl font-bold">@{username} blocked you</p>
        <p className="">You are blocked from seeing @{username}'s posts.</p>
      </div>
    </div>
  );
};
