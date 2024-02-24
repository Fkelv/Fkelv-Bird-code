/* eslint-disable no-undef */
/* eslint-disable react/prop-types */
/* eslint-disable no-nested-ternary */
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { FiMoreHorizontal } from "../constant/icons";
import CommentField from "../components/comments/CommentField";
import { DotsOptions } from "./DotsOptions";
import { ReactionIcons } from "./ReactionIcons";
import { useSelector } from "react-redux";
import { selectCurrentUser } from "../store/authSlice";
import { getTimeAgo } from "../libraries/getTimeAgo";

export const SinglePost = ({ post, refetch, isParent, children }) => {
  const userId = useSelector(selectCurrentUser);

  const [showPopUp, setShowPopUp] = useState(false);
  const [showMore, setShowMore] = useState(false);
  const [showCommentInput, setShowCommentInput] = useState(false);

  const handleMore = () => {
    setShowMore(() => !showMore);
    setShowPopUp(false);
  };
  const handlePopup = () => {
    setShowPopUp(() => !showPopUp);
    setShowMore(false);
  };

  const handleCommentClick = () => {
    setShowCommentInput(!showCommentInput); // Toggle comment input visibility
    setShowMore(false); // Close more options when clicking comment
  };

  const closeDotPopups = () => {
    setShowMore(false);
  };
  const avatarURL = post?.user?.avatar
    ? `${import.meta.env.VITE_API_URL}/${post?.user?.avatar}`
    : "/assets/blank-profile-picture.png";
  const isBlocked = post?.user?.blockedUsers?.includes(userId);
  if (isBlocked) {
    return (
      <div className="flex px-5 py-4 border-b-[0.5px]">
        <p className="bg-gray-300 px-4 py-2 w-full rounded-md">
          You are blocked by this user.
        </p>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      {children}
      <div
        className={`flex items-stretch p-2 gap-2 ${
          isParent ? "" : "border-b-[0.5px]"
        } border-gray-300`}
      >
        <div className="basis-[10%] flex flex-col items-stretch grow-0">
          <Link
            to={`/users/${post.user.name}`}
            className="flex justify-center grow-0"
          >
            <div className="h-10 w-10 overflow-hidden">
              <img
                src={avatarURL}
                alt={post.user.name}
                className="h-full w-full rounded-full object-cover"
              />
            </div>
          </Link>
          {isParent && (
            <div className="flex flex grow-1 h-full justify-center">
              <div className="w-0.5 h-[130%] bg-gray-200"></div>
            </div>
          )}
        </div>
        <div className="basis-[90%] flex grow-1 flex-col gap-px">
          <div className="flex items-center justify-between">
            {/* name and username */}
            <Link
              to={`/users/${post.user._id}`}
              className="flex items-center gap-1"
            >
              <span className="font-bold text-base hover:underline">
                {post.user.name}
              </span>
              <span className="text-gray-500 text-base">
                @{post.user.username}
              </span>
              <span className="text-gray-500 text-base"> · </span>
              <span className="text-gray-500 text-base">
                {getTimeAgo(post.timestamp)}
              </span>
            </Link>

            <div className="flex mt-[-10px] items-center gap-2 group relative cursor-pointer">
              <div
                className="ml-auto p-2 hover:bg-gray-100 grid place-content-center rounded-full"
                onClick={handleMore}
              >
                <FiMoreHorizontal fontSize={23} />
              </div>
              <DotsOptions
                showMore={showMore}
                isOwner={userId === post.user._id}
                username={post.user.username}
                postId={post._id}
                closePopup={closeDotPopups}
                refetch={refetch}
              />
            </div>
          </div>
          <Link to={`/posts/${post._id}`}>
            <p className="text-gray-900 w-full">{post.content}</p>
            {post?.mediaType === "image/jpeg" && (
              <div className="rounded-3xl overflow-hidden mt-3 w-full">
                <img
                  src={`${import.meta.env.VITE_API_URL}/${post.media[0]}`}
                  alt=""
                  className="w-full h-auto"
                />
              </div>
            )}

            {post?.mediaType === "video/mp4" && (
              <div className="w-full">
                <video
                  width="100%"
                  height="100%"
                  className="rounded-md"
                  controls
                >
                  <source
                    src={`${import.meta.env.VITE_API_URL}/${post.media[0]}`}
                    type="video/mp4"
                  />
                </video>
              </div>
            )}

            {/* {post?.media && post?.media?.length !== 0 ? (
              <div className="w-full">
                <img
                  src={`${import.meta.env.VITE_API_URL}/${post.media[0]}`}
                  alt=""
                  className="w-full h-auto rounded-lg "
                />
              </div>
            ): } */}
          </Link>
          <ReactionIcons
            handlePopup={handlePopup}
            handleCommentClick={handleCommentClick}
            post={post}
            showPopUp={showPopUp}
            refetch={refetch}
          />
          {/* comment input box */}
          {showCommentInput && <CommentField postId={post._id} />}
        </div>
      </div>
    </div>
  );
};
