import React, { useState } from "react";
import { FiMoreHorizontal } from "react-icons/fi";
import { useSelector } from "react-redux";
import { Link, useParams } from "react-router-dom";
import { PostComments } from "../components/comments/post-comments";
import { Loader } from "../components/ui/Loader";
import { DotsOptions } from "../newsfeed/DotsOptions";
import { ReactionIcons } from "../newsfeed/ReactionIcons";
import { useGetPostQuery } from "../store";
import { selectCurrentUser } from "../store/authSlice";

export default function SinglePostView() {
  const userId = useSelector(selectCurrentUser);
  const { id } = useParams();
  const { data, isLoading, isSuccess, refetch } = useGetPostQuery(id);

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
  const timeString = new Date(data?.timestamp).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "numeric",
    hour12: true,
  });
  const dateString = new Date(data?.timestamp).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

  const avatar = data?.user?.avatar
    ? `${import.meta.env.VITE_API_URL}/${data?.user?.avatar}`
    : "/assets/avatar.png";
  return (
    <div className="max-w-[700px] mx-auto flex flex-col gap-6">
      <h2 className="text-2xl font-bold">Post</h2>
      {isLoading ? (
        <div className="h-28 flex justify-center items-center">
          <Loader />
        </div>
      ) : (
        <div className="flex flex-col gap-6">
          <div className="flex justify-between">
            <div className="flex gap-2">
              <Link to={`/users/${data?.user._id}`}>
                <img
                  src={avatar}
                  alt="avatar"
                  className="h-12 w-12 rounded-full"
                />
              </Link>
              <Link
                to={`/users/${data?.user._id}`}
                className="flex items-start mb-1 leading-3 flex-col gap-0.5"
              >
                <h3 className="font-bold text-lg hover:underline">
                  {data?.user.name}
                </h3>
                <p className="text-gray-500 text-sm">@{data?.user?.username}</p>
              </Link>
            </div>
            <div className="flex items-center gap-2 group relative cursor-pointer">
              <div
                className="ml-auto p-2 hover:bg-gray-100 grid place-content-center rounded-full"
                onClick={handleMore}
              >
                <FiMoreHorizontal fontSize={23} />
              </div>
              <DotsOptions
                showMore={showMore}
                isOwner={userId === data?.user._id}
                username={data?.user?.username}
              />
            </div>
          </div>
          <div className="flex flex-col gap-4">
            <p className="text-gray-900 w-full">{data?.content}</p>
            {data?.mediaType === "image/jpeg" && (
              <div className="rounded-3xl overflow-hidden mt-3 w-full">
                <img
                  src={`${import.meta.env.VITE_API_URL}/${data.media[0]}`}
                  alt=""
                  className="w-full h-auto"
                />
              </div>
            )}

            {data?.mediaType === "video/mp4" && (
              <div className="w-full">
                <video
                  width="100%"
                  height="100%"
                  className="rounded-md"
                  controls
                >
                  <source
                    src={`${import.meta.env.VITE_API_URL}/${data.media[0]}`}
                    type="video/mp4"
                  />
                </video>
              </div>
            )}

            <p className="text-gray-500 text-sm flex items-center gap-0.5">
              {timeString}
              <span> · </span>
              {dateString}
            </p>
            <ReactionIcons
              handlePopup={handlePopup}
              handleCommentClick={handleCommentClick}
              post={data}
              showPopUp={showPopUp}
            />
            <PostComments postId={data?._id} />
          </div>
        </div>
      )}
    </div>
  );
}
