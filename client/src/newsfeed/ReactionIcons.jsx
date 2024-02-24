/* eslint-disable react/prop-types */
/* eslint-disable react/no-array-index-key */
import React from "react";
import { useSelector } from "react-redux";
import { Link } from "react-router-dom";
import { BsBarChart, FaRegComment, FiShare } from "../constant/icons";
import { selectCurrentUser } from "../store/authSlice";
import { LikePost } from "./like-post/like-post";
import { RetweetPost } from "./retweet-post/retweet-post";

export const ReactionIcons = ({
  post,
  handlePopup,
  handleCommentClick,
  showPopUp,
  refetch,
  dismissPopup,
}) => {
  const { _id: postId, retweets, likes = [] } = post || {};
  const userId = useSelector(selectCurrentUser);

  const likeStatus = post.likes.includes(userId);
  const retweetStatus = post.retweets.includes(userId);
  const retweetsNumber = post.retweets.length;
  const commentsNumber = post.comments1.length;
  return (
    <div className="flex items-center justify-between">
      <Link to="#" className="flex items-center gap-2 group">
        <div className="h-8 w-8 grid place-content-center rounded-full">
          <FaRegComment
            onClick={handleCommentClick}
            fontSize={18}
            className="text-gray-900 transition-none group-hover:text-blue-500"
          />
        </div>
        {commentsNumber > 0 && (
          <p className="mt-[-2px] transition-none text-gray-900 group-hover:text-blue-500">
            {commentsNumber}
          </p>
        )}
      </Link>
      <RetweetPost
        postId={postId}
        retweetStatus={retweetStatus}
        postRetweetNumber={retweetsNumber}
      />
      <LikePost
        postLiked={likeStatus}
        postLikesNo={likes.length}
        postId={postId}
      />
      <div className="flex items-center gap-2 group relative cursor-pointer">
        <div
          className="h-8 w-8 grid place-content-center rounded-full"
          onClick={handlePopup}
        >
          <FiShare
            fontSize={18}
            className="text-gray-900 transition-none group-hover:text-blue-500"
          />
        </div>
        {/* Share post popup component */}
        <div
          className={`absolute z-[5] bottom-full min-w-full right-0 ${
            showPopUp ? "flex opacity-100" : "hidden opacity-0"
          } flex-col  bg-white shadow-sm shadow-gray-300 opacity-1 py-2 px-3`}
        >
          {["Bookmark", "Share the link", "Send via direct message"].map(
            (item) => (
              <div
                className="w-max rounded-sm hover:bg-gray-100 px-2 py-[4px] min-w-full "
                key={item}
              >
                <Link to className="text-black text-sm">
                  {item}
                </Link>
              </div>
            )
          )}
        </div>
      </div>
      {/* analytics button */}
      {post.user._id === userId && (
        <Link
          to="/analytics"
          className="flex items-center gap-2 group cursor-pointer"
        >
          <div className="h-8 w-8 grid place-content-center rounded-full">
            <BsBarChart
              fontSize={18}
              className="transition-none group-hover:text-blue-700"
            />
          </div>
        </Link>
      )}
    </div>
  );
};
