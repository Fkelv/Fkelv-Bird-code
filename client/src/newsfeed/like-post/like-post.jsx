import { useState } from "react";
import { AiFillHeart, AiOutlineHeart } from "react-icons/ai";
import { useLikePostMutation, useUnlikePostMutation } from "../../store";
import { FaLaptopHouse } from "react-icons/fa";

export const LikePost = ({ postLiked, postLikesNo, postId }) => {
  const [isLiked, setLiked] = useState(postLiked);
  const [likesNumber, setPostLikesNumber] = useState(postLikesNo);
  const [likePost, {}] = useLikePostMutation();
  const [unlikePost, {}] = useUnlikePostMutation();

  const handleLike = async () => {
    try {
      await likePost(postId);
      setLiked(true);
      setPostLikesNumber((prevCount) => prevCount + 1);
    } catch (e) {
      console.error("Unable to like post");
    }
  };

  const handleUnlike = async () => {
    try {
      await unlikePost(postId);
      setLiked(false);
      setPostLikesNumber((prevCount) => prevCount - 1);
    } catch (e) {
      console.error("Unable to unlike post");
    }
  };
  return (
    <div className="flex items-center gap-2 group cursor-pointer">
      <div className="h-8 w-8 grid place-content-center rounded-full">
        {isLiked ? (
          <AiFillHeart
            fontSize={18}
            onClick={handleUnlike}
            className="text-pink-500"
          />
        ) : (
          <AiOutlineHeart
            onClick={handleLike}
            fontSize={18}
            className="text-gray-900 transition-none group-hover:text-pink-500 group-hover:text-pink-500"
          />
        )}
      </div>
      {likesNumber > 0 && (
        <p
          className={`mt-[-2px] transition-none text-gray-900 group-hover:text-pink-500`}
        >
          {likesNumber}
        </p>
      )}
    </div>
  );
};
