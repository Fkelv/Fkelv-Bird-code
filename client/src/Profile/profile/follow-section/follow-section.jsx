import { useRef } from "react";
import { useFollowUserMutation, useUnfollowUserMutation } from "../../../store";
import { Loader } from "../../../components/ui/Loader";
import { toast } from "react-toastify";

export const FollowSection = ({ userId, followStatus }) => {
  const followBtnRef = useRef();
  const [followUser, { isLoading: followLoading }] = useFollowUserMutation();
  const [unfollowUser, { isLoading: unfollowLoading }] =
    useUnfollowUserMutation();
  const handleMouseEnter = () => {
    if (followBtnRef.current.innerText === "Following") {
      followBtnRef.current.innerText = "Unfollow";
    }
  };
  const handleMouseLeave = () => {
    if (followBtnRef.current.innerText === "Unfollow") {
      followBtnRef.current.innerText = "Following";
    }
  };

  const handleClick = async () => {
    if (!followStatus) {
      const response = await followUser(userId);
      if (response.error) {
        const message = response.error.data.message;
        toast.error(message, {
          toastId: `follow-${userId}`,
        });
      }
    } else {
      unfollowUser(userId);
    }
  };
  return (
    <button
      onClick={handleClick}
      ref={followBtnRef}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      className={`py-[7px] rounded-full tracking-wide border border-blue-100 ${
        !followStatus
          ? "bg-blue-600 w-[90px] font-medium text-white hover:bg-blue-500"
          : "text-blue-500 font-bold hover:bg-red-100 hover:text-red-500 hover:border-red-100 w-[108px]"
      } text-[16px]`}
      type="button"
    >
      {followLoading || unfollowLoading ? (
        <Loader />
      ) : !followStatus ? (
        "Follow"
      ) : (
        "Following"
      )}
    </button>
  );
};
