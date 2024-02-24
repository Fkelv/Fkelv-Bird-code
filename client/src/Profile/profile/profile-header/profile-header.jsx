import { useState } from "react";
import { Link } from "react-router-dom";
import {
  MdLink,
  MdOutlineBlock,
  MdOutlineLocationOn,
  MdOutlineNotificationAdd,
  MdOutlineNotificationsActive,
  MdWork,
} from "react-icons/md";
import { BsPatchCheckFill } from "react-icons/bs";
import { HiOutlineMail } from "react-icons/hi";
import { FiMoreHorizontal } from "react-icons/fi";
import { useSelector } from "react-redux";
import { selectCurrentUser } from "../../../store/authSlice";
import { FollowSection } from "../follow-section/follow-section";
import { useUnmuteUserMutation, useGetUserQuery } from "../../../store";
import { BlockButton } from "../block-button/block-button";
import { DotOptions } from "./dot-options/dot-options";
import { toast } from "react-toastify";

export const ProfileHeader = ({ existingUser, blockedStatus, mutedStatus }) => {
  const [showMore, setShowMore] = useState(false);
  const handleMore = () => {
    setShowMore(() => !showMore);
  };
  const [activeNotification, setActiveNotification] = useState(false);
  const [follow, setFollow] = useState(false);
  const {
    _id,
    name,
    avatar,
    backgroundURL,
    bio,
    username,
    work_title,
    city,
    country,
    following,
    followers,
    profileLink,
  } = existingUser;
  const userId = useSelector(selectCurrentUser);
  const randomUser = userId === _id;

  const avatarURL = avatar
    ? `${import.meta.env.VITE_API_URL}/${avatar}`
    : "/assets/avatar.png";
  const followStatus = followers.includes(userId);
  const [unmute, {}] = useUnmuteUserMutation();
  const handleUnmute = async () => {
    const response = await unmute(_id);
    if (response.data) {
      toast(`@${username} unmuted!`, {
        toastId: `unmute-${_id}`,
        type: "success",
      });
    }
  };
  return (
    <>
      <div>
        {backgroundURL ? (
          <div className="h-[150px] overflow-hidden">
            <img
              className="object-cover"
              src="https://source.unsplash.com/3_MEgdUNMH0"
              alt="bg"
              height="150px"
              width="100%"
            />
          </div>
        ) : (
          <div className="h-[150px] bg-gradient-to-r from-cyan-300 to-blue-400" />
        )}
      </div>
      <div className="pl-7">
        <div className="flex items-end justify-between">
          <div className="h-32 w-32 mt-[-70px] border-[-4px] border-white overflow-hidden rounded-full">
            <img
              className="h-full w-full object-cover rounded-full "
              src={avatarURL}
              alt="user"
            />
          </div>
          <div className="flex items-center gap-3">
            {!randomUser ? (
              <>
                {follow && (
                  <div
                    onClick={() => setActiveNotification(!activeNotification)}
                    className="p-2 rounded-full border hover:bg-gray-50 cursor-pointer"
                  >
                    {!activeNotification ? (
                      <MdOutlineNotificationAdd fontSize={23} />
                    ) : (
                      <MdOutlineNotificationsActive fontSize={23} />
                    )}
                  </div>
                )}
                {!blockedStatus && (
                  <>
                    <button
                      className="p-2 hover:bg-gray-50 border rounded-full"
                      type="button"
                    >
                      <HiOutlineMail fontSize={23} />
                    </button>

                    <FollowSection userId={_id} followStatus={followStatus} />
                  </>
                )}
                <div className="flex items-center border hover:bg-gray-100 rounded-full relative cursor-pointer">
                  <button
                    className="p-2 grid place-content-center"
                    onClick={handleMore}
                  >
                    <FiMoreHorizontal fontSize={23} />
                  </button>
                  {showMore && (
                    <DotOptions
                      userId={_id}
                      username={username}
                      blockedStatus={blockedStatus}
                      mutedStatus={mutedStatus}
                    />
                  )}
                </div>
                {blockedStatus && <BlockButton userId={_id} />}
              </>
            ) : (
              <Link
                to="/account/edit"
                type="button"
                className="py-[6px] px-4 border-2 font-medium tracking-[.015em] border-blue-600 text-blue-600 hover:bg-gray-50 cursor-pointer rounded-full"
              >
                Edit Profile
              </Link>
            )}
          </div>
        </div>
        <header className="pt-4">
          <h2 className="font-semibold text-xl flex items-center gap-2">
            {name} <BsPatchCheckFill fontSize={15} className="text-blue-600" />
          </h2>

          <p className="text-sm text-gray-500">{username}</p>
          <p className="py-2">{bio}</p>
        </header>
        <div className="flex flex-wrap gap-x-5 gap-y-1 mb-4">
          {
            work_title && (
              <div className="flex items-center text-sm gap-2">
                <MdWork fontSize={22} />
                <p>{work_title}</p>
              </div>
            )
            /* <div className="flex items-center text-sm gap-2">
                        <GoCalendar fontSize={19} />
                        <p>Joined April 2022</p>
                    </div> */
          }
          {city && country && (
            <div className="flex items-center text-sm gap-2">
              <MdOutlineLocationOn fontSize={20} />
              <p>
                {city}, {country}
              </p>
            </div>
          )}
          {profileLink && (
            <div className="flex basis-full items-center mt-1 gap-2">
              <MdLink fontSize={22} />
              <a
                className="text-sm text-blue-600"
                href={profileLink}
                target="_blank"
              >
                {profileLink}
              </a>
            </div>
          )}
          <div className="flex basis-full items-center gap-2 mt-[8px]">
            <p className="text-black">
              {following.length === 0 ? (
                <>{following.length} Following</>
              ) : (
                <Link to={`/users/${_id}/following`}>
                  {following.length} Following
                </Link>
              )}
            </p>
            <span>·</span>
            <p className="text-black">
              {followers.length === 0 ? (
                <>{followers.length} Followers</>
              ) : (
                <Link to={`/users/${_id}/followers`}>
                  {followers.length} Followers
                </Link>
              )}{" "}
            </p>
          </div>
        </div>
        {mutedStatus && (
          <p>
            You have muted posts from this account.&nbsp;
            <button
              className="text-blue-500 hover:underline"
              onClick={handleUnmute}
            >
              Unmute
            </button>
          </p>
        )}
      </div>
    </>
  );
};
