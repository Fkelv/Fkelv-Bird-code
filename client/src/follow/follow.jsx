import { useParams } from "react-router-dom";
import { useGetFollowersQuery, useGetFollowingQuery } from "../store";
import { UserItem } from "../components/user-item/user-item";
import { useState } from "react";
import { Loader } from "../components/ui/Loader";

export const Follow = () => {
  const { id, follow } = useParams();
  const [activeTab, setActiveTab] = useState(follow);

  return (
    <div className="max-w-[700px] mx-auto flex flex-col gap-4 pt-6 border-x border-gray-200 min-h-screen">
      <div className="flex bg-white rounded-lg overflow-hidden shadow-md">
        <div
          className={`flex-1 text-center py-4 cursor-pointer transition duration-300 ${
            activeTab === "followers"
              ? "border-blue-500 border-b-4 text-black"
              : "hover:bg-blue-100"
          }`}
          onClick={() => setActiveTab("followers")}
        >
          Followers
        </div>
        <div
          className={`flex-1 text-center py-4 cursor-pointer transition duration-300 ${
            activeTab === "following"
              ? "border-blue-500 border-b-4 text-black"
              : "hover:bg-blue-100"
          }`}
          onClick={() => setActiveTab("following")}
        >
          Following
        </div>
      </div>

      <div className="flex flex-col gap-2 divide-y divide-blue-200">
        {activeTab === "followers" && <FollowersTab userId={id} />}
        {activeTab === "following" && <FollowingTab userId={id} />}
      </div>
    </div>
  );
};

const FollowersTab = ({ userId }) => {
  const { data, isLoading } = useGetFollowersQuery(userId);

  return (
    <>
      {isLoading && (
        <div className="flex items-center h-28 w-full justify-center">
          <Loader />
        </div>
      )}
      {data?.length === 0 && !isLoading && (
        <div className="flex items-center h-28 w-full justify-center">
          <p className="font-bold text-lg">
            You don't have any followers now :)
          </p>
        </div>
      )}
      {data?.map((user) => (
        <UserItem user={user} key={user._id} currentUser={userId} />
      ))}
    </>
  );
};

const FollowingTab = ({ userId }) => {
  const { data, isLoading } = useGetFollowingQuery(userId);

  return (
    <>
      {isLoading && (
        <div className="flex items-center h-28 w-full justify-center">
          <Loader />
        </div>
      )}

      {data?.length === 0 && !isLoading && (
        <div className="flex items-center h-28 w-full justify-center">
          <p className="font-bold text-lg">
            You are not following anyone now :)
          </p>
        </div>
      )}
      {data?.map((user) => (
        <UserItem user={user} key={user._id} currentUser={userId} />
      ))}
    </>
  );
};
