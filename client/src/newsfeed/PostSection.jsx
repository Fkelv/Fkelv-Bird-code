/* eslint-disable react/prop-types */
import { Loader } from "../components/ui/Loader";
import { useSocket } from "../hooks/useSocket";
import { SinglePost } from "./SinglePost";
import { useEffect, useState } from "react";

export const PostSection = ({ isLoading, posts, refetch, userId }) => {
  const [updates, setUpdates] = useState([]);

  const socket = useSocket(userId);
  useEffect(() => {
    if (socket) {
      socket.on("feedUpdate", (data) => {
        setUpdates((prev) => [...prev, data]);
      });
    }
  }, [socket]);

  if (isLoading) {
    return (
      <div className="w-full h-36 flex justify-center items-center">
        <Loader />
      </div>
    );
  }

  const handleRefetch = () => {
    refetch();
    setUpdates([]);
  };
  return (
    <div className="relative">
      {updates.length > 0 && (
        <div className="flex w-full py-2 justify-center items-center border-b-[0.5px] border-gray-300">
          <button onClick={handleRefetch} className="text-blue-500">
            {updates.length}&nbsp;new post{updates.length > 1 ? "s" : ""}
          </button>
        </div>
      )}
      {posts.map((post) => (
        <SinglePost post={post} key={post._id} refetch={refetch} />
      ))}
    </div>
  );
};
