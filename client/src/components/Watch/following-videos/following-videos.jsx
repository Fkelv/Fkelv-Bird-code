import { useSelector } from "react-redux";
import { selectCurrentUser } from "../../../store/authSlice";
import { useGetFollowingVideosQuery } from "../../../store";
import { Loader } from "../../../components/ui/Loader";
import { VideoPreview } from "../video-preview/video-preview";

export const FollowingVideos = () => {
  const userId = useSelector(selectCurrentUser);

  const { data, isLoading } = useGetFollowingVideosQuery(userId, {});

  if (isLoading) {
    return (
      <div className="w-full h-32 flex justify-center items-center">
        <Loader />
      </div>
    );
  }

  if (data?.length === 0) {
    return (
      <div className="w-full h-32 flex justify-center items-center">
        <p>No videos at the moment.</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-4 gap-4">
      {data?.map((item) => (
        <VideoPreview video={item} key={item._id} />
      ))}
    </div>
  );
};
