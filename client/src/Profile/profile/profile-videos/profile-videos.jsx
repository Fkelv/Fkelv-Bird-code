import Loader from "../../../components/ui/Loader";
import { VideoItem } from "../../../components/video-item/video-item";
import { useGetUserVideosQuery } from "../../../store";

export const ProfileVideos = ({ userId }) => {
  const { data, isLoading, refetch } = useGetUserVideosQuery(userId);

  if (isLoading) {
    return (
      <div className="flex h-32 w-full justify-center items-center">
        <Loader />
      </div>
    );
  }

  return (
    <>
      {data?.length === 0 && (
        <div className="flex h-32 w-full justify-center items-center">
          <p>No videos uploaded yet.</p>
        </div>
      )}
      <div className="flex flex-col gap-2">
        {data?.map((video) => (
          <VideoItem video={video} key={video._id} />
        ))}
      </div>
    </>
  );
};
