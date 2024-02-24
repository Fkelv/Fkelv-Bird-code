import { useGetUserMediaQuery } from "../../../store";
import { Loader } from "../../../components/ui/Loader";
import { SinglePost } from "../../../newsfeed/SinglePost";

export const ProfileImages = ({ userId }) => {
  const { data, isLoading, refetch } = useGetUserMediaQuery(userId);
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
          <p>No media posted yet.</p>
        </div>
      )}
      <div className="flex flex-col gap-2">
        {data?.map((post) => (
          <SinglePost post={post} refetch={refetch} key={post._id} />
        ))}
      </div>
    </>
  );
};
