import { Loader } from "../../../components/ui/Loader";
import { SinglePost } from "../../../newsfeed/SinglePost";
import { useGetUserRepliesQuery } from "../../../store";

export const ProfileReplies = ({ userId }) => {
  const { data, refetch, isLoading } = useGetUserRepliesQuery(userId);
  return (
    <div className="flex flex-col gap-2">
      {isLoading && (
        <div className="flex h-32 w-full justify-center items-center">
          <Loader />
        </div>
      )}
      {data?.length === 0 && (
        <div className="flex h-32 w-full justify-center items-center">
          <p>No replies at the moment.</p>
        </div>
      )}
      {data?.map((post) => (
        <div className="flex flex-col gap-2" key={post._id}>
          <SinglePost
            post={post.parentPost}
            isParent={true}
            refetch={refetch}
          />
          <SinglePost post={post} refetch={refetch} />
        </div>
      ))}
    </div>
  );
};
