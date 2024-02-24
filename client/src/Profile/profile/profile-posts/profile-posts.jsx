import { Repost } from "../../../components/repost/repost";
import { Loader } from "../../../components/ui/Loader";
import { SinglePost } from "../../../newsfeed/SinglePost";
import { useGetUserPostsQuery } from "../../../store";

export const ProfilePosts = ({ userId }) => {
  const { data, refetch, isLoading } = useGetUserPostsQuery(userId);

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
          <p>No user posts at the moment.</p>
        </div>
      )}
      <div className="flex flex-col gap-2">
        {data?.map((post) =>
          post.interactionType === "repost" ? (
            <Repost repost={post} refetch={refetch} key={post?._id} />
          ) : (
            <SinglePost post={post} refetch={refetch} key={post?._id} />
          )
        )}
      </div>
    </>
  );
};
