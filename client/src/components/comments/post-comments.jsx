import { SinglePost } from "../../newsfeed/SinglePost";
import { useGetCommentsQuery } from "../../store";
import Loader from "../ui/Loader";
import CommentField from "./CommentField";

export const PostComments = ({ postId }) => {
  const { data, isLoading, refetch } = useGetCommentsQuery(postId);
  return (
    <div className="flex flex-col gap-4">
      <CommentField postId={postId} refetch={refetch} />
      <div className="flex flex-col gap-2">
        {isLoading ? (
          <div className="flex justify-center items-center h-24">
            <Loader />
          </div>
        ) : (
          data?.map((comment) => (
            <SinglePost post={comment} key={comment._id} refetch={refetch} />
          ))
        )}
      </div>
    </div>
  );
};
