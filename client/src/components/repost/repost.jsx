import { useSelector } from "react-redux";
import { selectCurrentUser } from "../../store/authSlice";
import { BiRepost } from "react-icons/bi";
import { SinglePost } from "../../newsfeed/SinglePost";
import { useGetPostQuery, useGetUserQuery } from "../../store";
import { Loader } from "../ui/Loader";

export const Repost = ({ repost, refetch }) => {
  const userId = useSelector(selectCurrentUser);
  const { data: postData, isLoading: postLoading } = useGetPostQuery(
    repost?.post
  );
  const { data: userData, isLoading: userLoading } = useGetUserQuery(
    repost?.user
  );

  if (userLoading || postLoading) {
    return (
      <div className="flex justify-center items-center h-24">
        <Loader />
      </div>
    );
  }
  return (
    <SinglePost post={postData} refetch={refetch}>
      <div className="pl-10 flex gap-px items-center">
        <BiRepost className="text-sm text-gray-500" />
        <p className="text-sm text-gray-500">
          {userId === userData._id ? "You" : userData.name} reposted
        </p>
      </div>
    </SinglePost>
  );
};
