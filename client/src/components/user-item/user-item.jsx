import { Link } from "react-router-dom";
import { FollowSection } from "../../Profile/profile/follow-section/follow-section";

export const UserItem = ({ user, currentUser }) => {
  const followStatus = user.followers.includes(currentUser);
  const avatar = user.avatar
    ? `${import.meta.env.VITE_API_URL}/${user.avatar}`
    : "/assets/avatar.png";
  return (
    <div className="flex justify-between p-2" key={user._id}>
      <Link to={`/users/${user._id}`} className="flex gap-2 items-center">
        <img
          src={avatar}
          alt={user.name}
          className="h-10 w-10 rounded-full overflow-hidden"
        />
        <div className="flex flex-col gap-px">
          <p className="font-bold">{user.name}</p>
          <p>@{user.username}</p>
        </div>
      </Link>
      <div className="flex gap-2 items-center">
        <FollowSection userId={user._id} followStatus={followStatus} />
      </div>
    </div>
  );
};
