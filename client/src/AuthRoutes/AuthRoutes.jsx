import { useSelector } from "react-redux";
import { useRefreshAccessTokenQuery } from "../store";
import { selectCurrentUser } from "../store/authSlice";
import { Navigate, Outlet } from "react-router-dom";

export const AuthRoutes = () => {
  const { _ } = useRefreshAccessTokenQuery();
  const userId = useSelector(selectCurrentUser);

  return userId === null ? <Outlet /> : <Navigate to="/" />;
};
