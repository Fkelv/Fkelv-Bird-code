import React from "react";
import { Navigate, Outlet } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { selectCurrentUser, signOut } from "../store/authSlice";
import { useRefreshAccessTokenQuery } from "../store";
import Loader from "../components/ui/Loader";

export const PrivateRoutes = () => {
  const { isLoading } = useRefreshAccessTokenQuery();
  const userId = useSelector(selectCurrentUser);

  const dispatch = useDispatch();
  if (isLoading) {
    return <Loader />;
  }

  return userId ? <Outlet /> : <Navigate to="auth/signin" />;
};
