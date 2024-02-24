import React from "react";
import { Navigate } from "react-router-dom";
import useAuth from "../hooks/useAuth";
import { useRefreshAccessTokenQuery } from "../store";

const PublicRoute = ({ children }) => {
  useRefreshAccessTokenQuery();
  const auth = useAuth();
  return !auth ? children : <Navigate to="/" />;
};

export default PublicRoute;
