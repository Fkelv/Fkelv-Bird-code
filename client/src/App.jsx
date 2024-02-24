import React, { useLayoutEffect } from "react";
import { Route, Routes, useLocation } from "react-router-dom";
import { PrivateRoutes } from "./AuthRoutes/PrivateRoute";
import PublicRoute from "./AuthRoutes/PublicRoute";
import Nav from "./components/Nav";
import Loader from "./components/ui/Loader";
import useAuthCheck from "./hooks/useAuthCheck";
import Discover from "./pages/Discover";
import EditProfilePage from "./pages/EditProfilePage";
import MessagesPage from "./pages/Messages/MessagesPage";
import { Notifications } from "./pages/Notifications";
import PostAnalytics from "./pages/PostAnalytics";
import { Profile } from "./Profile/profile/profile";
import Search from "./pages/Search";
import Settings from "./pages/Settings";
import SinglePostView from "./pages/SinglePostView";
import Subscriptions from "./pages/Subscriptions";
import { SingleVideo } from "./pages/watch/SingleVideo";
import Watch from "./pages/watch/Watch";
import { NewsFeed } from "./newsfeed/NewsFeed";
import { SignIn } from "./auth/sign-in/sign-in";
import { SignUp } from "./auth/sign-up/sign-up";
import { PasswordForget } from "./auth/password-forget/password-forget";
import { PasswordReset } from "./auth/password-reset/password-reset";
import "react-toastify/dist/ReactToastify.css";
import { Follow } from "./follow/follow";
import { Studio } from "./VideoStudio/Studio";
import { ManagingVideos } from "./VideoStudio/ManagingVideos";
import { Analytics } from "./VideoStudio/analytics/Analytics";
import { GoLive } from "./VideoStudio/GoLive";
import { Monetization } from "./VideoStudio/Monitization";
import { UploadVideo } from "./VideoStudio/upload-video/upload-video";
import { StreamManager } from "./VideoStudio/Stream/StreamManager";

const Wrapper = ({ children }) => {
  const location = useLocation();
  useLayoutEffect(() => {
    document.documentElement.scrollTo(0, 0);
  }, [location.pathname]);
  return children;
};

function App() {
  const authCheck = useAuthCheck();
  return !authCheck ? (
    <Loader />
  ) : (
    <div className="relative">
      <Nav />
      <Wrapper>
        <Routes>
          <Route element={<PrivateRoutes />}>
            <Route element={<NewsFeed />} path={"/"} exact />
            <Route path="/posts/:id" element={<SinglePostView />} />
            <Route path="studio" element={<Studio />}>
              <Route path="content" element={<ManagingVideos />} />
              <Route path="analytics" element={<Analytics />} />
              <Route path="go-live" element={<GoLive />} />
              <Route path="monetization" element={<Monetization />} />
              <Route path="stream-manager" element={<StreamManager />} />
              <Route path="upload-video" element={<UploadVideo />} />
            </Route>

            <Route path="/settings" element={<Settings isLoggedIn={true} />} />
            <Route path="/users/:id" element={<Profile />} />
            <Route path="/users/:id/:follow" element={<Follow />} />
            <Route path="/discover" element={<Discover isLoggedIn={true} />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route
              path="/subscription"
              element={<Subscriptions isLoggedIn={true} />}
            />
            <Route
              path="/messages"
              element={<MessagesPage isLoggedIn={true} />}
            />
            <Route
              path="/analytics"
              element={<PostAnalytics isLoggedIn={true} />}
            />
            <Route
              path="/account/edit"
              element={<EditProfilePage isLoggedIn={true} />}
            />
          </Route>

          <Route path="/search" element={<Search />} />
          <Route path="/watch" element={<Watch />} />
          <Route path="/watch/:id" element={<SingleVideo />} />
          <Route
            path="/auth/signin"
            element={
              <PublicRoute>
                <SignIn />
              </PublicRoute>
            }
          />
          <Route
            path="/auth/signup"
            element={
              <PublicRoute>
                <SignUp />
              </PublicRoute>
            }
          />
          <Route
            path="/auth/password/forget"
            element={
              <PublicRoute>
                <PasswordForget />
              </PublicRoute>
            }
          />
          <Route
            path="/auth/password/forget"
            element={
              <PublicRoute>
                <PasswordForget />
              </PublicRoute>
            }
          />
          <Route
            path="/auth/password/reset/:token"
            element={
              <PublicRoute>
                <PasswordReset />
              </PublicRoute>
            }
          />
        </Routes>
      </Wrapper>
    </div>
  );
}

export default App;
