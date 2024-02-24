import { configureStore } from "@reduxjs/toolkit";
import { setupListeners } from "@reduxjs/toolkit/query/react";
import authReducer from "./authSlice";
import { useDispatch, useSelector } from "react-redux";
import { api } from "./apiSlice";

export const store = configureStore({
  reducer: {
    [api.reducerPath]: api.reducer,
    auth: authReducer,
  },

  devTools: import.meta.env.MODE !== "production",
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(api.middleware),
});

setupListeners(store.dispatch);

export const { signIn, signUp } = api.endpoints;

export const {
  useSignUpMutation,
  useSignInMutation,
  useRefreshAccessTokenQuery,
  useFeedQuery,
  useForgetPasswordMutation,
  useResetPasswordMutation,
  useGetUserQuery,
  useGetUserPostsQuery,
  useUploadFileMutation,
  useUpdateUserMutation,
  useCreatePostMutation,
  useLikePostMutation,
  useUnlikePostMutation,
  useRetweetPostMutation,
  useUnRetweetPostMutation,
  useCreateCommentMutation,
  useGetCommentsQuery,
  useGetPostQuery,
  useDeletePostMutation,
  useFollowUserMutation,
  useUnfollowUserMutation,
  useFollowingFeedQuery,
  useAddPostMutation,
  useGetFollowersQuery,
  useGetFollowingQuery,
  useGetUserRepliesQuery,
  useGetUserMediaQuery,
  useGetPinnedPostQuery,
  useGetUnreadNotificationsQuery,
  useGetNotificationsQuery,
  useClearNotificationsMutation,
  useDeleteNotificationMutation,
  useReadNotificationMutation,
  useCreateVideoMutation,
  useGetVideoQuery,
  useGetFollowingVideosQuery,
  useGetUserVideosQuery,
  useDeleteVideoQuery,
  useBlockUserMutation,
  useUnblockUserMutation,
  useMuteUserMutation,
  useUnmuteUserMutation,
} = api;

export const useAppDispatch = () => useDispatch();
export const useAppSelector = useSelector;
