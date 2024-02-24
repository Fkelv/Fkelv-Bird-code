import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import { authEndpoints } from "./services/auth.service";
import { postEndpoints } from "./services/post.service";
import { userEndpoints } from "./services/user.service";
import { fileEndpoints } from "./services/file.service";
import { feedEndpoints } from "./services/feed.service";
import { notificationEndpoints } from "./services/notification.service";
import { videoEndpoints } from "./services/video.service";

const API_URL = import.meta.env.VITE_API_URL;
export const AUTH_HEADER_NAME = "Authorization";
export const REFRESH_TOKEN_HEADER_NAME = "Refresh-Token";

export const api = createApi({
  baseQuery: fetchBaseQuery({
    baseUrl: `${API_URL}/api`,
    prepareHeaders(headers, { getState }) {
      const accessToken = getState().auth.accessToken;
      const refreshToken = getState().auth.refreshToken;
      console.log(refreshToken)

      if (accessToken && refreshToken) {
        headers.set(AUTH_HEADER_NAME, `Bearer ${accessToken}`);
        headers.set(REFRESH_TOKEN_HEADER_NAME, refreshToken);
      }

      return headers;
    },
    credentials: "include",
  }),
  tagTypes: ["Post", "User", "Feed", "Notification"],
  extractRehydrationInfo(action, { reducerPath }) {
    if (action.type === "HYDRATE") {
      return action.payload[reducerPath];
    }
  },
  endpoints: () => ({}),
})
  .injectEndpoints({
    endpoints: authEndpoints,
  })
  .injectEndpoints({
    endpoints: postEndpoints,
  })
  .injectEndpoints({
    endpoints: userEndpoints,
  })
  .injectEndpoints({
    endpoints: fileEndpoints,
  })
  .injectEndpoints({
    endpoints: feedEndpoints,
  })
  .injectEndpoints({
    endpoints: notificationEndpoints,
  })
  .injectEndpoints({
    endpoints: videoEndpoints,
  });
