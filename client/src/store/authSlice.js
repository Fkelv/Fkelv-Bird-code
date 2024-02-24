import { createSlice } from "@reduxjs/toolkit";
import { api } from "./apiSlice";

const ACCESS_TOKEN_TAG = import.meta.env.VITE_ACCESS_TOKEN_TAG;
const REFRESH_TOKEN_TAG = import.meta.env.VITE_REFRESH_TOKEN_TAG;

const authSlice = createSlice({
  name: "auth",
  initialState: {
    accessToken: localStorage.getItem(ACCESS_TOKEN_TAG) || null,
    refreshToken: localStorage.getItem(REFRESH_TOKEN_TAG) || null,
    userId: null,
  },
  reducers: {
    signOut: (state, _) => {
      state.userId = null;
      state.accessToken = null;
      state.refreshToken = null;

      localStorage.removeItem(ACCESS_TOKEN_TAG);
      localStorage.removeItem(REFRESH_TOKEN_TAG);
    },
  },
  extraReducers: (builder) => {
    builder.addMatcher(
      api.endpoints.signIn.matchFulfilled,
      (state, { payload }) => {
        state.accessToken = payload.accessToken;
        state.refreshToken = payload.refreshToken;
        state.userId = payload.user._id;
        console.log("rr:", payload);
        localStorage.setItem(ACCESS_TOKEN_TAG, payload.accessToken);
        localStorage.setItem(REFRESH_TOKEN_TAG, payload.refreshToken);
      }
    );
    builder.addMatcher(
      api.endpoints.signUp.matchFulfilled,
      (state, { payload }) => {
        state.accessToken = payload.accessToken;
        state.refreshToken = payload.refreshToken;
        state.userId = payload.user._id;

        localStorage.setItem(ACCESS_TOKEN_TAG, payload.accessToken);
        localStorage.setItem(REFRESH_TOKEN_TAG, payload.refreshToken);
      }
    );
    builder.addMatcher(
      api.endpoints.refreshAccessToken.matchFulfilled,
      (state, { payload }) => {
        console.log(payload)
        state.accessToken = payload.accessToken;
        state.refreshToken = payload.refreshToken;
        state.userId = payload.userId;

        localStorage.setItem(ACCESS_TOKEN_TAG, payload.accessToken);
        localStorage.setItem(REFRESH_TOKEN_TAG, payload.refreshToken);
      }
    );
  },
});

export const selectCurrentUser = (state) => state.auth.userId;

const { actions, reducer } = authSlice;

export const { signOut } = actions;

export default reducer;
