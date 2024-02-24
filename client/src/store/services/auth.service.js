export const ACCESS_TOKEN_HEADER_NAME = "Authorization";
export const REFRESH_TOKEN_HEADER_NAME = "Refresh-Token";

export const authEndpoints = (builder) => ({
  signIn: builder.mutation({
    query: (payload) => ({
      url: `/auth/signin`,
      method: "POST",
      body: payload,
    }),
    transformResponse: (response, meta, _args) => {
      return {
        user: response,
        accessToken: getAccessToken(
          meta.response.headers.get(ACCESS_TOKEN_HEADER_NAME)
        ),
        refreshToken: meta.response.headers.get(REFRESH_TOKEN_HEADER_NAME),
      };
    },
  }),
  signUp: builder.mutation({
    query: (payload) => ({
      url: "/auth/signup",
      method: "POST",
      body: payload,
    }),
    transformResponse: (response, meta, _args) => ({
      user: response,
      accessToken: getAccessToken(
        meta.response.headers.get(ACCESS_TOKEN_HEADER_NAME)
      ),
      refreshToken: meta.response.headers.get(REFRESH_TOKEN_HEADER_NAME),
    }),
  }),
  refreshAccessToken: builder.query({
    query: (payload) => ({
      url: "/auth/refresh",
      method: "GET",
      body: payload,
    }),
    transformResponse: (response, meta, _args) => ({
      userId: response.userId,
      accessToken: getAccessToken(
        meta.response.headers.get(ACCESS_TOKEN_HEADER_NAME)
      ),
      refreshToken: meta.response.headers.get(REFRESH_TOKEN_HEADER_NAME),
    }),
  }),
  forgetPassword: builder.mutation({
    query: (payload) => ({
      url: "/auth/password/forget",
      method: "POST",
      body: payload,
    }),
  }),
  resetPassword: builder.mutation({
    query: (payload) => ({
      url: `auth/password/reset/${payload.token}`,
      method: "POST",
      body: {
        password: payload.password,
      },
    }),
  }),
});

export const getAccessToken = (authHeader) => {
  return authHeader.split(" ")[1];
};
