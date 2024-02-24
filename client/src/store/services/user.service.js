const userTag = "User";
export const userEndpoints = (builder) => ({
  getUser: builder.query({
    query: (payload) => ({
      url: `/users/${payload}`,
      method: "GET",
    }),
    providesTags: (result) =>
      result ? [{ type: userTag, id: result._id }, userTag] : [userTag],
  }),
  getUserReplies: builder.query({
    query: (payload) => ({
      url: `/users/${payload}/replies`,
      method: "GET",
    }),
  }),
  getUserMedia: builder.query({
    query: (payload) => ({
      url: `/users/${payload}/media`,
      method: "GET",
    }),
  }),
  getPinnedPost: builder.query({
    query: (payload) => ({
      url: `/users/${payload}/posts/pinned`,
      method: "GET",
    }),
  }),
  updateUser: builder.mutation({
    query: ({ userId, ...payload }) => ({
      url: `/users/${userId}`,
      method: "PUT",
      body: payload,
    }),
    invalidatesTags: [userTag],
  }),
  getFollowers: builder.query({
    query: (payload) => ({
      url: `/users/${payload}/followers`,
      method: "GET",
    }),
    providesTags: (result) =>
      result
        ? [
            ...result.map(({ _id }) => ({ type: "User", id: _id })),
            { type: "User", id: "LIST" },
          ]
        : [{ type: "User", id: "LIST" }],
  }),
  getFollowing: builder.query({
    query: (payload) => ({
      url: `/users/${payload}/following`,
      method: "GET",
    }),
    providesTags: (result) =>
      result
        ? [
            ...result.map(({ _id }) => ({ type: "User", id: _id })),
            { type: "User", id: "LIST" },
          ]
        : [{ type: "User", id: "LIST" }],
  }),

  followUser: builder.mutation({
    query: (payload) => ({
      url: `/users/follow/${payload}`,
      method: "POST",
    }),
    invalidatesTags: (result, error, arg) => [
      { type: "User", id: arg },
      { type: "User", id: "LIST" },
    ],
  }),
  unfollowUser: builder.mutation({
    query: (payload) => ({
      url: `/users/unfollow/${payload}`,
      method: "POST",
    }),
    invalidatesTags: (result, error, arg) => [
      { type: "User", id: arg },
      { type: "User", id: "LIST" },
    ],
  }),
  blockUser: builder.mutation({
    query: (payload) => ({
      url: `/users/block/${payload}`,
      method: "POST",
    }),
    invalidatesTags: (result) =>
      result ? [{ type: userTag, id: result._id }] : [userTag],
  }),
  unblockUser: builder.mutation({
    query: (payload) => ({
      url: `/users/unblock/${payload}`,
      method: "POST",
    }),
    invalidatesTags: (result) =>
      result ? [{ type: userTag, id: result._id }] : [userTag],
  }),
  muteUser: builder.mutation({
    query: (payload) => ({
      url: `/users/mute/${payload}`,
      method: "POST",
    }),
    invalidatesTags: (result) =>
      result ? [{ type: userTag, id: result._id }] : [userTag],
  }),
  unmuteUser: builder.mutation({
    query: (payload) => ({
      url: `/users/unmute/${payload}`,
      method: "POST",
    }),
    invalidatesTags: (result) =>
      result ? [{ type: userTag, id: result._id }] : [userTag],
  }),
});
