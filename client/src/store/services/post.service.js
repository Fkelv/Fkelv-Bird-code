const postTag = "Post";

export const postEndpoints = (build) => ({
  feed: build.query({
    query: (userId) => ({
      url: `/posts/feed/${userId}`,
      method: "GET",
    }),
  }),
  getUserPosts: build.query({
    query: (userId) => ({
      url: `/posts/users/${userId}`,
      method: "GET",
    }),
    providesTags: (result, error, arg) => {
      return result
        ? [...result.map(({ _id }) => ({ type: postTag, id: _id })), postTag]
        : [postTag];
    },
  }),
  followingFeed: build.query({
    query: () => ({
      url: `/posts/following`,
      method: "GET",
    }),
    providesTags: (result) =>
      result
        ? [
            ...result.map(({ _id }) => ({ type: "Post", id: _id })),
            { type: "Post", id: "LIST" },
          ]
        : [{ type: "Post", id: "LIST" }],
  }),
  createPost: build.mutation({
    query: (payload) => ({
      url: `/posts/new`,
      method: "POST",
      body: payload,
    }),
    invalidateTags: [{ type: "Post", id: "LIST" }],
  }),
  likePost: build.mutation({
    query: (payload) => ({
      url: `posts/likes/${payload}`,
      method: "POST",
    }),
    invalidateTags: (result, error, arg) => [{ type: postTag, id: arg }],
  }),
  unlikePost: build.mutation({
    query: (payload) => ({
      url: `/posts/likes/${payload}`,
      method: "DELETE",
    }),
    invalidateTags: (result, error, arg) => [{ type: postTag, id: arg }],
  }),
  retweetPost: build.mutation({
    query: (payload) => ({
      url: `/posts/retweets/${payload}`,
      method: "POST",
    }),
  }),
  unRetweetPost: build.mutation({
    query: (payload) => ({
      url: `/posts/retweets/${payload}`,
      method: "DELETE",
    }),
  }),
  getPost: build.query({
    query: (payload) => ({
      url: `/posts/${payload}`,
      method: "GET",
    }),
    providesTags: (result) => {
      return result ? [{ type: postTag, id: result._id }, postTag] : [postTag];
    },
  }),

  createComment: build.mutation({
    query: ({ postId, formData }) => ({
      url: `/posts/${postId}/comments`,
      method: "POST",
      body: formData,
      formData: true,
    }),
    invalidateTags: (result, error, arg) => [{ type: postTag, id: arg }],
  }),
  getComments: build.query({
    query: (payload) => ({
      url: `/posts/${payload}/comments`,
      method: "GET",
    }),
  }),
  deletePost: build.mutation({
    query: (payload) => ({
      url: `/posts/${payload}`,
      method: "DELETE",
    }),
  }),
  pinPost: build.mutation({
    query: (payload) => ({
      url: `/posts/pin/${payload}`,
      method: "PUT",
    }),
  }),
  unpinPost: build.mutation({
    query: (payload) => ({
      url: `/posts/unpin/${payload}`,
      method: "PUT",
    }),
  }),
});
