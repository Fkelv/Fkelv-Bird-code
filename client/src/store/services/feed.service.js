export const feedEndpoints = (build) => ({
  getPosts1: build.query({
    query: () => "/posts/feed",
    providesTags: (result, error, arg) =>
      result
        ? [...result.map(({ _id }) => ({ type: "Post", id: _id })), "Post"]
        : ["Post"],
  }),
  addPost: build.mutation({
    query: (body) => ({
      url: "/posts/new",
      method: "POST",
      body,
    }),
    invalidatesTags: ["Post"],
  }),
  editPost: build.mutation({
    query: (body) => ({
      url: `post/${body.id}`,
      method: "POST",
      body,
    }),
    invalidatesTags: ["Post"],
  }),
});
