const videoTag = "Video";

export const videoEndpoints = (build) => ({
  createVideo: build.mutation({
    query: (payload) => ({
      url: "/videos/new",
      method: "POST",
      body: payload,
    }),
    providesTags: [videoTag]
  }),
  getVideo: build.query({
    query: (payload) => ({
      url: `/videos/${payload}`,
      method: "GET",
    }),
  }),
  getUserVideos: build.query({
    query: (payload) => ({
      url: `videos/users/${payload}`,
      method: "GET",
    }),
    providesTags: [videoTag],
  }),
  getFollowingVideos: build.query({
    query: (payload) => ({
      url: `/videos/users/${payload}/following`,
      method: "GET",
    }),
    providesTags: [videoTag],
  }),
  deleteVideo: build.mutation({
    query: (payload) => ({
      url: `/videos/${payload}`,
      method: "DELETE",
    }),
    invalidatesTags: [videoTag],
  }),
});
