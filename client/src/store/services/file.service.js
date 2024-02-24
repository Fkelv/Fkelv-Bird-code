export const fileEndpoints = (builder) => ({
  uploadFile: builder.mutation({
    query: (payload) => ({
      url: "files/upload",
      method: "POST",
      body: payload,
    }),
  }),
});
