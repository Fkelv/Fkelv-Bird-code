const notificationTag = "Notification";
export const notificationEndpoints = (build) => ({
  getNotifications: build.query({
    query: () => ({
      url: `/notifications`,
      method: "GET",
    }),
    providesTags: (result) =>
      result
        ? [
            ...result.map(({ _id }) => ({ type: notificationTag, id: _id })),
            { type: notificationTag, id: "LIST" },
          ]
        : [{ type: notificationTag, id: "LIST" }],
  }),
  getUnreadNotifications: build.query({
    query: () => ({
      url: `/notifications/unread`,
      method: "GET",
    }),
    providesTags: (result) =>
      result
        ? [
            ...result.map(({ _id }) => ({ type: notificationTag, id: _id })),
            { type: "Notification", id: "UNREAD" },
          ]
        : [{ type: "Notification", id: "UNREAD" }],
  }),
  clearNotifications: build.mutation({
    query: () => ({
      url: `/notifications/clear`,
      method: "POST",
    }),
    invalidatesTags: [{ type: "Notification", id: "UNREAD" }],
  }),
  deleteNotification: build.mutation({
    query: (payload) => ({
      url: `/notifications/${payload}`,
      method: "DELETE",
    }),
    invalidatesTags: [
      { type: notificationTag, id: "LIST" },
      { type: notificationTag, id: "UNREAD" },
    ],
  }),
  readNotification: build.mutation({
    query: (payload) => ({
      url: `/notifications/${payload}/read`,
      method: "POST",
    }),
    invalidatesTags: [{ type: notificationTag, id: "UNREAD" }],
  }),
});
