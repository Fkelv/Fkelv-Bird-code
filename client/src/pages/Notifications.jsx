import React, { useEffect } from "react";
import { SingleNotification } from "../components/notifications/SingleNotification";
import { BsCheckAll } from "../constant/icons";
import {
  useClearNotificationsMutation,
  useGetNotificationsQuery,
} from "../store";

export const Notifications = () => {
  const { data } = useGetNotificationsQuery();
  const [clearNotifications] = useClearNotificationsMutation();

  useEffect(() => {
    clearNotifications();
  }, []);
  return (
    <div className="max-w-[600px] mx-auto">
      <div className="flex items-center justify-between px-6 py-3 border-b">
        <p className="font-medium text-xl">All notifications</p>
      </div>
      <div>
        {data?.map((notification) => (
          <SingleNotification
            notification={notification}
            key={notification._id}
          />
        ))}
      </div>
    </div>
  );
};
