import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ToastContainer, toast } from "react-toastify";
import {
  AiOutlineDelete,
  AiOutlineEye,
  FiMoreHorizontal,
} from "../../constant/icons";
import { useDeleteNotificationMutation } from "../../store";
import { Loader } from "../../components/ui/Loader";

export default function DotsOptions({ notifId }) {
  const [showMore, setShowMore] = useState(false);

  const [deleteNotification, { isSuccess, isLoading }] =
    useDeleteNotificationMutation();
  const handleMore = () => {
    setShowMore(() => !showMore);
  };

  const handleDelete = async () => {
    const response = await deleteNotification(notifId);
    console.log(response);
    if (response.data) {
      toast("Notification deleted.", {
        toastId: `delete-${notifId}`,
        type: "success",
      });
    }
  };

  return (
    <>
      <div className="flex mt-[-10px] group-hover:visible ml-auto invisible items-center gap-2 group relative cursor-pointer">
        <button
          className="ml-auto p-2 hover:bg-gray-100 grid place-content-center rounded-full"
          onClick={handleMore}
        >
          <FiMoreHorizontal className="rotate-90" fontSize={23} />
        </button>
        <div
          className={`absolute z-[5] top-full min-w-[150px] right-0 ${
            showMore ? "flex opacity-100" : "hidden opacity-0"
          } flex-col  bg-white shadow-lg shadow-gray-300 opacity-1`}
        >
          <div className="w-max rounded-sm hover:bg-gray-100 px-4 py-3 min-w-full ">
            <button className="text-black text-sm" onClick={handleDelete}>
              <div className="flex items-center text-[17px]">
                <div className="mr-2">
                  {isLoading ? <Loader /> : <AiOutlineDelete fontSize={22} />}
                </div>
                Delete this notification
              </div>
            </button>
          </div>
          <div className="w-max rounded-sm hover:bg-gray-100 px-4 py-3 min-w-full ">
            <Link to className="text-black text-sm">
              <div className="flex items-center text-[17px]">
                <div className="mr-2">
                  <AiOutlineEye fontSize={22} />
                </div>
                Turn of all from{" "}
                <span className="font-medium ml-2"> Jahid hasan</span>
              </div>
            </Link>
          </div>
        </div>
      </div>
      <ToastContainer position="top-center" />
    </>
  );
}
