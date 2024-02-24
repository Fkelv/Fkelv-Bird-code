import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  AiOutlineDelete,
  AiOutlineEye,
  AiOutlinePushpin,
  MdOutlineBlock,
  MdOutlineNotificationsOff,
  MdOutlineReportProblem,
  RiUserUnfollowLine,
  TbReportOff,
} from "../constant/icons";
import { useDeletePostMutation } from "../store";
import { ToastContainer, toast } from "react-toastify";
import { Modal } from "../components/modal/modal";

export const DotsOptions = ({
  showMore,
  isOwner,
  username,
  postId,
  closePopup,
  refetch,
}) => {
  const [deletePost, { isSuccess }] = useDeletePostMutation();
  const [isModalOpen, setModalOpen] = useState(false);

  const openModal = () => {
    setModalOpen(true);
    closePopup();
  };

  const closeModal = () => {
    setModalOpen(false);
  };
  const handleOpenDelete = async () => {
    openModal();
  };

  const handleDelete = async () => {
    const response = await deletePost(postId);

    if (response.data) {
      setModalOpen(false);
      toast("Post deleted.", { toastId: `delete-${postId}`, type: "success" });
      refetch();
    }
  };

  return (
    <>
      <div
        className={`absolute z-[5] top-full min-w-[150px] right-0 ${
          showMore ? "flex opacity-100" : "hidden opacity-0"
        } flex-col  bg-white shadow-sm shadow-gray-300 opacity-1 p-2`}
      >
        {isOwner ? (
          <>
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2">
                    <AiOutlinePushpin fontSize={22} />
                  </div>
                  Pin
                </div>
              </button>
            </div>
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button onClick={handleOpenDelete} className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2" onClick={handleDelete}>
                    <AiOutlineDelete fontSize={22} />
                  </div>
                  Delete
                </div>
              </button>
            </div>
            {/* {location.pathname === `/users/${loggedInUser}` && ( */}
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2">
                    <AiOutlineEye fontSize={22} />
                  </div>
                  Who can reply?
                </div>
              </button>
            </div>
            {/* )} */}
          </>
        ) : (
          <>
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2">
                    <MdOutlineNotificationsOff fontSize={22} />
                  </div>
                  Mute
                </div>
              </button>
            </div>
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2">
                    <MdOutlineBlock fontSize={20} />
                  </div>
                  Block
                </div>
              </button>
            </div>
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2">
                    <RiUserUnfollowLine fontSize={20} />
                  </div>
                  Follow {username}
                </div>
              </button>
            </div>
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2">
                    <TbReportOff fontSize={20} />
                  </div>
                  Not interested in this Post
                </div>
              </button>
            </div>
            <div className="w-max rounded-sm hover:bg-gray-100 px-2 py-[7px] min-w-full ">
              <button className="text-black text-sm">
                <div className="flex items-center">
                  <div className="mr-2">
                    <MdOutlineReportProblem fontSize={20} />
                  </div>
                  Report Post
                </div>
              </button>
            </div>
          </>
        )}
      </div>

      <Modal isModalOpen={isModalOpen} closeModal={closeModal}>
        <div className="flex flex-col gap-2">
          <h1 className="text-lg font-bold">Delete Post</h1>
          <p>Are you sure you want to delete this post?</p>
          <div className="flex flex-col gap-2">
            <button
              className="bg-red-700 rounded-lg text-white w-full py-px font-bold"
              onClick={handleDelete}
            >
              Delete
            </button>
            <button
              className="border-2 rounded-lg w-full py-px font-bold"
              onClick={closeModal}
            >
              Cancel
            </button>
          </div>
        </div>
      </Modal>
    </>
  );
};
