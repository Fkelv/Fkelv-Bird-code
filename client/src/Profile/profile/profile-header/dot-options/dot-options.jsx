import { useState } from "react";
import { MdOutlineBlock, MdOutlineNotificationsOff } from "react-icons/md";
import { AiOutlineUndo } from "react-icons/ai";
import { toast } from "react-toastify";
import { Modal } from "../../../../components/modal/modal";
import {
  useBlockUserMutation,
  useMuteUserMutation,
  useUnblockUserMutation,
  useUnmuteUserMutation,
} from "../../../../store";

export function DotOptions({ userId, username, blockedStatus, mutedStatus }) {
  const [blockUser, {}] = useBlockUserMutation();
  const [unblockUser, {}] = useUnblockUserMutation();
  const [unmuteUser, {}] = useUnmuteUserMutation();
  const [muteUser, {}] = useMuteUserMutation();
  const [isModalOpen, setModalOpen] = useState(false);
  const [showButton, setShowButton] = useState(true);

  const openModal = () => {
    setModalOpen(true);
    setShowButton(false);
  };

  const closeModal = () => {
    setModalOpen(false);
  };

  const handleClick = async () => {
    const response = await blockUser(userId);
    if (response.data) {
      closeModal();
    }
  };

  const handleMute = async () => {
    const response = await muteUser(userId);
    if (response.data) {
      toast.success(`Successfully muted @${username}`, {
        toastId: `muted-${userId}`,
      });
      setShowButton(false);
    }
  };

  const handleUnmute = async () => {
    const response = await unmuteUser(userId);
    if (response.data) {
      toast.success(`Successfully unmuted @${username}`, {
        toastId: `unmuted-${userId}`,
      });
      setShowButton(false);
    }
  };

  const handleUnblock = async () => {
    const response = await unblockUser(userId);
    if (response.data) {
      toast.success(`Successfully unblocked @${username}`, {
        toastId: `unblocked-${userId}`,
      });
      setShowButton(false);
    }
  };
  return (
    <>
      <div className="absolute z-[5] top-[105%] min-w-[150px] right-0 flex-col  bg-white shadow-sm shadow-gray-300 opacity-1">
        {showButton && (
          <div className="w-max flex flex-col gap-2 rounded-sm px-2 py-[7px] min-w-full ">
            {blockedStatus ? (
              <button
                type="button"
                className="text-black text-sm hover:bg-gray-100"
                onClick={handleUnblock}
              >
                <div className="flex items-center">
                  <div className="mr-2">
                    <AiOutlineUndo fontSize={20} />
                  </div>
                  UnBlock @{username}
                </div>
              </button>
            ) : (
              <button
                type="button"
                className="text-black text-sm hover:bg-gray-100"
                onClick={openModal}
              >
                <div className="flex items-center">
                  <div className="mr-2">
                    <MdOutlineBlock fontSize={20} />
                  </div>
                  Block
                </div>
              </button>
            )}
            {mutedStatus ? (
              <button
                type="button"
                className="text-black text-sm hover:bg-gray-100"
                onClick={handleUnmute}
              >
                <div className="flex items-center">
                  <div className="mr-2">
                    <AiOutlineUndo fontSize={20} />
                  </div>
                  Unmute @{username}
                </div>
              </button>
            ) : (
              <button
                className="flex w-full gap-2 items-center hover:bg-gray-100"
                onClick={handleMute}
              >
                <MdOutlineNotificationsOff fontSize={20} />
                <span className="text-sm">Mute</span>
              </button>
            )}
          </div>
        )}
      </div>
      <Modal isModalOpen={isModalOpen} closeModal={closeModal}>
        <div className="flex flex-col gap-4 max-w-[300px]">
          <h1 className="text-2xl font-bold">Block @{username}</h1>
          <p className="text-gray-600">
            They will not be able to follow you or view your posts, and you will
            not see posts or notifications from @{username}.
          </p>
          <div className="flex flex-col gap-4">
            <button
              className="bg-red-600 rounded-lg text-white w-full py-2 px-1 font-bold"
              onClick={handleClick}
            >
              Block
            </button>
            <button
              className="border-2 rounded-lg w-full py-2 px-1 font-bold"
              onClick={closeModal}
            >
              Cancel
            </button>
          </div>
        </div>
      </Modal>
    </>
  );
}
