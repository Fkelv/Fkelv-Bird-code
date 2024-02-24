import { useRef } from "react";
import { useUnblockUserMutation } from "../../../store";

export function BlockButton({ userId }) {
  const [unblock] = useUnblockUserMutation();
  const btnRef = useRef();

  const handleMouseEnter = () => {
    btnRef.current.innerText = "Unblock";
  };

  const handleMouseLeave = () => {
    btnRef.current.innerText = "Blocked";
  };

  const handleClick = async () => {
    await unblock(userId);
  };
  return (
    <button
      className="bg-red-600 text-white py-1.5 px-4 rounded-full font-bold"
      onClick={handleClick}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      ref={btnRef}
      type="button"
    >
      Blocked
    </button>
  );
}
