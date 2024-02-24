import { useState } from "react";
import { AiOutlineRetweet } from "react-icons/ai";
import { useRetweetPostMutation, useUnRetweetPostMutation } from "../../store";

export const RetweetPost = ({ retweetStatus, postRetweetNumber, postId }) => {
  const [isRetweet, setIsretweet] = useState(retweetStatus);
  const [retweetNumber, setRetweetNumber] = useState(postRetweetNumber);
  const color = isRetweet ? "green" : "gray";

  const [retweet, { isError: retweetError }] = useRetweetPostMutation();
  const [unretweet, { isError }] = useUnRetweetPostMutation();
  const handleClick = async () => {
    if (isRetweet) {
      await unretweet(postId);
      setRetweetNumber((prev) => prev - 1);
      setIsretweet(false);
    } else {
      await retweet(postId);
      setRetweetNumber((prev) => prev + 1);
      setIsretweet(true);
    }
  };

  return (
    <div className="flex items-center gap-2 group cursor-pointer">
      <div className="h-8 w-8 grid place-content-center rounded-full">
        {isRetweet ? (
          <AiOutlineRetweet
            fontSize={18}
            fontWeight={900}
            className={`text-green-500 transition-none group-hover:text-green-500`}
            onClick={handleClick}
          />
        ) : (
          <AiOutlineRetweet
            fontSize={18}
            fontWeight={900}
            className={`text-gray-900 transition-none group-hover:text-gray-500`}
            onClick={handleClick}
          />
        )}
      </div>
      {retweetNumber > 0 && (
        <p className={`mt-[-2px] transition-none text-${color}-950`}>
          {retweetNumber}
        </p>
      )}
    </div>
  );
};
