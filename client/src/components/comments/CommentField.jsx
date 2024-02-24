import React, { useRef, useState } from "react";
import Comments from "./Comments";
import { useSelector } from "react-redux";
import { selectCurrentUser } from "../../store/authSlice";
import { useCreateCommentMutation, useGetUserQuery } from "../../store";
import { useForm } from "react-hook-form";
import TextareaAutosize from "react-textarea-autosize";
import { BiImageAlt } from "react-icons/bi";
import Loader from "../ui/Loader";

export default function CommentField({ postId, refetch }) {
  const currentUserId = useSelector(selectCurrentUser);
  const { data: userProfile } = useGetUserQuery(currentUserId);
  const [createComment, { data, isLoading }] = useCreateCommentMutation();
  const [file, setFile] = useState("");
  const avatar = userProfile?.avatar
    ? `${import.meta.env.VITE_API_URL}/${userProfile?.avatar}`
    : "/assets/avatar.png";

  const inputRef = useRef(null);

  const { handleSubmit, setValue, reset, register } = useForm();

  const onSubmit = async (data) => {
    const formData = new FormData();
    if (data.media) {
      formData.append("media", data.media[0]);
    }
    formData.append("content", data.content);
    const sentData = { postId, formData };
    const response = await createComment(sentData);
    if (response.data) {
      reset();
      setFile(null);
      inputRef.current.value = null;
      refetch();
    }
  };
  const handleImgfiles = (e) => {
    const selectedFile = e.target.files[0];
    setValue("media", e.target.files);

    if (!selectedFile) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const imageDataUrl = event.target.result;
      setFile(imageDataUrl);
    };
    reader.readAsDataURL(selectedFile);
  };
  const handleRemovefile = () => {
    inputRef.current.files = null;
    setFile("");
  };
  return (
    <>
      <div className="py-2 border-t-[.5px] border-gray-300">
        <div className="flex items-start gap-3">
          <div className="basis-1/12">
            <img
              src={avatar}
              className="w-10 h-10 mt-[4.2px] rounded-full"
              alt="d"
            />
          </div>
          <form onSubmit={handleSubmit(onSubmit)} className="basis-11/12">
            <div className="flex flex-col gap-4 mt-[3px] rounded-xl">
              <div className="flex items-center">
                <div className="w-[34px] h-[34px] grid place-content-center hover:bg-gray-100 rounded-full">
                  <label
                    htmlFor="commentFile"
                    className="cursor-pointer relative"
                  >
                    <BiImageAlt fontSize={22} />
                    <input
                      type="file"
                      id="media"
                      name="media"
                      accept="image/*"
                      ref={inputRef}
                      onChange={handleImgfiles}
                      className="h-[34px] w-[34px] absolute z-10 top-0 opacity-0"
                    />
                  </label>
                </div>
                <TextareaAutosize
                  {...register("content")}
                  className="w-full focus:outline-none outline-none py-2 px-2 placeholder:text-gray-500  font-regular"
                  placeholder="What's on your mind?"
                  minRows={1}
                />
              </div>
              {file && (
                <div className="flex w-full relative">
                  <img
                    src={file}
                    alt="Uploaded Photo"
                    className="w-full h-auto"
                  />
                  <button
                    type="button"
                    className="rounded-full bg-sky-300 p-2 m-3 text-white absolute top-0 right-0"
                    onClick={handleRemovefile}
                  >
                    x
                  </button>
                </div>
              )}
              <div className="flex justify-end">
                <button
                  className={
                    "py-[6px] text-white font-semibold px-7 rounded-full bg-blue-600 hover:bg-blue-500"
                  }
                  type="submit"
                  // disabled={isInputEmpty}
                >
                  {isLoading ? <Loader /> : <>Reply</>}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </>
  );
}
