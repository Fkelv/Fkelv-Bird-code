/* eslint-disable no-undef */
import React, { forwardRef, useRef, useState } from "react";
import TextareaAutosize from "react-textarea-autosize";
import { Link } from "react-router-dom";
import { BiImageAlt, BiVideo, CgMediaLive } from "../constant/icons";
import { useSelector } from "react-redux";
import { selectCurrentUser } from "../store/authSlice";
import { useForm } from "react-hook-form";
import { useCreatePostMutation, useGetUserQuery } from "../store";
import Loader from "../components/ui/Loader";
import { ToastContainer, toast } from "react-toastify";

const checkFileType = (file) => {
  const fileType = file.split(",")[0].split(";")[0].split("/")[0];
  if (fileType === "data:video") {
    return "video";
  }
  if (fileType === "data:image") {
    return "image";
  }
};
export const CreatePost = forwardRef(function CreatePost({ refetch }, ref) {
  const userId = useSelector(selectCurrentUser);
  const { data: profileData } = useGetUserQuery(userId);
  const [file, setFile] = useState("");
  const [video, setVideo] = useState("");
  const avatar = profileData?.avatar
    ? `${import.meta.env.VITE_API_URL}/${profileData?.avatar}`
    : "/assets/avatar.png";

  const inputRef = useRef(null);
  const [isInputEmpty, setIsInputEmpty] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
    reset,
    setError,
    formState: { errors },
  } = useForm();
  const [createPost, { isLoading, isSuccess, data: mutationData, isError }] =
    useCreatePostMutation();

  const onSubmit = async (data) => {
    const formData = new FormData();
    if (data.media) {
      formData.append("media", data.media[0]);
    }
    formData.append("content", data.content);
    const res = await createPost(formData);
    if (res.data) {
      toast.info(() => <CustomToastWithLink postId={res.data._id} />, {
        toastId: res.data._id,
        type: "success",
      });
      reset();
      setFile(null);
      refetch();
    }
    if (res?.error) {
      toast("Post creation failed. Kindly try again later", {
        toastId: "create-post",
        type: "error",
      });
    }
  };

  const handleImgfiles = (e) => {
    const selectedFile = e.target.files[0];

    setValue("media", e.target.files);
    if (!selectedFile) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const imageDataUrl = event.target.result;
      if (checkFileType(imageDataUrl) === "image") {
        setFile(imageDataUrl);
      }

      if (checkFileType(imageDataUrl) === "video") {
        const media = new Audio(reader.result);
        media.onloadedmetadata = function () {
          if (media.duration <= 120) {
            setVideo(imageDataUrl);
          } else {
            setError("media", {
              type: "custom",
              message: "Video file exceeds 2 minutes",
            });
          }
        };
        setVideo(imageDataUrl);
      }
    };
    reader.readAsDataURL(selectedFile);
  };

  const createRemoveMedia = (fileType) => () => {
    inputRef.current.files = null;
    if (fileType === "video") {
      setVideo(null);
    }
    if (fileType === "image") {
      setFile(null);
    }
  };

  return (
    <div className="border-b-[.5px] border-gray-300" ref={ref}>
      <div className="flex items-start gap-4 py-4 pt-3 px-4">
        <div className="h-10 w-10 overflow-hidden">
          <img
            className="h-full w-full object-cover rounded-full"
            src={avatar}
            alt="user"
          />
        </div>
        <form
          encType="multipart/form-data"
          className="flex-1 mt-[2px]"
          onSubmit={handleSubmit(onSubmit)}
        >
          <TextareaAutosize
            {...register("content")}
            className="w-full focus:outline-none outline-none py-2 px-2 placeholder:text-gray-500  font-regular"
            placeholder="What's on your mind?"
            minRows={1}
          />

          {errors.media && (
            <div className="bg-rose-300 px-1 py-0.5 rounded-md">
              <p className="text-sm text-rose-950">{errors.media.message}</p>
            </div>
          )}
          {file && (
            <div className="flex relative">
              <img src={file} alt="Uploaded Photo" className="w-full h-auto" />
              <button
                type="button"
                className="rounded-full py-1 px-2 absolute z-10 top-0.5 right-0.5 bg-zinc-700 text-white"
                onClick={createRemoveMedia("image")}
              >
                &#x2715;
              </button>
            </div>
          )}

          {video && (
            <div className="max-w-fit rounded-md relative">
              <video
                width="100%"
                height="auto"
                className="rounded-t-md"
                controls
              >
                <source src={video} type="video/mp4" />
              </video>
              <button
                type="button"
                onClick={createRemoveMedia("video")}
                className="rounded-full py-1 px-2 absolute z-10 top-0.5 right-0.5 bg-zinc-700 text-white"
              >
                &#x2715;
              </button>
            </div>
          )}

          <div className="flex items-center justify-between">
            <div className="flex items-center pt-3 -ml-2">
              <div className="w-[34px] h-[34px] grid place-content-center hover:bg-gray-100 rounded-full">
                <label htmlFor="media" className="cursor-pointer">
                  <BiImageAlt fontSize={22} />
                  <input
                    type="file"
                    id="media"
                    name="media"
                    accept="image/*,video/mp4"
                    ref={inputRef}
                    onChange={handleImgfiles}
                    className="opacity-0 hidden h-[.1px] w-[.1px]"
                  />
                </label>
              </div>
              <Link
                to="/studio/upload-video"
                className="w-[34px] h-[34px] grid place-content-center hover:bg-gray-100 rounded-full"
              >
                <BiVideo fontSize={23} />
              </Link>
              <Link
                to="/studio/go-live"
                className="w-[34px] h-[34px] grid place-content-center hover:bg-gray-100 rounded-full"
              >
                <CgMediaLive fontSize={19} />
              </Link>
            </div>
            <button
              className={`py-[6px] text-white font-semibold px-7 rounded-full ${
                isInputEmpty
                  ? "bg-gray-300 cursor-not-allowed"
                  : "bg-blue-600 hover:bg-blue-500"
              }`}
              type="submit"
            >
              {isLoading ? <Loader /> : <>Post</>}
            </button>
          </div>
        </form>

        <ToastContainer position="bottom-center" />
      </div>
    </div>
  );
});

const CustomToastWithLink = ({ postId }) => {
  return (
    <Link to={`/posts/${postId}`} className="">
      Post created.<span className="font-bold">View Here</span>
    </Link>
  );
};
