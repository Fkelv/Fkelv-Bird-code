import { useRef, useState } from "react";
import { Scrollbars } from "react-custom-scrollbars-2";
import { useForm } from "react-hook-form";
import { ToastContainer, toast } from "react-toastify";
import { Loader } from "../../components/ui/Loader";
import { BiImageAlt, BiVideo } from "react-icons/bi";
import { useCreateVideoMutation } from "../../store";
import { Link } from "react-router-dom";

export const UploadVideo = () => {
  const { register, handleSubmit, setValue, reset } = useForm();
  const [thumbnail, setThumbnail] = useState(null);
  const [video, setVideo] = useState(null);
  const videoInputRef = useRef(null);
  const inputRef = useRef(null);
  const [createVideo, { data, isLoading }] = useCreateVideoMutation();

  const handleThumbnailChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      setValue("thumbnail", selectedFile);
      const reader = new FileReader();

      reader.onload = (event) => {
        const imageDataUrl = event.target.result;
        setThumbnail(imageDataUrl);
      };

      reader.readAsDataURL(selectedFile);
    }
  };

  const handleVideoChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      setValue("video", selectedFile);
      const reader = new FileReader();

      reader.onload = (event) => {
        const videoDataUrl = event.target.result;
        setVideo(videoDataUrl);
        const media = new Audio(reader.result);
        media.onloadedmetadata = () => {
          setValue("duration", media.duration);
        };
      };

      reader.readAsDataURL(selectedFile);
    }
  };

  const handleVideoClick = () => {
    if (videoInputRef.current) {
      videoInputRef.current.click();
    }
  };

  const handleThumbnailClick = () => {
    if (inputRef.current) {
      inputRef.current.click();
    }
  };

  const createRemoveMedia = (fileType) => () => {
    if (fileType === "image") {
      inputRef.current.value = null;
      setThumbnail(null);
      setValue("thumbnail", null);
    }

    if (fileType === "video") {
      videoInputRef.current.value = null;
      setVideo(null);
      setValue("video", null);
    }
  };
  const onSubmit = async (data) => {
    const formData = new FormData();

    if (data.thumbnail) {
      formData.append("thumbnail", data.thumbnail);
    }

    if (data.video) {
      formData.append("video", data.video);
    }

    if (data.duration) {
      formData.append("duration", data.duration);
    }
    formData.append("title", data.title);
    formData.append("description", data.description);
    formData.append("visibility", data.visibility);
    formData.append("category", data.category);
    const res = await createVideo(formData);
    if (res.data) {
      toast.info(() => <CustomToastWithLink id={res.data._id} />, {
        toastId: res.data._id,
        type: "success",
      });
      reset();
      setThumbnail(null);
      setVideo(null);
    }
    if (res?.error) {
      toast("Video upload failed. Kindly try again later", {
        toastId: "upload-video",
        type: "error",
      });
    }
  };
  return (
    <Scrollbars style={{ width: "100%", height: "80vh" }}>
      <div className="pr-5 w-[60%]">
        <h2 className="text-3xl font-semibold">Upload Video</h2>
        <form
          encType="multipart/form-data"
          onSubmit={handleSubmit(onSubmit)}
          className="grid grid-cols-2 gap-2 border-b-[.5px] pb-4 pl-2 mt-2"
        >
          <div className="p-4 rounded-md hover:shadow-lg hover:shadow-gray-100 shadow-sm shadow-gray-100 h-[140px] col-span-1 w-[75%] mx-auto">
            <label
              htmlFor="file"
              className="cursor-pointer flex flex-col items-center border-2 border-dashed border-blue-300 h-full rounded-md"
            >
              <button type="button" onClick={handleVideoClick} className="mt-7">
                <BiVideo fontSize={25} className="mx-auto text-blue-400" />
                <p className="font-semibold text-sm text-blue-400">
                  Upload Video
                </p>
              </button>
              <input
                id="video"
                type="file"
                className="opacity-0 h-[.1px] w-[.1px]"
                accept="video/mp4,video/x-m4v,video/*"
                ref={videoInputRef}
                onChange={handleVideoChange}
                multiple={false}
              />
            </label>
          </div>
          <div className="rounded-md col-span-1 -mt-2">
            {video && (
              <div className="border p-2 max-w-fit rounded-md mt-2 relative">
                <video
                  width="180px"
                  height="100%"
                  className="rounded-t-md"
                  controls
                >
                  <source src={video} type="video/mp4" />
                </video>
                <p className="text-xs font-semibold pt-2 px-2">Preview video</p>

                <button
                  type="submit"
                  className="rounded-full py-1 px-2 absolute z-10 top-0.5 right-0.5 bg-zinc-700 text-white "
                  onClick={createRemoveMedia("video")}
                >
                  &#x2715;
                </button>
              </div>
            )}
          </div>
          <div className="p-4 rounded-md hover:shadow-lg hover:shadow-gray-100 shadow-sm shadow-gray-100 h-[140px] col-span-1 w-[75%] mx-auto">
            <label
              htmlFor="file"
              className="cursor-pointer flex flex-col items-center border-2 border-dashed border-blue-300 h-full rounded-md"
            >
              <button
                type="button"
                onClick={handleThumbnailClick}
                className="mt-8"
              >
                <BiImageAlt fontSize={22} className="mx-auto text-blue-400" />
                <p className="font-semibold text-xs text-blue-400">
                  Upload Thumbnail
                </p>
              </button>
              <input
                type="file"
                id="thumbnail"
                name="thumbnail"
                accept="image/*"
                className="opacity-0 h-[10px] w-[10px]"
                onChange={handleThumbnailChange}
                ref={inputRef}
                multiple={false}
              />
            </label>
          </div>
          <div className="w-full h-full">
            {thumbnail && (
              <div className="flex relative w-[180px] h-4/5">
                <img
                  src={thumbnail}
                  alt=""
                  className="w-full h-full object-cover"
                />
                <button
                  type="button"
                  className="rounded-full py-1 px-2 absolute z-10 top-0.5 right-0.5 bg-zinc-700 text-white"
                  onClick={createRemoveMedia("image")}
                >
                  &#x2715;
                </button>
              </div>
            )}
          </div>
          <label htmlFor="title" className="flex flex-col col-span-2">
            <span className="mb-2 text-lg font-semibold">Title</span>
            <input
              className="bg-gray-100 rounded-md px-3 py-2"
              placeholder="Add video title"
              type="text"
              {...register("title")}
            />
          </label>
          <label htmlFor="visibility" className="text-sm col-span-1">
            <span className="text-sm font-semibold">Visibility</span>
            <select
              id="visibility"
              className="bg-gray-100 mt-2 w-full outline-none block px-2 py-1 font-medium text-gray-500"
              {...register("visibility")}
              defaultValue={"public"}
            >
              <option className="bg-gray-100" value="private">
                Private
              </option>
              <option className="bg-gray-100" value="public">
                Public
              </option>
            </select>
          </label>
          <label htmlFor="catagory" className="text-sm col-span-1 mb-3">
            <span className="text-sm font-semibold">Category</span>
            <select
              className="bg-gray-100 mt-2 w-full outline-none block px-2 py-1 font-medium text-gray-500"
              {...register("category")}
              defaultValue={"people & blog"}
            >
              <option className="bg-gray-100" value={"people & blog"}>
                People & Blog
              </option>
              <option className="bg-gray-100" value="programming">
                Programming
              </option>
            </select>
          </label>
          <label htmlFor="id" className="flex flex-col col-span-2">
            <span className="mb-2 text-sm font-semibold">Description</span>
            <textarea
              className="bg-gray-100 rounded-md px-3 py-2 resize-none"
              placeholder="Add video description"
              type="text"
              {...register("description")}
            />
          </label>
          <button
            className="py-[6px] max-w-fit text-white font-semibold px-7 rounded-full hover:bg-blue-600 bg-blue-500"
            type="submit"
          >
            {isLoading ? <Loader /> : <>Post</>}
          </button>
        </form>
      </div>
      <ToastContainer position="bottom-center" />
    </Scrollbars>
  );
};

const CustomToastWithLink = ({ id }) => {
  return (
    <Link to={`/watch/${id}`} className="">
      Video Uploaded.<span className="font-bold">View Here</span>
    </Link>
  );
};
