import React, { useEffect } from "react";
import { MdModeEditOutline } from "../constant/icons";
import { useForm } from "react-hook-form";
import {
  useGetUserQuery,
  useUpdateUserMutation,
  useUploadFileMutation,
} from "../store";
import { selectCurrentUser } from "../store/authSlice";
import { useSelector } from "react-redux";
import { Input, Textarea } from "../components/input/input";
import { Loader } from "../components/ui/Loader";
import { ToastContainer, toast } from "react-toastify";

export default function EditProfile() {
  const userId = useSelector(selectCurrentUser);
  const { data: profileData, isLoading: userLoading } = useGetUserQuery(
    userId,
    {
      skip: userId === null,
    }
  );
  const [uploadFile, _] = useUploadFileMutation();
  const [updateUser, { data: updatedUser, isLoading, isSuccess }] =
    useUpdateUserMutation();
  const { register, handleSubmit, reset } = useForm();
  useEffect(() => {
    reset({
      name: profileData?.name,
      profileLink: profileData?.profileLink,
      username: profileData?.username,
      bio: profileData?.bio,
    });
  }, [reset, profileData]);

  const handleUpdateAvatar = async (event) => {
    if (event.target.files) {
      const file = event.target.files[0];
      const formData = new FormData();
      formData.append("files", file);
      const data = await uploadFile(formData).unwrap();
      await updateUser({
        userId,
        avatar: data.files[0].url,
      });
    }
  };

  const onSubmit = async (data) => {
    await updateUser({
      userId,
      ...data,
    });
  };
  const avatar = `${import.meta.env.VITE_API_URL}/${profileData?.avatar}`;

  if (isSuccess) {
    toast.success("Profile Updated", { toastId: `profile-updated-${userId}` });
  }

  return (
    <div className="bg-white px-5 py-5">
      <form onSubmit={handleSubmit(onSubmit)}>
        {/* change profile and cover picture */}
        <div className="flex h-32 items-center relative overflow-hidden justify-center py-3 border-b-[.5px] mb-4">
          <img className="absolute z-1" src="./assets/2.jpg" alt="cover" />
          <img
            className="h-24 w-24 z-[2] absolute rounded-full"
            src={avatar}
            alt="user"
          />
          <div className="absolute z-20 bottom-[17px] ml-[71px]">
            <button
              type="button"
              className="py-2 px-2 rounded-full hover:opacity-40 bg-black opacity-60 text-white"
            >
              <label htmlFor="file" className="cursor-pointer">
                <MdModeEditOutline fontSize={16} />
                <input
                  type="file"
                  id="file"
                  accept="image/*"
                  className="opacity-0 hidden h-[.1px] w-[.1px]"
                  onChange={handleUpdateAvatar}
                />
              </label>
            </button>
          </div>
          <div>
            <button
              type="button"
              className="py-2 px-2 absolute top-2 right-2 rounded-full hover:opacity-40 bg-black opacity-60 text-white"
            >
              <label htmlFor="file" className="cursor-pointer">
                <MdModeEditOutline fontSize={16} />
                <input
                  type="file"
                  id="file"
                  accept="image/*"
                  className="opacity-0 hidden h-[.1px] w-[.1px]"
                />
              </label>
            </button>
          </div>
        </div>
        {/* change others field */}
        <div className="grid grid-cols-2 gap-2">
          <div className="flex flex-col col-span-2">
            <Input
              register={register}
              name="name"
              label="Full Name"
              placeholder="Full Name"
            />
          </div>
          <div className="flex flex-col col-span-2">
            <Input
              register={register}
              name="profileLink"
              label="Website"
              placeholder="testlink.com"
            />
          </div>
          <div className="flex flex-col col-span-2">
            <Input
              register={register}
              name="username"
              label="Username"
              placeholder="username"
            />
          </div>

          <div className="flex flex-col col-span-2">
            <Textarea
              register={register}
              name="bio"
              label="Update Bio"
              place="What's on your mind?"
            />
          </div>
          <button
            type="submit"
            className="col-span-2 hover:bg-blue-600 py-2 bg-blue-500 text-white rounded-md"
          >
            {isLoading ? <Loader /> : <>Save</>}
          </button>
        </div>
      </form>

      <ToastContainer />
    </div>
  );
}
