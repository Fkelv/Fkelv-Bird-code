import { useForm } from "react-hook-form";
import { Modal } from "../../components/modal/modal";
import { useUpdateUserMutation } from "../../store";
import { Loader } from "../../components/ui/Loader";

export const PreferencesModal = ({
  userId,
  isModalOpen,
  setModalOpen,
  homePreference,
}) => {
  const [updateUser, { isSuccess, isLoading }] = useUpdateUserMutation();
  const { register, handleSubmit } = useForm({
    defaultValues: {
      homePreference: homePreference,
    },
  });

  const onSubmit = async (data) => {
    await updateUser({
      userId,
      ...data,
    });
  };
  return (
    <Modal isModalOpen={isModalOpen} closeModal={() => setModalOpen(false)}>
      <div className="flex min-w-[600px] gap-2 flex-col">
        <h3 className="font-bold text-xl">Timeline Settings</h3>
        <form className="flex flex-col gap-2" onSubmit={handleSubmit(onSubmit)}>
          <div className="flex gap-4">
            <label className="flex gap-2 items-center">
              <input
                type="radio"
                value={"forYou"}
                {...register("homePreference")}
              />
              For You
            </label>
            <label className="flex gap-2 items-center">
              <input
                type="radio"
                value={"following"}
                {...register("homePreference")}
              />
              Following
            </label>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className="p-2 rounded-lg text-white bg-blue-500"
            >
              {isLoading ? <Loader /> : <>Save Preference</>}
            </button>
          </div>
        </form>
      </div>
    </Modal>
  );
};
