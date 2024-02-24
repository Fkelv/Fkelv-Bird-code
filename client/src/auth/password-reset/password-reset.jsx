import { useForm } from "react-hook-form";
import { useNavigate, useParams } from "react-router-dom";
import { Input } from "../../components/input/input";
import { useResetPasswordMutation } from "../../store";

export const PasswordReset = () => {
  const { token } = useParams();
  const navigate = useNavigate();
  const { register, handleSubmit } = useForm();
  const [resetPassword, { isError }] = useResetPasswordMutation();
  const onSubmit = async (data) => {
    await resetPassword({ token, ...data });
    if (data) {
      navigate("/auth/signin");
    }
  };
  return (
    <main className="mx-auto mt-12 max-w-md">
      <div className="flex flex-col gap-5">
        <h2 className="text-[28px] font-medium mb-2">New Password</h2>
        {isError && (
          <div className="bg-red-300 p-4">
            <p className="text-sm text-red-700">Token has expired</p>
          </div>
        )}
        <form className="flex flex-col gap-2" onSubmit={handleSubmit(onSubmit)}>
          <Input
            label="New Password"
            type="password"
            name="password"
            placeholder="password"
            register={register}
          />
          <button
            type="submit"
            className=" hover:bg-blue-600 py-2 bg-blue-500 text-white rounded-md"
          >
            Reset Password
          </button>
        </form>
      </div>
    </main>
  );
};
