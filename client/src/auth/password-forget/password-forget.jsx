import { useForm } from "react-hook-form";
import { Input } from "../../components/input/input";
import { Link } from "react-router-dom";
import { useForgetPasswordMutation } from "../../store";

export const PasswordForget = () => {
  const { register, handleSubmit } = useForm();
  const [forgetPassword, { isSuccess, isError }] = useForgetPasswordMutation();
  const onSubmit = async (data) => {
    await forgetPassword(data);
  };

  return (
    <main className="mx-auto mt-12 max-w-md">
      <div className="flex flex-col gap-5">
        <h2 className="text-[28px] font-medium mb-2">Forgot your Password?</h2>
        <p className="text-sm mb-5">
          Go back to{" "}
          <Link
            className="text-blue-500 hover:underline decoration-blue-500"
            to="/auth/signin"
          >
            Sign in?
          </Link>
        </p>
        {isError ||
          (isSuccess && (
            <div className="bg-lime-200 p-4">
              <p className="text-sm text-lime-700">
                Check your email for reset password link
              </p>
            </div>
          ))}
        <form className="flex flex-col gap-2" onSubmit={handleSubmit(onSubmit)}>
          <Input
            label="Email Address"
            type="email"
            name="email"
            placeholder="email@gmail.com"
            register={register}
          />
          <button
            type="submit"
            className=" hover:bg-blue-600 py-2 bg-blue-500 text-white rounded-md"
          >
            Send Reset Password Email
          </button>
        </form>
      </div>
    </main>
  );
};
