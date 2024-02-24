import { useForm } from "react-hook-form";
import { Input } from "../../components/input/input";
import { Loader } from "../../components/ui/Loader";
import { Link } from "react-router-dom";
import { useSignInMutation } from "../../store";

export const SignIn = () => {
  const { register, handleSubmit } = useForm();
  const [login, { isError, isLoading, error }] = useSignInMutation();

  const onSubmit = async (data) => {
    await login(data);
  };
  return (
    <main className="mx-auto mt-12 max-w-md">
      <div>
        <h2 className="text-[28px] font-medium mb-2">Sign in</h2>
        <p className="text-sm mb-5">
          Don't have an account?{" "}
          <Link
            className="text-blue-500 hover:underline decoration-blue-500"
            to="/auth/signup"
          >
            Sign Up
          </Link>
        </p>
        {isError && (
          <div className="bg-rose-300 p-4 mb-2">
            <p className="text-sm text-rose-950">{error?.data?.message}</p>
          </div>
        )}
        <form className="grid gap-y-2" onSubmit={handleSubmit(onSubmit)}>
          <Input
            label="Email Address"
            type="email"
            name="email"
            placeholder="email@gmail.com"
            register={register}
          />

          <Input
            label="Password"
            type="password"
            placeholder="Password"
            name="password"
            register={register}
          />
          <div className="py-3 flex items-center justify-between">
            <div className="flex items-center gap-1 ml-[1px]">
              <input type="checkbox" name="checkbox" id="checkbox" />
              <label htmlFor="checkbox" className="text-xs">
                Remember Me?
              </label>
            </div>
            <Link
              to="/auth/password/forget"
              className="text-xs text-blue-500 hover:underline decoration-blue-500"
            >
              Forgot password?
            </Link>
          </div>
          <button
            type="submit"
            className=" hover:bg-blue-600 py-2 bg-blue-500 text-white rounded-md"
          >
            {isLoading ? <Loader /> : <>Sign In</>}
          </button>
        </form>
      </div>
    </main>
  );
};
