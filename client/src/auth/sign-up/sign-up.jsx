import { useForm } from "react-hook-form";
import { Link } from "react-router-dom";
import { Input } from "../../components/input/input";
import { useSignUpMutation } from "../../store";
import Loader from "../../components/ui/Loader";

export const SignUp = () => {
  const { register, handleSubmit } = useForm();
  const [signup, { isError, error, isLoading }] = useSignUpMutation();
  const onSubmit = async (data) => {
    await signup(data);
  };
  return (
    <main className="mx-auto mt-12 max-w-md">
      {JSON.stringify(error)}
      <div>
        <h2 className="text-[28px] font-medium mb-2">Sign up</h2>
        <p className="text-sm mb-5">
          Already have an account ?{" "}
          <Link
            className="text-blue-500 hover:underline decoration-blue-500"
            to="/auth/signin"
          >
            Sign in
          </Link>
        </p>
        {isError && (
          <div className="bg-rose-300 p-4 mb-2">
            <p className="text-sm text-rose-950">{error.data.message}</p>
          </div>
        )}
        <form className="grid gap-y-2" onSubmit={handleSubmit(onSubmit)}>
          <Input
            label="Full Name"
            type="text"
            name="fullName"
            placeholder="Full Name"
            register={register}
          />
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
            {isLoading ? <Loader /> : <> Sign up</>}
          </button>
        </form>
      </div>
    </main>
  );
};
