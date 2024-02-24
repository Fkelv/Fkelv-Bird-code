import React from "react";
import { useForm } from "react-hook-form";
import { Link } from "react-router-dom";
import { useSignInMutation } from "../store";
import { Input } from "../components/input/input";

export default function Login() {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm();
  const [login, {}] = useSignInMutation();

  const onSubmit = async (data) => {
    await login(data);
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    try {
      login(credentials);
    } catch (error) {
      console.log({ error });
    }
  };

  return (
    <div className="mx-auto mt-12 max-w-md">
      <header>
        <h2 className="text-[28px] font-medium mb-2">Sign in</h2>
        <p className="text-sm mb-5">
          Don't have an account?{" "}
          <Link
            className="text-blue-500 hover:underline decoration-blue-500"
            to="/auth/signup"
          >
            Sign up
          </Link>
        </p>
      </header>
      <form className="grid gap-y-2" onSubmit={handleSubmit(onSubmit)}>
        <label className="flex flex-col" htmlFor="email">
          <span className="text-sm mb-1 font-semibold">Email address</span>
          <input
            className="bg-gray-100 rounded-md outline-none px-3 py-2"
            type="email"
            placeholder="mohammah@gmail.com"
            {...register("email")}
          />
        </label>
        <label className="flex flex-col" htmlFor="password">
          <span className="text-sm mb-1 font-semibold">Password</span>
          <input
            className="bg-gray-100 rounded-md outline-none px-3 py-2"
            type="password"
            placeholder="Password"
            {...register("password")}
          />
        </label>
        <div className="py-3 flex items-center justify-between">
          <label
            htmlFor="checkbox"
            className="flex items-center gap-1 ml-[1px]"
          >
            <input type="checkbox" name="checkbox" id="checkbox" />
            <p className="text-xs">Remember me</p>
          </label>
          <Link
            to
            className="text-xs text-blue-500 hover:underline decoration-blue-500"
          >
            Forgot password?
          </Link>
        </div>

        <button
          // disabled={isLoading}
          type="submit"
          className=" hover:bg-blue-600 py-2 bg-blue-500 text-white rounded-md"
        >
          Sign in
        </button>
      </form>
    </div>
  );
}
