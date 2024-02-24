/* eslint-disable no-unused-vars */
import React from "react";
import { useForm } from "react-hook-form";
import { Link } from "react-router-dom";
import { useSignUpMutation } from "../store";

export default function Register() {
  const { register, handleSubmit } = useForm();
  const [signup, _] = useSignUpMutation();
  const onSubmit = async (data) => {
    await signup(data);
  };

  return (
    <div className="mx-auto mt-12 max-w-md">
      <header>
        <h2 className="text-[28px] font-medium mb-2">
          Sign up with your email
        </h2>
        <p className="text-sm mb-5">
          Already have an account?{" "}
          <Link
            className="text-blue-500 hover:underline decoration-blue-500"
            to="/login"
          >
            Sign in
          </Link>
        </p>
      </header>
      <form
        className="grid gap-y-2"
        noValidate
        onSubmit={handleSubmit(onSubmit)}
      >
        <label className="flex flex-col" htmlFor="fullName">
          <span className="text-sm mb-1 font-semibold">Full Name</span>
          <input
            autoComplete="off"
            className="bg-gray-100 rounded-md outline-none px-3 py-2"
            type="text"
            placeholder="Mohammah Ali"
            {...register("fullName")}
          />
        </label>
        <label className="flex flex-col" htmlFor="email">
          <span className="text-sm mb-1 font-semibold">Email address</span>
          <input
            autoComplete="off"
            className="bg-gray-100 rounded-md outline-none px-3 py-2"
            type="email"
            placeholder="mohammah@gmail.com"
            {...register("email")}
          />
        </label>
        <label className="flex flex-col" htmlFor="password">
          <span className="text-sm mb-1 font-semibold">Password</span>
          <input
            autoComplete="off"
            className="bg-gray-100 rounded-md outline-none px-3 py-2"
            type="password"
            placeholder="Password"
            {...register("password")}
          />
        </label>
        <label
          htmlFor="checkbox"
          className="flex items-center gap-1 py-4 ml-[1px]"
        >
          <input type="checkbox" name="checkbox" id="checkbox" />
          <p className="text-xs">
            I agree to the{" "}
            <Link
              to
              className="text-blue-500 hover:underline decoration-blue-500"
            >
              Terms of Service
            </Link>{" "}
            and{" "}
            <Link
              to
              className="text-blue-500 hover:underline decoration-blue-500"
            >
              Privacy Policy
            </Link>
          </p>
        </label>
        <button
          type="submit"
          className=" hover:bg-blue-600 py-2 bg-blue-500 text-white rounded-md"
        >
          Sign up
        </button>
      </form>
    </div>
  );
}
