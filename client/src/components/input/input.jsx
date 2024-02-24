import React from "react";

export const Input = ({ label, name, register, ...others }) => {
  return (
    <div className="flex flex-col">
      <label htmlFor={name} className="text-sm mb-1 font-semibold">
        {label}
      </label>
      <input
        className="bg-gray-100 rounded-md outline-none px-3 py-2"
        id={name}
        {...register(name)}
        {...others}
      />
    </div>
  );
};

export const Textarea = ({ label, name, register, ...others }) => {
  return (
    <div className="flex flex-col">
      <label htmlFor={name} className="text-sm mb-1 font-semibold">
        {label}
      </label>
      <textarea
        rows="3"
        placeholder="What's on your mind"
        className="focus rounded-md resize-none py-2 bg-gray-100 placeholder:text-black border-1 border-black px-3"
        {...register(name)}
        {...others}
      />
    </div>
  );
};
