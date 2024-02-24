import React from "react";
import date from 'date-and-time';


export default function RelatedVideo({data}) {
  const originalDateString = data.createdAt;
  const originalDate = new Date(originalDateString);

  const day = originalDate.getUTCDate();
  const month = new Intl.DateTimeFormat('en-US', { month: 'short' }).format(originalDate);
  const year = originalDate.getUTCFullYear();
  
  const formattedDate = `${day} ${month} ${year}`;

  return (
    <div className="w-full flex flex-row gap-2 mb-4">
      <div className="relative w-[168px] h-[94px] flex-none duration-300 hover:scale-[1.03]">
        <a href={`/watch/${data._id}`} className=" w-full h-full ">
          <img src={`http://localhost:8000/api/videos/${data.thumbnailURL}`} className="object-cover w-full h-full rounded-lg" alt="video thumbnail" />
        </a>
        <p className="absolute right-2 bottom-2 bg-gray-900 text-gray-100 text-xs px-1 py">{data.duration.toFixed(2)}</p>
      </div>

      <div className="flex flex-col w-full">
        <a href="/">
          <p className="text-slate-900 text-sm font-semibold">{data.title}</p>
        </a>
        <a className="text-gray-400 text-xs mt-2 hover:text-gray-600" href="/">
          {data.name}
        </a>
        <p className="text-gray-400 text-xs mt-1">{data.views} views  . {formattedDate }</p>
      </div>
    </div>
  );
}
