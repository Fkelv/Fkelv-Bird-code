import React from "react";
import RelatedVideosList from "../../components/Watch/SingleVdeoPage/RelatedVideosList";
import { useGetVideoQuery, useRefreshAccessTokenQuery } from "../../store";
import { useParams } from "react-router-dom";
import { getTimeAgo } from "../../libraries/getTimeAgo";
import { LikeUnlike } from "../../components/Watch/SingleVdeoPage/LikeUnlike";

export function SingleVideo() {
  const { id } = useParams();
  const {} = useRefreshAccessTokenQuery();
  const { data, isLoading } = useGetVideoQuery(id);
  const videoURL = `${import.meta.env.VITE_API_URL}/${data?.videoURL}`;
  const avatarURL = data?.user?.avatar
    ? `${import.meta.env.VITE_API_URL}/${data?.user?.avatar}`
    : "/assets/avatar.png";

  return (
    <section className="pt-6 pb-20">
      <div className="mx-auto max-w-7xl px-2 pb-20 min-h-[400px]">
        <div className="grid grid-cols-3 gap-2 lg:gap-8">
          <div className="col-span-full w-full space-y-4 lg:col-span-2">
            {!isLoading && (
              <video width="100%" controls>
                <source src={videoURL} type="video/mp4" />
              </video>
            )}
            <div>
              <h1 className="text-xl font-semibold tracking-tight mb-4">
                {data?.title}
              </h1>
              <div className="pb-4 flex items-center justify-between border-b">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-10 w-10 overflow-hidden">
                      <img
                        className="w-full h-full object-cover rounded-full"
                        src={avatarURL}
                        alt="user"
                      />
                    </div>
                    <p className="font-semibold">{data?.user.name}</p>
                  </div>
                </div>
                <LikeUnlike />
              </div>
              <div className="mt-4">
                <p className="text-sm font-semibold mb-2">
                  {data?.views} views{" "}
                  <span className="ml-2">{getTimeAgo(data?.uploadDate)}</span>
                </p>
                <p className="text-sm ">{data?.description}</p>
              </div>
            </div>
            <div className="flex border-y-[0.5px]">
              <div className="h-28 w-full flex justify-center items-center">
                <p>No comments.</p>
              </div>
            </div>
          </div>

          <RelatedVideosList id={id}/>
        </div>
      </div>
    </section>
  );
}
