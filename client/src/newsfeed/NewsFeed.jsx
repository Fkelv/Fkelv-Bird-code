import { useEffect, useState } from "react";
import { IoMdSettings } from "react-icons/io";
import { CreatePost } from "./CreatePost";
import { VideosComponent } from "./VideosComponent";
import { PostSection } from "./PostSection";
import { useFollowingFeedQuery, useGetUserQuery, useGetUserVideosQuery } from "../store";
import { PreferencesModal } from "./preferences-modal/preferences-modal";
import { useSelector } from "react-redux";
import { selectCurrentUser } from "../store/authSlice";
import Loader from "../components/ui/Loader";

export const NewsFeed = () => {
  const userId = useSelector(selectCurrentUser);
  console.log(userId)
  const { data, isLoading: userLoading } = useGetUserQuery(userId);
  const [videos, setvideos] = useState([])
  const [activeTab, setActiveTab] = useState(data?.homePreference || "forYou");
  const [isModalOpen, setModal] = useState(false);
  const { data: feedData, isLoading, refetch } = useFollowingFeedQuery();
  const renderedPosts = feedData || [];
  // const Get =async()=>{
  //   const datavideo = await fetch(`http://localhost:8000/api/videos/users/${userId}`)
  //   const vid = await datavideo.json()
  //   setvideos(vid)
  // }
  // useEffect(() => {
  //   setActiveTab(data?.homePreference);
  //   Get()
  // }, [data]);

  return (
    <main className="max-w-[700px] mx-auto border-x border-gray-200 z-0 relative">
      <div className="flex items-center sticky bg-w z-10 top-[73px] border-b border-gray-200 backdrop-blur-sm">
        <div className="basis-11/12 flex">
          <div className={`w-1/2 flex justify-center hover:bg-slate-100`}>
            <button
              className={`py-4 font-bold ${
                activeTab === "forYou" ? "border-blue-500 border-b-4" : ""
              }`}
              onClick={() => setActiveTab("forYou")}
            >
              For You
            </button>
          </div>
          <div className="w-1/2 flex justify-center hover:bg-slate-100">
            <button
              className={`py-4 font-bold ${
                activeTab === "following" ? "border-blue-500 border-b-4" : ""
              }`}
              onClick={() => setActiveTab("following")}
            >
              Following
            </button>
          </div>
        </div>
        <div className="basis-1/12 flex justify-center">
          <button
            onClick={() => setModal(true)}
            className="p-2 hover:bg-slate-100 rounded-full"
          >
            <IoMdSettings />
          </button>
        </div>
      </div>
      <CreatePost refetch={refetch} />
      {userLoading ? (
        <div className="w-full h-24 flex justify-center items-center">
          <Loader />
        </div>
      ) : (
        <>
          <div
            id="forYou"
            className={`tab-content ${activeTab === "forYou" ? "active" : ""}`}
          >
            {videos.map((videoProp, i) => (
              <div key={videoProp.id}>
              <VideosComponent videoProp={videoProp} />
              </div>
            ))}
          </div>
          <div
            id="following"
            className={`tab-content ${
              activeTab === "following" ? "active" : ""
            }`}
          >
            <PostSection
              posts={renderedPosts}
              isLoading={isLoading}
              refetch={refetch}
              userId={userId}
            />
          </div>
        </>
      )}
      {!userLoading && (
        <PreferencesModal
          setModalOpen={setModal}
          isModalOpen={isModalOpen}
          homePreference={data?.homePreference}
          userId={userId}
        />
      )}
    </main>
  );
};
