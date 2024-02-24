import axios from "axios";
import React, { useState } from "react";
import Autosuggest from "react-autosuggest";
import { Link, useLocation } from "react-router-dom";
import {
  AiOutlineSetting,
  BiDollarCircle,
  MdOutlineAccountBox,
  MdOutlineLogin,
  MdSlowMotionVideo,
} from "../constant/icons";
import { NotificationIcon } from "./notifications/NotificationIcon";
import useAuth from "../hooks/useAuth";
import { useDispatch, useSelector } from "react-redux";
import { selectCurrentUser, signOut } from "../store/authSlice";
import { useGetUserQuery } from "../store";

export default function Nav() {
  const dispatch = useDispatch();
  const auth = useAuth();
  const location = useLocation();
  const [dropDown, setDropDown] = useState(false);

  const userId = useSelector(selectCurrentUser);
  const { data: profileData } = useGetUserQuery(userId);
  const avatar = profileData?.avatar
    ? `${import.meta.env.VITE_API_URL}/${profileData?.avatar}`
    : "/assets/avatar.png";

  const [search, setSearch] = useState({
    value: "",
    suggestions: [],
  });

  const watchPage =
    location.pathname === `/watch` ||
    location.pathname === "/studio/stream-manager";

  const handleClick = () => {
    setDropDown(() => !dropDown);
  };

  const navItems = [
    {
      id: 1,
      icon: <MdOutlineAccountBox fontSize={24} />,
      title: "Profile",
      url: `/users/${userId}`,
    },
    {
      id: 2,
      icon: <MdSlowMotionVideo fontSize={24} />,
      title: "Creator Studio",
      url: "/studio/content",
    },
    {
      id: 3,
      icon: <BiDollarCircle fontSize={24} />,
      title: "Subscription",
      url: "/subscription",
    },
    {
      id: 4,
      icon: <AiOutlineSetting fontSize={24} />,
      title: "Settings",
      url: "/settings",
    },
  ];

  function handleLogOut() {
    dispatch(signOut());
  }

  return (
    <div
      className={`w-full sticky top-0 z-10 ${
        watchPage ? "bg-[#212121]" : "bg-w"
      }`}
    >
      <div className="flex items-center max-w-[1450px] mx-auto justify-between px-4 py-4 backdrop-blur-sm">
        <div className="flex items-center">
          <Link
            to="/"
            className={`font-bold text-3xl ${watchPage ? "text-white" : ""}`}
          >
            Header
          </Link>
          <ul className="flex items-center gap-6 ml-20">
            {["Home", "Discover", "Watch", "Messages"].map((item) => (
              <li
                className={`${
                  watchPage ? "text-white" : "hover:text-blue-500"
                }  text-[20px] mt-[3px]`}
                key={item}
              >
                <Link to={item === "Home" ? "/" : `/${item.toLowerCase()}`}>
                  {item}
                </Link>
              </li>
            ))}
          </ul>
        </div>
        <div className="flex items-center gap-2">
          {/* <Autosuggest
            className='flex items-center bg-gray-100 rounded-3xl py-2 px-4'
            suggestions={search.suggestions}
            onSuggestionsFetchRequested={({ value }) => getSuggestions(value)}
            onSuggestionsClearRequested={() =>
              setSearch({ ...search, suggestions: [] })
            }
            getSuggestionValue={(suggestion) => suggestion.user.name}
            renderSuggestion={renderSuggestion}
            onSuggestionSelected={onSuggestionSelected}
            inputProps={{
              placeholder: 'Search..',
              value: search.value,
              onChange: handleOnChange,
              onBlur: () => setSearch({ ...search, value: '' }),
              className:
                'w-28 transition-all duration-500 ml-3 outline-none focus:outline-none bg-gray-100 text-md placeholder:text-black',
            }}
            theme={theme}
          /> */}

          {/* <form
            onSubmit={handleSubmit}
            className="flex items-center bg-gray-100 rounded-3xl py-2 px-4"
          >
            <div>
              <AiOutlineSearch fontSize={23} />
            </div>
            <input
              type="text"
              value={search}
              onChange={handleInputChange}
              className="w-28 transition-all duration-500 ml-3 outline-none focus:outline-none bg-gray-100 text-md placeholder:text-black"
              placeholder="Search"
            />
          </form> */}
          {/* <AutoSuggestions suggestions={suggestions} />
          <SearchResults results={results} /> */}
          {auth ? (
            <>
              <NotificationIcon watchPage={watchPage} userId={userId} />
              <div className="cursor-pointer relative" onClick={handleClick}>
                <div className="h-10 w-10 overflow-hidden">
                  <img
                    className="h-full w-full object-cover rounded-full"
                    src={avatar}
                    alt="user"
                  />
                </div>
                <div
                  className={`absolute top-[109%] min-w-[250px] right-0 ${
                    dropDown ? "flex opacity-100" : "hidden opacity-0"
                  } flex-col  bg-white shadow-sm shadow-gray-300 opacity-1`}
                >
                  {navItems.map((item) => (
                    <div
                      className="w-max rounded-sm hover:bg-gray-100 px-4 py-2 min-w-full "
                      key={item.id}
                    >
                      <Link
                        to={item.url}
                        className="text-black text-lg flex items-center gap-2"
                      >
                        {item.icon}
                        {item.title}
                      </Link>
                    </div>
                  ))}
                  <button
                    className="text-black text-lg flex items-center gap-2 px-4 py-2 min-w-full hover:bg-gray-100"
                    onClick={handleLogOut}
                  >
                    {<MdOutlineLogin fontSize={24} />} Logout
                  </button>
                </div>
              </div>
            </>
          ) : (
            <Link to="/auth/signin">Login</Link>
          )}
        </div>
      </div>
    </div>
  );
}
