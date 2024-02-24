import { AiOutlineDelete, AiOutlineEyeInvisible } from "react-icons/ai";
import { FaRegEdit } from "react-icons/fa";
import { Link } from "react-router-dom";

export function VideoRow({ video }) {
  const thumbnailURL = `${import.meta.env.VITE_API_URL}/${video.thumbnailURL}`;
  const options = { year: "numeric", month: "short", day: "numeric" };
  const formattedDate = new Date(video.uploadDate).toLocaleDateString(
    "en-US",
    options
  );

  return (
    <tr className="group">
      <td className="flex gap-2">
        <div className="relative w-[120px] duration-300 hover:scale-[1.02]">
          <Link to={`/watch/${video._id}`}>
            <img
              src={thumbnailURL}
              className="object-cover rounded-sm"
              alt="Some video title"
            />
          </Link>

          <p className="absolute right-2 bottom-2 bg-gray-900 text-gray-100 text-xs px-1 py">
            12:10
          </p>
        </div>
        <div className="">
          <a href="/">
            <p className="text-sm font-semibold">{video.title}</p>
          </a>
          <div className="flex opacity-0 group-hover:opacity-100 items-center mt-2 ml-2 gap-1">
            <FaRegEdit
              fontSize={25}
              className="p-1 hover:text-green-500 cursor-pointer"
            />
            <AiOutlineDelete
              fontSize={26}
              className="p-1 hover:text-red-500 cursor-pointer"
            />
          </div>
        </div>
      </td>

      <td>
        <div className="flex items-center gap-1">
          <AiOutlineEyeInvisible fontSize={19} />
          <p>{video.visibility}</p>
        </div>
      </td>
      <td>{formattedDate}</td>
      <td>{video.views}</td>
      <td>{0}</td>
      <td>{0}</td>
      <td>{0}</td>
    </tr>
  );
}
