import { useSelector } from "react-redux";
import { selectCurrentUser } from "../store/authSlice";

const useAuth = () => {
  const userId = useSelector(selectCurrentUser);
  if (userId) {
    return true;
  } else {
    return false;
  }
};

export default useAuth;
