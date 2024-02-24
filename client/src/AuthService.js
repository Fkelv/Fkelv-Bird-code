
import axios from 'axios';
import { loginSuccess, loginFailure, logout } from './actions/authActions'; // Redux actions

const apiUrl = 'http://localhost:8000/api/users';

export const loginUser = async (credentials, dispatch) => {
  try {
    const response = await axios.post(`${apiUrl}/login`, credentials);
    const token = response.data;
    dispatch(loginSuccess(token)); // Dispatch login success action
    return token;
  } catch (error) {
    dispatch(loginFailure(error)); // Dispatch login failure action
    throw error;
  }
};

export const logoutUser = (dispatch) => {
  dispatch(logout()); // Dispatch logout action
};
