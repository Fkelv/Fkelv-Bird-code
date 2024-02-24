import { createSlice } from "@reduxjs/toolkit";

const postSlice = createSlice({
  name: "post",
  initialState: {
    feed: [],
  },
  reducers: {},
});

const { actions, reducer } = postSlice;

export default reducer;
