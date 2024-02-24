import React from "react";
import Cards from "../../components/Watch/Cards";
import Slider from "../../components/Watch/Slider";
import { useRefreshAccessTokenQuery } from "../../store";

export default function Watch() {
  const {} = useRefreshAccessTokenQuery();
  return (
    <div>
      <Slider />
      <div className="max-w-[1380px] mx-auto mt-8">
        <Cards />
      </div>
    </div>
  );
}
