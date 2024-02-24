import React, { useEffect, useState } from "react";
import RelatedVideo from "./RelatedVideo";

export default function RelatedVideosList({id}) {
  const [similarVideos, setSimilarVideos] = useState([])
  const Get =async()=>{
    const data = await fetch(`http://localhost:8000/api/videos/similarvideos/${id}`)
    const similar = await data.json()
    setSimilarVideos(similar)
  }
useEffect(()=>{
  Get()
})
  return (
    <div className="col-span-full lg:col-auto max-h-[570px] overflow-y-auto">
     {similarVideos.map((e)=>{
     
      return(
        <div key={e._id}>
               <RelatedVideo data={e} />
        </div>
      )
     })
     }
    </div>
  );
}
