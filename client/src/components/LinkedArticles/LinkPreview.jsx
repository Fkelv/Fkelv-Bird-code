import React from "react";

const LinkPreview = ({ metadata }) => {
  return (
    <div>
      {metadata && (
        <>
          <img src={metadata.image} alt="Preview" />
          <p>{metadata.title}</p>
          <p>{metadata.url}</p>
        </>
      )}
    </div>
  );
};

export default LinkPreview;
