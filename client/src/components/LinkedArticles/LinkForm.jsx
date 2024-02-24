import React, { useState } from "react";
import MetadataFetcher from "react-metadata-fetcher";

const LinkForm = () => {
  const [url, setUrl] = useState("");
  const [metadata, setMetadata] = useState(null);

  const handleUrlChange = (e) => {
    setUrl(e.target.value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const data = await MetadataFetcher.fetch(url);
      setMetadata(data);
    } catch (error) {
      console.error("Error fetching metadata:", error);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={url}
        onChange={handleUrlChange}
        placeholder="Enter URL"
      />
      <button type="submit">Fetch Metadata</button>
    </form>
  );
};

export default LinkForm;
