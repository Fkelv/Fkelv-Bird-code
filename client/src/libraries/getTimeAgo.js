export function getTimeAgo(dateCreated) {
  const currentDate = new Date();
  const createdDate = new Date(dateCreated);

  const timeDifferenceInSeconds = Math.floor(
    (currentDate - createdDate) / 1000
  );

  if (timeDifferenceInSeconds < 60) {
    return `${timeDifferenceInSeconds} second${
      timeDifferenceInSeconds === 1 ? "" : "s"
    }`;
  } else if (timeDifferenceInSeconds < 3600) {
    const minutes = Math.floor(timeDifferenceInSeconds / 60);
    return `${minutes}m`;
  } else if (timeDifferenceInSeconds < 86400) {
    const hours = Math.floor(timeDifferenceInSeconds / 3600);
    return `${hours}h`;
  } else {
    // You can implement additional logic for days, weeks, etc. as needed
    // For simplicity, let's just return the full date
    return createdDate.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });
  }
}
