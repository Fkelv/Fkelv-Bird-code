const User = require("../models/user");

const isUsernameTaken = async (username) => {
  const existingUser = await User.findOne({ username });
  return !!existingUser;
};
const generateUniqueUsername = async (fullname) => {
  const namesplit = fullname.trim().split(" ");
  const firstName = namesplit[0];
  // Use the first name only if there's no last name, or use the last name if available
  const lastName = namesplit.length > 1 ? namesplit[1] : '';
  
  // Construct baseUsername to handle scenarios where lastName might be empty
  let baseUsername = `${firstName.toLowerCase()}${lastName.toLowerCase()}`;
  let username = baseUsername;

  let counter = 1;
  while (await isUsernameTaken(username)) {
    // If the username is already taken, modify it
    username = `${baseUsername}${counter}`;
    counter++;
  }

  return username;
};


module.exports = {
  generateUniqueUsername,
};
