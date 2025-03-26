const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  twofa_secret: { type: String, required: true },
});

module.exports = mongoose.model("User", UserSchema);
