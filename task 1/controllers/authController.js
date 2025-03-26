const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const generate2FA = require("../utils/generateQR");
const User = require("../models/User");

exports.register = async (req, res) => {
  const { username, password } = req.body;

  try {
    const userExists = await User.findOne({ username });
    if (userExists) return res.status(400).json({ message: "User exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const { secret } = await generate2FA();
    // const { secret, qrCodeData } = await generate2FA();

    const newUser = new User({
      username,
      password: hashedPassword,
      twofa_secret: secret,
    });
    await newUser.save();

    res.json({ message: "Registered" });
  } catch (error) {
    res.status(500).json({ message: "Server Error" });
  }
};

exports.login = async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ message: "Invalid credentials" });

    const { qrCodeData } = await generate2FA(user.twofa_secret);
    res.json({ qrCodeData });
  } catch (error) {
    res.status(500).json({ message: "Server Error" });
  }
};

exports.verify = async (req, res) => {
  const { username, password, token } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ message: "Invalid credentials" });

    const verified = speakeasy.totp.verify({
      secret: user.twofa_secret,
      encoding: "base32",
      token,
    });

    if (!verified) return res.status(400).json({ message: "Invalid 2FA Code" });

    const jwtToken = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "10m",
      }
    );

    res.json({ token: jwtToken });
  } catch (error) {
    res.status(500).json({ message: "Server Error" });
  }
};
