const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const generate2FA = async (sec) => {
  const secret = speakeasy.generateSecret({ name: "MyApp" });
  const otpAuthUrl = `otpauth://totp/${encodeURIComponent("MyApp")}?secret=${
    secret.base32
  }&issuer=${encodeURIComponent("MyApp")}`;

  const qrCodeData = await QRCode.toDataURL(sec ? sec : otpAuthUrl);
  return { secret: secret.base32, qrCodeData };
};

module.exports = generate2FA;
