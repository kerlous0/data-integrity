const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

const generate2FA = async (sec) => {
  const secret = sec
    ? {
        base32: sec,
        otpauth_url: `otpauth://totp/MyApp?secret=${sec}`,
      }
    : speakeasy.generateSecret({ name: "MyApp" });

  const qrCodeData = await QRCode.toDataURL(secret.otpauth_url);
  return { secret: secret.base32, qrCodeData };
};

module.exports = generate2FA;
