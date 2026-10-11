import { createHash, generateKeyPairSync, createCipheriv } from "crypto";
const h = createHash("sha1").update(x).digest("hex");
const { publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 3072,
});
const c = createCipheriv("aes-256-gcm", key, iv);
const k = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]);
