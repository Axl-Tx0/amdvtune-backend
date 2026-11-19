import express from "express";
import crypto from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";

const FIREBASE_PROJECT_ID = "gen-lang-client-0352254569";
const ADMIN_EMAIL = "amdvtune@gmail.com";

const JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
);

const app = express();
app.use(express.json());

// Ruta de prueba para comprobar que el servidor está encendido
app.get("/", (_req, res) => {
  res.json({ ok: true, service: "AMDV-TUNE Upload Signer" });
});

app.post("/sign-upload", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (!token) {
      return res.status(401).json({ error: "Falta el token de sesión." });
    }

    // Verifica el token de Google/Firebase con las llaves oficiales de Google
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`,
      audience: FIREBASE_PROJECT_ID
    });

    const email = String(payload.email || "").toLowerCase();
    if (email !== ADMIN_EMAIL || payload.email_verified !== true) {
      return res.status(403).json({ error: "Solo el administrador puede subir música." });
    }

    const cloudName = (process.env.CLOUDINARY_CLOUD_NAME || "").trim();
    const apiKey = (process.env.CLOUDINARY_API_KEY || "").trim();
    const apiSecret = (process.env.CLOUDINARY_API_SECRET || "").trim();
    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).json({ error: "Faltan variables de Cloudinary en Render." });
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder = String(req.body?.folder || "").trim();
    const publicId = String(req.body?.public_id || "").trim();

    const paramsToSign = { timestamp };
    if (folder) paramsToSign.folder = folder;
    if (publicId) paramsToSign.public_id = publicId;

    const sortedString = Object.keys(paramsToSign)
      .sort()
      .map((k) => `${k}=${paramsToSign[k]}`)
      .join("&");

    const signature = crypto
      .createHash("sha1")
      .update(sortedString + apiSecret)
      .digest("hex");

    return res.json({ cloudName, apiKey, timestamp, signature });
  } catch (err) {
    return res.status(401).json({ error: "Sesión inválida o expirada." });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`AMDV-TUNE backend listening on port ${port}`);
});
