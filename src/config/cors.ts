import { CorsOptions } from "cors";
import { env } from "./env";

const defaultAllowedOrigins = env.isProduction
    ? [
          "https://dashkommo-snowy.vercel.app",
          "https://amcontabilidade.kommo.com",
      ]
    : [
          "http://localhost:3000",
          "http://localhost:3001",
          "http://127.0.0.1:3000",
          "http://127.0.0.1:3001",
          "https://dashkommo-snowy.vercel.app",
          "https://amcontabilidade.kommo.com",
      ];

const envAllowedOrigins = process.env.CORS_ALLOWED_ORIGINS
    ? process.env.CORS_ALLOWED_ORIGINS.split(",")
          .map((origin) => origin.trim())
          .filter(Boolean)
    : [];

const effectiveAllowedOrigins = [...new Set([...defaultAllowedOrigins, ...envAllowedOrigins])];

function isAllowedOrigin(origin: string): boolean {
    return effectiveAllowedOrigins.includes(origin);
}

export const corsOptions: CorsOptions = {
    origin: (origin, callback) => {
        if (!origin) {
            return callback(null, true);
        }

        if (isAllowedOrigin(origin)) {
            return callback(null, true);
        }

        return callback(new Error(`Origem não permitida pelo CORS: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    optionsSuccessStatus: 204,
};
