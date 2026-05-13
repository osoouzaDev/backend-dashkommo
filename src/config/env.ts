export class ValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ValidationError";
    }
}

function getRequiredEnv(name: string): string {
    const value = process.env[name]?.trim();

    if (!value) {
        throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
    }

    return value;
}

function getStrongSecretEnv(name: string, minLength = 32): string {
    const value = getRequiredEnv(name);

    if (value.length < minLength || value.toLowerCase().includes("change_me")) {
        throw new Error(
            `Variável ${name} fraca. Use um segredo com pelo menos ${minLength} caracteres aleatórios.`
        );
    }

    return value;
}

const isProduction = process.env.NODE_ENV === "production";
const webhookToleranceSeconds = Number(process.env.WEBHOOK_SIGNATURE_TOLERANCE_SEC ?? "300");
const refreshTokenTtlDays = Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? "30");
const accessTokenCookieMaxAgeSec = Number(process.env.ACCESS_TOKEN_COOKIE_MAX_AGE_SEC ?? "1800");
const refreshTokenCookieMaxAgeSec = Number(
    process.env.REFRESH_TOKEN_COOKIE_MAX_AGE_SEC ?? String(refreshTokenTtlDays * 24 * 60 * 60)
);
const rawAuthCookieSameSite = (process.env.AUTH_COOKIE_SAMESITE ?? (isProduction ? "none" : "lax"))
    .trim()
    .toLowerCase();
const authCookieSecure = process.env.AUTH_COOKIE_SECURE
    ? process.env.AUTH_COOKIE_SECURE === "true"
    : isProduction;

if (!Number.isInteger(webhookToleranceSeconds) || webhookToleranceSeconds <= 0) {
    throw new Error("WEBHOOK_SIGNATURE_TOLERANCE_SEC inválida.");
}

if (!Number.isInteger(refreshTokenTtlDays) || refreshTokenTtlDays <= 0) {
    throw new Error("REFRESH_TOKEN_TTL_DAYS inválida.");
}

if (
    !Number.isInteger(accessTokenCookieMaxAgeSec) ||
    accessTokenCookieMaxAgeSec <= 0 ||
    !Number.isInteger(refreshTokenCookieMaxAgeSec) ||
    refreshTokenCookieMaxAgeSec <= 0
) {
    throw new Error("Configuração de expiração de cookie inválida.");
}

if (!["lax", "strict", "none"].includes(rawAuthCookieSameSite)) {
    throw new Error("AUTH_COOKIE_SAMESITE inválido. Use lax, strict ou none.");
}

if (rawAuthCookieSameSite === "none" && !authCookieSecure) {
    throw new Error("AUTH_COOKIE_SAMESITE=none exige AUTH_COOKIE_SECURE=true.");
}

export const env = {
    port: process.env.PORT || "8000",
    jwtSecret: getStrongSecretEnv("JWT_SECRET"),
    passwordPepper: getStrongSecretEnv("PASSWORD_PEPPER"),
    jwtIssuer: getRequiredEnv("JWT_ISSUER"),
    jwtAudience: getRequiredEnv("JWT_AUDIENCE"),
    webhookSecret: getStrongSecretEnv("WEBHOOK_SECRET"),
    webhookToleranceSeconds,
    webhookAllowLegacySecret: process.env.WEBHOOK_ALLOW_LEGACY_SECRET === "true",
    refreshTokenTtlDays,
    isProduction,
    authCookiesEnabled: process.env.AUTH_COOKIES_ENABLED === "true",
    accessTokenCookieName: process.env.ACCESS_TOKEN_COOKIE_NAME?.trim() || "access_token",
    refreshTokenCookieName: process.env.REFRESH_TOKEN_COOKIE_NAME?.trim() || "refresh_token",
    accessTokenCookieMaxAgeSec,
    refreshTokenCookieMaxAgeSec,
    authCookieDomain: process.env.AUTH_COOKIE_DOMAIN?.trim() || undefined,
    rawAuthCookieSameSite,
    authCookieSecure,
} as const;
