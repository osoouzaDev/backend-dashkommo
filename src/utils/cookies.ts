import { Response, Request } from "express";
import { env } from "../config/env";
import { getHeaderString } from "./request";

type CookieSameSite = "Lax" | "Strict" | "None";

interface CookieConfig {
    maxAgeSec: number;
}

function parseCookieHeader(cookieHeader: string | undefined): Record<string, string> {
    if (!cookieHeader) {
        return {};
    }

    return cookieHeader
        .split(";")
        .map((part) => part.trim())
        .filter(Boolean)
        .reduce<Record<string, string>>((acc, pair) => {
            const separatorIndex = pair.indexOf("=");

            if (separatorIndex <= 0) {
                return acc;
            }

            const key = pair.slice(0, separatorIndex).trim();
            const value = pair.slice(separatorIndex + 1).trim();

            if (!key) {
                return acc;
            }

            try {
                acc[key] = decodeURIComponent(value);
            } catch {
                acc[key] = value;
            }

            return acc;
        }, {});
}

export function getCookie(req: Request, name: string): string | undefined {
    const cookieHeader = getHeaderString(req.headers.cookie);
    const cookies = parseCookieHeader(cookieHeader);
    const value = cookies[name];

    return value?.trim() || undefined;
}

function getCookieSameSite(): CookieSameSite {
    if (env.rawAuthCookieSameSite === "strict") {
        return "Strict";
    }

    if (env.rawAuthCookieSameSite === "none") {
        return "None";
    }

    return "Lax";
}

function buildSetCookieHeader(name: string, value: string, config: CookieConfig): string {
    const parts = [
        `${name}=${encodeURIComponent(value)}`,
        "Path=/",
        "HttpOnly",
        `Max-Age=${config.maxAgeSec}`,
        `SameSite=${getCookieSameSite()}`,
    ];

    if (env.authCookieSecure) {
        parts.push("Secure");
    }

    if (env.authCookieDomain) {
        parts.push(`Domain=${env.authCookieDomain}`);
    }

    return parts.join("; ");
}

export function writeAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
    if (!env.authCookiesEnabled) {
        return;
    }

    res.setHeader("Set-Cookie", [
        buildSetCookieHeader(env.accessTokenCookieName, accessToken, {
            maxAgeSec: env.accessTokenCookieMaxAgeSec,
        }),
        buildSetCookieHeader(env.refreshTokenCookieName, refreshToken, {
            maxAgeSec: env.refreshTokenCookieMaxAgeSec,
        }),
    ]);
}

export function clearAuthCookies(res: Response): void {
    if (!env.authCookiesEnabled) {
        return;
    }

    res.setHeader("Set-Cookie", [
        buildSetCookieHeader(env.accessTokenCookieName, "", { maxAgeSec: 0 }),
        buildSetCookieHeader(env.refreshTokenCookieName, "", { maxAgeSec: 0 }),
    ]);
}
