import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { banco } from "../db/bancoMysql";

export interface TokenPayload {
    id: number;
    userLogin: string;
    acesso: "administrador" | "usuario";
    jti: string;
    exp: number;
}

export interface AuthRequest extends Request {
    user?: TokenPayload;
}

function getRequiredEnv(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
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

const secret = getStrongSecretEnv("JWT_SECRET");
const jwtIssuer = getRequiredEnv("JWT_ISSUER");
const jwtAudience = getRequiredEnv("JWT_AUDIENCE");
const accessTokenCookieName = process.env.ACCESS_TOKEN_COOKIE_NAME?.trim() || "access_token";

function getHeaderString(value: string | string[] | undefined): string | undefined {
    if (!value) {
        return undefined;
    }

    return Array.isArray(value) ? value[0] : value;
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

function extractAccessToken(req: Request): string | null {
    const authHeader = req.headers.authorization;

    if (authHeader?.startsWith("Bearer ")) {
        const token = authHeader.slice(7).trim();
        if (token) {
            return token;
        }
    }

    const cookieHeader = getHeaderString(req.headers.cookie);
    const cookies = parseCookieHeader(cookieHeader);
    const cookieToken = cookies[accessTokenCookieName];
    return cookieToken ? cookieToken.trim() : null;
}

export async function autenticarToken(
    req: AuthRequest,
    res: Response,
    next: NextFunction
): Promise<Response | void> {
    const token = extractAccessToken(req);

    if (!token) {
        return res.sendStatus(401);
    }

    try {
        const decoded = jwt.verify(token, secret, {
            algorithms: ["HS256"],
            issuer: jwtIssuer,
            audience: jwtAudience,
        }) as jwt.JwtPayload & TokenPayload;

        const jti = typeof decoded.jti === "string" ? decoded.jti : "";
        const exp = Number(decoded.exp);

        if (!jti || !Number.isFinite(exp) || exp <= 0) {
            return res.sendStatus(403);
        }

        const revogado = await banco.tokenRevogado(jti);

        if (revogado) {
            return res.sendStatus(401);
        }

        req.user = {
            id: Number(decoded.id),
            userLogin: String(decoded.userLogin),
            acesso: decoded.acesso,
            jti,
            exp,
        };
        next();
    } catch {
        return res.sendStatus(403);
    }
}
