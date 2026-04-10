import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { tokenBlacklist } from "./token-blacklist";

export interface TokenPayload {
    id: number;
    userLogin: string;
    acesso: "administrador" | "usuario";
}

export interface AuthRequest extends Request {
    user?: TokenPayload;
}

function getRequiredEnv(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
    return value;
}

const secret = getRequiredEnv("JWT_SECRET");

export function autenticarToken(
    req: AuthRequest,
    res: Response,
    next: NextFunction
): Response | void {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.sendStatus(401);
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
        return res.sendStatus(401);
    }

    if (tokenBlacklist.has(token)) {
        return res.sendStatus(401);
    }

    try {
        const decoded = jwt.verify(token, secret) as TokenPayload;
        req.user = decoded;
        next();
    } catch {
        return res.sendStatus(403);
    }
}