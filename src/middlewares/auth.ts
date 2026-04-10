import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface TokenPayload {
    id: number;
    userLogin: string;
    // FIX: tipo restrito — evita comparações com string arbitrária
    acesso: "administrador" | "usuario";
}

export interface AuthRequest extends Request {
    user?: TokenPayload;
}

// FIX: leitura segura — lança erro na inicialização se ausente,
// sem precisar de cast "as string" que mascara undefined
function getRequiredEnv(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
    return value;
}

const secret = getRequiredEnv("JWT_SECRET");

// FIX: blacklist importada de um módulo neutro para evitar dependência circular com main.ts
import { tokenBlacklist } from "./Tokenblacklist";

export function autenticarToken(
    req: AuthRequest,
    res: Response,
    next: NextFunction
): Response | void {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(" ")[1];

    if (!token) {
        return res.sendStatus(401);
    }

    // FIX: tokens invalidados via logout são rejeitados
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