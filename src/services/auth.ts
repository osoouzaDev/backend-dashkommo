import bcrypt from "bcryptjs";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { randomBytes, randomUUID } from "crypto";
import { env } from "../config/env";

export function isArgon2Hash(hash: string): boolean {
    return hash.startsWith("$argon2");
}

export function isBcryptHash(hash: string): boolean {
    return hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$");
}

export async function verificarSenha(
    hash: string,
    senhaDigitada: string
): Promise<{ senhaValida: boolean; precisaMigrarHash: boolean }> {
    const senhaComPepper = senhaDigitada + env.passwordPepper;

    if (isArgon2Hash(hash)) {
        const senhaValida = await argon2.verify(hash, senhaComPepper);

        if (senhaValida) {
            return { senhaValida: true, precisaMigrarHash: false };
        }

        const senhaValidaSemPepper = await argon2.verify(hash, senhaDigitada);
        return {
            senhaValida: senhaValidaSemPepper,
            precisaMigrarHash: senhaValidaSemPepper,
        };
    }

    if (isBcryptHash(hash)) {
        const senhaValida = await bcrypt.compare(senhaDigitada, hash);
        return { senhaValida, precisaMigrarHash: senhaValida };
    }

    return { senhaValida: false, precisaMigrarHash: false };
}

export function criarAccessToken(usuario: {
    id: number;
    userLogin: string;
    acesso: "administrador" | "usuario";
}): string {
    return jwt.sign(
        {
            id: usuario.id,
            userLogin: usuario.userLogin,
            acesso: usuario.acesso,
        },
        env.jwtSecret,
        {
            expiresIn: "30m",
            algorithm: "HS256",
            issuer: env.jwtIssuer,
            audience: env.jwtAudience,
            jwtid: randomUUID(),
            subject: String(usuario.id),
        }
    );
}

export function gerarRefreshToken(): string {
    return randomBytes(48).toString("hex");
}

export function gerarRefreshFamilyId(): string {
    return randomUUID();
}

export function getRefreshTokenExpUnix(): number {
    return Math.floor(Date.now() / 1000) + env.refreshTokenTtlDays * 24 * 60 * 60;
}

export function normalizarLoginChave(login: string): string {
    return login.trim().toLowerCase();
}

export function buildLoginAttemptKey(login: string, ip: string): string {
    return `${normalizarLoginChave(login)}|${ip}`;
}
