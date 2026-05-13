import { Router } from "express";
import { banco } from "../db/bancoMysql";
import { AuthRequest, autenticarToken } from "../middlewares/auth";
import { logoutSchema, loginSchema, refreshSchema } from "../schemas";
import { registrarAuditoriaSeguro } from "../services/auditoria";
import {
    buildLoginAttemptKey,
    criarAccessToken,
    gerarRefreshFamilyId,
    gerarRefreshToken,
    getRefreshTokenExpUnix,
    verificarSenha,
} from "../services/auth";
import {
    LOGIN_LOCK_BASE_MS,
    LOGIN_LOCK_MAX_MS,
    loginLimiter,
    logoutLimiter,
    refreshLimiter,
} from "../config/rateLimit";
import { clearAuthCookies, getCookie, writeAuthCookies } from "../utils/cookies";
import { getClientIp } from "../utils/request";
import { validarEntrada } from "../utils/validation";
import { env } from "../config/env";

export const authRouter = Router();

authRouter.post("/login", loginLimiter, async (req, res) => {
    try {
        const parsedBody = validarEntrada(loginSchema, req.body, res);

        if (!parsedBody) {
            return;
        }

        const { userLogin, senha } = parsedBody;
        const ip = getClientIp(req);
        const loginAttemptKey = buildLoginAttemptKey(userLogin, ip);
        const lockRemainingMs = await banco.getLoginLockRemainingMs(loginAttemptKey);

        if (lockRemainingMs > 0) {
            await registrarAuditoriaSeguro("login", "negado", {
                userLogin,
                ip,
                motivo: "conta temporariamente bloqueada",
                lockRemainingMs,
                requestId: req.requestId ?? null,
            });

            return res.status(429).json({
                message: "Muitas tentativas de login. Aguarde alguns minutos e tente novamente.",
            });
        }

        const usuarios = await banco.findByLogin(userLogin);
        const usuario = usuarios[0];

        if (!usuario) {
            await banco.registrarFalhaLogin(loginAttemptKey, LOGIN_LOCK_BASE_MS, LOGIN_LOCK_MAX_MS);

            await registrarAuditoriaSeguro("login", "falha", {
                userLogin,
                ip,
                motivo: "credencial inválida",
                requestId: req.requestId ?? null,
            });

            return res.status(401).json({
                message: "Usuário ou senha incorretos",
            });
        }

        const { senhaValida, precisaMigrarHash } = await verificarSenha(usuario.senha, senha);

        if (!senhaValida) {
            await banco.registrarFalhaLogin(loginAttemptKey, LOGIN_LOCK_BASE_MS, LOGIN_LOCK_MAX_MS);

            await registrarAuditoriaSeguro("login", "falha", {
                userLogin,
                ip,
                motivo: "credencial inválida",
                requestId: req.requestId ?? null,
            });

            return res.status(401).json({
                message: "Usuário ou senha incorretos",
            });
        }

        await banco.resetarFalhasLogin(loginAttemptKey);

        if (precisaMigrarHash) {
            await banco.atualizarHashSenha(usuario.id, senha);
        }

        const token = criarAccessToken({
            id: usuario.id,
            userLogin: usuario.userLogin,
            acesso: usuario.acesso,
        });
        const refreshToken = gerarRefreshToken();
        const refreshFamilyId = gerarRefreshFamilyId();

        await banco.criarRefreshToken(
            refreshToken,
            usuario.id,
            refreshFamilyId,
            getRefreshTokenExpUnix()
        );

        await registrarAuditoriaSeguro("login", "sucesso", {
            userId: usuario.id,
            userLogin: usuario.userLogin,
            ip,
            requestId: req.requestId ?? null,
        });

        writeAuthCookies(res, token, refreshToken);

        return res.json({
            token,
            refreshToken,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                acesso: usuario.acesso,
            },
        });
    } catch (error) {
        console.error("Erro no login.", error);

        await registrarAuditoriaSeguro("login", "falha", {
            ip: getClientIp(req),
            motivo: "erro interno",
            requestId: req.requestId ?? null,
        });

        return res.status(500).json({ message: "Erro no login" });
    }
});

authRouter.post("/auth/refresh", refreshLimiter, async (req, res) => {
    try {
        const parsedBody = validarEntrada(refreshSchema, req.body ?? {}, res);

        if (!parsedBody) {
            return;
        }

        const refreshToken = parsedBody.refreshToken ?? getCookie(req, env.refreshTokenCookieName);

        if (!refreshToken) {
            return res.status(400).json({ message: "Refresh token obrigatório." });
        }

        const registro = await banco.buscarRefreshToken(refreshToken);

        if (!registro) {
            await registrarAuditoriaSeguro("refresh_token", "falha", {
                ip: getClientIp(req),
                motivo: "token não encontrado",
                requestId: req.requestId ?? null,
            });

            return res.status(401).json({ message: "Refresh token inválido" });
        }

        const refreshExpirado = new Date(registro.expira_em).getTime() < Date.now();
        const refreshRevogado = Boolean(registro.revogado_em);

        if (refreshRevogado || refreshExpirado) {
            if (refreshRevogado && registro.substituido_por_hash) {
                await banco.revogarFamiliaRefreshToken(registro.family_id);
            }

            await registrarAuditoriaSeguro("refresh_token", "negado", {
                ip: getClientIp(req),
                userId: registro.user_id,
                motivo: "token revogado/expirado",
                requestId: req.requestId ?? null,
            });

            return res.status(401).json({ message: "Refresh token inválido" });
        }

        const usuario = await banco.findUserByid(String(registro.user_id));

        if (!usuario) {
            await banco.revogarFamiliaRefreshToken(registro.family_id);

            await registrarAuditoriaSeguro("refresh_token", "falha", {
                ip: getClientIp(req),
                userId: registro.user_id,
                motivo: "usuário inexistente",
                requestId: req.requestId ?? null,
            });

            return res.status(401).json({ message: "Refresh token inválido" });
        }

        const novoRefreshToken = gerarRefreshToken();
        const rotated = await banco.rotacionarRefreshToken(
            refreshToken,
            novoRefreshToken,
            getRefreshTokenExpUnix()
        );

        if (!rotated) {
            await banco.revogarFamiliaRefreshToken(registro.family_id);

            await registrarAuditoriaSeguro("refresh_token", "negado", {
                ip: getClientIp(req),
                userId: registro.user_id,
                motivo: "falha na rotação",
                requestId: req.requestId ?? null,
            });

            return res.status(401).json({ message: "Refresh token inválido" });
        }

        const novoAccessToken = criarAccessToken({
            id: Number(usuario.id),
            userLogin: usuario.userLogin,
            acesso: usuario.acesso,
        });

        await registrarAuditoriaSeguro("refresh_token", "sucesso", {
            ip: getClientIp(req),
            userId: usuario.id ?? null,
            requestId: req.requestId ?? null,
        });

        writeAuthCookies(res, novoAccessToken, novoRefreshToken);

        return res.json({
            token: novoAccessToken,
            refreshToken: novoRefreshToken,
        });
    } catch (error) {
        console.error("Erro no refresh token.", error);

        await registrarAuditoriaSeguro("refresh_token", "falha", {
            ip: getClientIp(req),
            motivo: "erro interno",
            requestId: req.requestId ?? null,
        });

        return res.status(500).json({ message: "Erro no refresh token" });
    }
});

authRouter.post("/logout", logoutLimiter, autenticarToken, async (req: AuthRequest, res) => {
    try {
        const parsedBody = validarEntrada(logoutSchema, req.body ?? {}, res);

        if (!parsedBody) {
            return;
        }

        const user = req.user;

        if (!user?.jti || !user.exp) {
            return res.sendStatus(401);
        }

        await banco.revogarTokenPorJti(user.jti, user.exp);

        const refreshToken = parsedBody.refreshToken ?? getCookie(req, env.refreshTokenCookieName);

        if (refreshToken) {
            await banco.revogarRefreshToken(refreshToken);
        }

        await registrarAuditoriaSeguro("logout", "sucesso", {
            userId: user.id,
            userLogin: user.userLogin,
            ip: getClientIp(req),
            requestId: req.requestId ?? null,
        });

        clearAuthCookies(res);

        return res.json({ message: "Logout realizado com sucesso" });
    } catch (error) {
        console.error("Erro no logout.", error);

        await registrarAuditoriaSeguro("logout", "falha", {
            userId: req.user?.id ?? null,
            ip: getClientIp(req),
            requestId: req.requestId ?? null,
        });

        return res.status(500).json({ message: "Erro no logout" });
    }
});
