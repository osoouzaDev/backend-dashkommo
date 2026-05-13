import rateLimit from "express-rate-limit";

export const LOGIN_LOCK_BASE_MS = 5 * 60 * 1000;
export const LOGIN_LOCK_MAX_MS = 60 * 60 * 1000;

export const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas requisições. Tente novamente em alguns minutos.",
    },
});

export const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas de login. Tente novamente em alguns minutos.",
    },
});

export const webhookLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas no webhook. Aguarde alguns minutos.",
    },
});

export const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas de refresh. Aguarde alguns minutos.",
    },
});

export const logoutLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas de logout. Aguarde alguns minutos.",
    },
});
