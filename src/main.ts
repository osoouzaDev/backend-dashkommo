import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import cors, { CorsOptions } from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "crypto";
import { z } from "zod";
import { banco } from "./db/bancoMysql";
import { autenticarToken, AuthRequest } from "./middlewares/auth";
import { autorizarAdmin } from "./middlewares/autorizarAdmin";

export class ValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ValidationError";
    }
}

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

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

const secret = getStrongSecretEnv("JWT_SECRET");
const passwordPepper = getStrongSecretEnv("PASSWORD_PEPPER");
const jwtIssuer = getRequiredEnv("JWT_ISSUER");
const jwtAudience = getRequiredEnv("JWT_AUDIENCE");
const webhookSecret = getStrongSecretEnv("WEBHOOK_SECRET");
const webhookToleranceSeconds = Number(process.env.WEBHOOK_SIGNATURE_TOLERANCE_SEC ?? "300");
const webhookAllowLegacySecret = process.env.WEBHOOK_ALLOW_LEGACY_SECRET === "true";
const refreshTokenTtlDays = Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? "30");
const isProduction = process.env.NODE_ENV === "production";
const authCookiesEnabled = process.env.AUTH_COOKIES_ENABLED === "true";
const accessTokenCookieName = process.env.ACCESS_TOKEN_COOKIE_NAME?.trim() || "access_token";
const refreshTokenCookieName = process.env.REFRESH_TOKEN_COOKIE_NAME?.trim() || "refresh_token";
const accessTokenCookieMaxAgeSec = Number(process.env.ACCESS_TOKEN_COOKIE_MAX_AGE_SEC ?? "1800");
const refreshTokenCookieMaxAgeSec = Number(
    process.env.REFRESH_TOKEN_COOKIE_MAX_AGE_SEC ?? String(refreshTokenTtlDays * 24 * 60 * 60)
);
const authCookieDomain = process.env.AUTH_COOKIE_DOMAIN?.trim() || undefined;
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

const allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "https://dashkommo-snowy.vercel.app",
    "https://kommo.com",
    "https://www.kommo.com",
    "https://amcontabilidade.kommo.com",
];

const envAllowedOrigins = process.env.CORS_ALLOWED_ORIGINS
    ? process.env.CORS_ALLOWED_ORIGINS.split(",")
          .map((origin) => origin.trim())
          .filter(Boolean)
    : [];

const effectiveAllowedOrigins = [...new Set([...allowedOrigins, ...envAllowedOrigins])];
const LOGIN_LOCK_BASE_MS = 5 * 60 * 1000;
const LOGIN_LOCK_MAX_MS = 60 * 60 * 1000;

const loginSchema = z.object({
    userLogin: z.string().trim().min(3).max(50),
    senha: z.string().min(1).max(255),
});

const userBaseSchema = z.object({
    nome: z.string().trim().min(1).max(50),
    email: z.string().trim().email().max(100),
    acesso: z.enum(["administrador", "usuario"]),
    setor: z.string().trim().min(1).max(50),
    userLogin: z.string().trim().min(3).max(50),
});

const createUserSchema = userBaseSchema.extend({
    senha: z.string().min(8).max(255),
});

const updateUserSchema = userBaseSchema.extend({
    senha: z.string().min(8).max(255).optional(),
});

const idParamSchema = z.object({
    id: z.string().regex(/^\d+$/),
});

const webhookSchema = z.unknown();
const refreshSchema = z.object({
    refreshToken: z.string().trim().min(32).max(512).optional(),
});
const logoutSchema = z.object({
    refreshToken: z.string().trim().min(32).max(512).optional(),
});

function isKommoOrigin(hostname: string): boolean {
    return (
        hostname === "kommo.com" ||
        hostname === "www.kommo.com" ||
        hostname.endsWith(".kommo.com")
    );
}

function isAllowedOrigin(origin: string): boolean {
    if (effectiveAllowedOrigins.includes(origin)) {
        return true;
    }

    try {
        const url = new URL(origin);

        const isLocalhost =
            url.protocol === "http:" &&
            (url.hostname === "localhost" || url.hostname === "127.0.0.1");

        if (isLocalhost) {
            return effectiveAllowedOrigins.includes(origin);
        }

        if (url.protocol !== "https:") {
            return false;
        }

        if (url.hostname === "frontend-dashkommo.vercel.app") {
            return true;
        }

        if (isKommoOrigin(url.hostname)) {
            return true;
        }

        return false;
    } catch {
        return false;
    }
}

const corsOptions: CorsOptions = {
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

app.use(helmet());
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use((req: Request, res: Response, next: NextFunction) => {
    const incomingRequestId = req.headers["x-request-id"];
    const requestIdRaw = Array.isArray(incomingRequestId)
        ? incomingRequestId[0]
        : incomingRequestId;
    const requestId = (requestIdRaw ?? randomUUID()).toString().slice(0, 120);

    req.requestId = requestId;
    res.setHeader("x-request-id", requestId);
    next();
});

app.use(
    express.json({
        limit: "200kb",
        verify: (req, _res, buffer) => {
            (req as Request & { rawBody?: string }).rawBody = buffer.toString("utf-8");
        },
    })
);
app.use(
    express.urlencoded({
        extended: true,
        limit: "200kb",
        verify: (req, _res, buffer) => {
            // Alguns provedores enviam webhook como x-www-form-urlencoded.
            const request = req as Request & { rawBody?: string };
            if (!request.rawBody) {
                request.rawBody = buffer.toString("utf-8");
            }
        },
    })
);

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas requisições. Tente novamente em alguns minutos.",
    },
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas de login. Tente novamente em alguns minutos.",
    },
});

const webhookLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas no webhook. Aguarde alguns minutos.",
    },
});

const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas de refresh. Aguarde alguns minutos.",
    },
});

const logoutLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas de logout. Aguarde alguns minutos.",
    },
});

app.use(globalLimiter);

function getHeaderString(
    value: string | string[] | undefined
): string | undefined {
    if (!value) {
        return undefined;
    }

    return Array.isArray(value) ? value[0] : value;
}

function getClientIp(req: Request): string {
    return req.ip || req.socket.remoteAddress || "desconhecido";
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

function getCookie(req: Request, name: string): string | undefined {
    const cookieHeader = getHeaderString(req.headers.cookie);
    const cookies = parseCookieHeader(cookieHeader);
    const value = cookies[name];
    return value?.trim() || undefined;
}

type CookieSameSite = "Lax" | "Strict" | "None";

interface CookieConfig {
    maxAgeSec: number;
}

function getCookieSameSite(): CookieSameSite {
    if (rawAuthCookieSameSite === "strict") {
        return "Strict";
    }
    if (rawAuthCookieSameSite === "none") {
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

    if (authCookieSecure) {
        parts.push("Secure");
    }
    if (authCookieDomain) {
        parts.push(`Domain=${authCookieDomain}`);
    }

    return parts.join("; ");
}

function writeAuthCookies(res: Response, accessToken: string, refreshToken: string): void {
    if (!authCookiesEnabled) {
        return;
    }

    res.setHeader("Set-Cookie", [
        buildSetCookieHeader(accessTokenCookieName, accessToken, {
            maxAgeSec: accessTokenCookieMaxAgeSec,
        }),
        buildSetCookieHeader(refreshTokenCookieName, refreshToken, {
            maxAgeSec: refreshTokenCookieMaxAgeSec,
        }),
    ]);
}

function clearAuthCookies(res: Response): void {
    if (!authCookiesEnabled) {
        return;
    }

    res.setHeader("Set-Cookie", [
        buildSetCookieHeader(accessTokenCookieName, "", { maxAgeSec: 0 }),
        buildSetCookieHeader(refreshTokenCookieName, "", { maxAgeSec: 0 }),
    ]);
}

function normalizeWebhookSignature(signature: string): string {
    return signature.startsWith("sha256=") ? signature.slice(7) : signature;
}

function isTimestampWithinTolerance(timestampSeconds: number): boolean {
    const nowSeconds = Math.floor(Date.now() / 1000);
    return Math.abs(nowSeconds - timestampSeconds) <= webhookToleranceSeconds;
}

function isWebhookLegacySecretValid(receivedSecret: string | undefined): boolean {
    if (!receivedSecret) {
        return false;
    }

    const receivedBuffer = Buffer.from(receivedSecret, "utf-8");
    const expectedBuffer = Buffer.from(webhookSecret, "utf-8");

    if (receivedBuffer.length !== expectedBuffer.length) {
        return false;
    }

    return timingSafeEqual(receivedBuffer, expectedBuffer);
}

async function isWebhookSignatureValid(
    signatureHeader: string | undefined,
    timestampHeader: string | undefined,
    rawBody: string
): Promise<boolean> {
    if (!signatureHeader || !timestampHeader || !rawBody) {
        return false;
    }

    const timestampSeconds = Number(timestampHeader);

    if (!Number.isFinite(timestampSeconds) || !isTimestampWithinTolerance(timestampSeconds)) {
        return false;
    }

    const payloadToSign = `${timestampHeader}.${rawBody}`;
    const expectedSignature = createHmac("sha256", webhookSecret)
        .update(payloadToSign)
        .digest("hex");
    const normalizedSignature = normalizeWebhookSignature(signatureHeader.trim());

    const receivedBuffer = Buffer.from(normalizedSignature, "utf-8");
    const expectedBuffer = Buffer.from(expectedSignature, "utf-8");

    if (receivedBuffer.length !== expectedBuffer.length) {
        return false;
    }

    const isValid = timingSafeEqual(receivedBuffer, expectedBuffer);

    if (!isValid) {
        return false;
    }

    const replayKeyHash = createHash("sha256")
        .update(`${timestampHeader}:${normalizedSignature}`)
        .digest("hex");
    const expUnix = Math.floor(Date.now() / 1000) + webhookToleranceSeconds;

    return banco.registrarWebhookReplay(replayKeyHash, expUnix);
}

function resumirPayloadWebhook(payload: unknown): Record<string, unknown> {
    const leadsAdd = Array.isArray((payload as any)?.leads?.add)
        ? (payload as any).leads.add.length
        : 0;
    const leadsUpdate = Array.isArray((payload as any)?.leads?.update)
        ? (payload as any).leads.update.length
        : 0;

    return {
        leadsAdd,
        leadsUpdate,
        possuiLeadDireto: Boolean(
            (payload as any)?.id &&
                (payload as any)?.pipeline_id &&
                (payload as any)?.status_id &&
                (payload as any)?.responsible_user_id
        ),
    };
}

function isMensagemValidacao(msg: string): boolean {
    const mensagensValidacao = [
        "inválido",
        "obrigatório",
        "longo",
        "curto",
        "caracteres",
        "email",
        "login",
        "senha",
        "acesso",
        "Já existe",
        "ID de usuário",
    ];

    return mensagensValidacao.some((mensagem) =>
        msg.toLowerCase().includes(mensagem.toLowerCase())
    );
}

function responderErro(
    res: Response,
    error: unknown,
    mensagemGenerica: string
): Response {
    if (error instanceof ValidationError) {
        return res.status(400).json({ message: error.message });
    }

    if (error instanceof Error && isMensagemValidacao(error.message)) {
        return res.status(400).json({ message: error.message });
    }

    return res.status(500).json({ message: mensagemGenerica });
}

function validarEntrada<T>(
    schema: z.ZodType<T>,
    payload: unknown,
    res: Response
): T | null {
    const parsed = schema.safeParse(payload);

    if (!parsed.success) {
        const issue = parsed.error.issues[0];
        res.status(400).json({
            message: issue?.message ?? "Dados inválidos.",
        });
        return null;
    }

    return parsed.data;
}

function normalizarLoginChave(login: string): string {
    return login.trim().toLowerCase();
}

function buildLoginAttemptKey(login: string, ip: string): string {
    return `${normalizarLoginChave(login)}|${ip}`;
}

async function registrarAuditoriaSeguro(
    evento: string,
    resultado: "sucesso" | "falha" | "negado",
    metadados: Record<string, unknown>
): Promise<void> {
    try {
        await banco.registrarAuditoria(evento, resultado, metadados);
    } catch (error) {
        console.error("Falha ao registrar auditoria.", error);
    }
}

function isArgon2Hash(hash: string): boolean {
    return hash.startsWith("$argon2");
}

function isBcryptHash(hash: string): boolean {
    return (
        hash.startsWith("$2a$") ||
        hash.startsWith("$2b$") ||
        hash.startsWith("$2y$")
    );
}

function gerarRefreshToken(): string {
    return randomBytes(48).toString("hex");
}

function getRefreshTokenExpUnix(): number {
    return Math.floor(Date.now() / 1000) + refreshTokenTtlDays * 24 * 60 * 60;
}

app.get("/", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true, message: "Backend funcionando" });
});

app.post("/webhook", webhookLimiter, async (req: Request, res: Response) => {
    const signatureHeader =
        getHeaderString(req.headers["x-webhook-signature"]) ??
        getHeaderString(req.headers["x-signature"]);
    const timestampHeader =
        getHeaderString(req.headers["x-webhook-timestamp"]) ??
        getHeaderString(req.headers["x-timestamp"]);
    const legacySecretHeader = getHeaderString(req.headers["x-webhook-secret"]);
    const rawBody = req.rawBody ?? "";
    const hmacValido = await isWebhookSignatureValid(signatureHeader, timestampHeader, rawBody);
    const legadoValido =
        webhookAllowLegacySecret && isWebhookLegacySecretValid(legacySecretHeader);
    const webhookAutenticado = hmacValido || legadoValido;

    if (!webhookAutenticado) {
        await registrarAuditoriaSeguro("webhook_recebido", "negado", {
            ip: getClientIp(req),
            motivo: "assinatura inválida",
            possuiAssinatura: Boolean(signatureHeader),
            possuiTimestamp: Boolean(timestampHeader),
            possuiRawBody: Boolean(rawBody),
            legadoHabilitado: webhookAllowLegacySecret,
            possuiHeaderLegado: Boolean(legacySecretHeader),
            bypassAutenticacaoWebhook: true,
            requestId: req.requestId ?? null,
        });
        console.warn("Webhook sem autenticacao valida foi aceito por bypass temporario.", {
            requestId: req.requestId ?? null,
            ip: getClientIp(req),
        });
    }

    console.log("Webhook recebido.", {
        method: req.method,
        path: req.path,
        origin: req.headers.origin ?? null,
        userAgent: req.headers["user-agent"] ?? null,
    });

    try {
        const data = validarEntrada(webhookSchema, req.body, res);

        if (!data) {
            await registrarAuditoriaSeguro("webhook_recebido", "falha", {
                ip: getClientIp(req),
                motivo: "payload inválido",
                requestId: req.requestId ?? null,
            });
            return;
        }

        const payload = data as Record<string, any>;

        console.log("Resumo do payload do webhook.", resumirPayloadWebhook(payload));

        await banco.salvarWebhook("kommo_event", payload);

        const leadsAdd = Array.isArray(payload?.leads?.add) ? payload.leads.add : [];
        const leadsUpdate = Array.isArray(payload?.leads?.update) ? payload.leads.update : [];

        console.log("Quantidade leads.add:", leadsAdd.length);
        console.log("Quantidade leads.update:", leadsUpdate.length);

        for (const lead of leadsAdd) {
            try {
                console.log(`Processando lead_add ID=${lead?.id}`);
                await banco.salvarWebhook("lead_add", lead);
                await banco.processarLead(lead);
            } catch (error) {
                console.error(`Erro ao processar lead_add ID=${lead?.id}:`, error);
            }
        }

        for (const lead of leadsUpdate) {
            try {
                console.log(`Processando lead_update ID=${lead?.id}`);
                await banco.salvarWebhook("lead_update", lead);
                await banco.processarLead(lead);
            } catch (error) {
                console.error(`Erro ao processar lead_update ID=${lead?.id}:`, error);
            }
        }

        const ehLeadDireto =
            payload &&
            payload.id &&
            payload.pipeline_id &&
            payload.status_id &&
            payload.responsible_user_id;

        if (ehLeadDireto) {
            try {
                console.log(`Processando lead direto ID=${payload.id}`);
                await banco.salvarWebhook("lead_direct", payload);
                await banco.processarLead(payload);
            } catch (error) {
                console.error(`Erro ao processar lead direto ID=${payload?.id}:`, error);
            }
        }

        await registrarAuditoriaSeguro("webhook_recebido", "sucesso", {
            ip: getClientIp(req),
            resumo: resumirPayloadWebhook(payload),
            requestId: req.requestId ?? null,
            autenticacao: hmacValido
                ? "hmac"
                : legadoValido
                  ? "legado"
                  : "bypass_sem_validacao",
        });

        return res.sendStatus(200);
    } catch (error) {
        console.error("ERRO WEBHOOK:", error);
        await registrarAuditoriaSeguro("webhook_recebido", "falha", {
            ip: getClientIp(req),
            motivo: "erro interno",
            requestId: req.requestId ?? null,
        });

        return res.status(500).json({
            message: "Erro no webhook",
        });
    }
});

app.get(
    "/relatorio",
    autenticarToken,
    autorizarAdmin,
    async (_req: Request, res: Response) => {
        try {
            const dados = await banco.relatorioLeads();
            return res.json(dados);
        } catch (error) {
            console.error("Erro ao gerar relatório.", error);
            return res.status(500).json({ message: "Erro ao gerar relatório" });
        }
    }
);

app.get(
    "/relatorio/total-ganho",
    autenticarToken,
    autorizarAdmin,
    async (_req: Request, res: Response) => {
        try {
            const total = await banco.totalLeadsGanhos();
            return res.json({ total });
        } catch (error) {
            console.error("Erro ao buscar total de leads ganhos.", error);
            return res
                .status(500)
                .json({ message: "Erro ao buscar total de leads ganhos" });
        }
    }
);

app.post("/login", loginLimiter, async (req: Request, res: Response) => {
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
                message:
                    "Muitas tentativas de login. Aguarde alguns minutos e tente novamente.",
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

        let senhaValida = false;
        let precisaMigrarHash = false;

        const senhaDigitada = senha;
        const senhaComPepper = senhaDigitada + passwordPepper;

        if (isArgon2Hash(usuario.senha)) {
            senhaValida = await argon2.verify(usuario.senha, senhaComPepper);

            if (!senhaValida) {
                const senhaValidaSemPepper = await argon2.verify(
                    usuario.senha,
                    senhaDigitada
                );

                if (senhaValidaSemPepper) {
                    senhaValida = true;
                    precisaMigrarHash = true;
                }
            }
        } else if (isBcryptHash(usuario.senha)) {
            senhaValida = await bcrypt.compare(senhaDigitada, usuario.senha);

            if (senhaValida) {
                precisaMigrarHash = true;
            }
        } else {
            await banco.registrarFalhaLogin(loginAttemptKey, LOGIN_LOCK_BASE_MS, LOGIN_LOCK_MAX_MS);
            await registrarAuditoriaSeguro("login", "falha", {
                userLogin,
                ip,
                motivo: "hash inválido",
                requestId: req.requestId ?? null,
            });
            return res.status(401).json({
                message: "Usuário ou senha incorretos",
            });
        }

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
            await banco.atualizarHashSenha(usuario.id, senhaDigitada);
        }

        const token = jwt.sign(
            {
                id: usuario.id,
                userLogin: usuario.userLogin,
                acesso: usuario.acesso,
            },
            secret,
            {
                expiresIn: "30m",
                algorithm: "HS256",
                issuer: jwtIssuer,
                audience: jwtAudience,
                jwtid: randomUUID(),
                subject: String(usuario.id),
            }
        );
        const refreshToken = gerarRefreshToken();
        const refreshFamilyId = randomUUID();

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

app.post("/auth/refresh", refreshLimiter, async (req: Request, res: Response) => {
    try {
        const parsedBody = validarEntrada(refreshSchema, req.body ?? {}, res);

        if (!parsedBody) {
            return;
        }

        const refreshToken = parsedBody.refreshToken ?? getCookie(req, refreshTokenCookieName);

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

        const novoAccessToken = jwt.sign(
            {
                id: usuario.id,
                userLogin: usuario.userLogin,
                acesso: usuario.acesso,
            },
            secret,
            {
                expiresIn: "30m",
                algorithm: "HS256",
                issuer: jwtIssuer,
                audience: jwtAudience,
                jwtid: randomUUID(),
                subject: String(usuario.id),
            }
        );

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

app.post("/logout", logoutLimiter, autenticarToken, async (req: AuthRequest, res: Response) => {
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
        const refreshToken = parsedBody.refreshToken ?? getCookie(req, refreshTokenCookieName);
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

app.post(
    "/usuarios",
    autenticarToken,
    autorizarAdmin,
    async (req: Request, res: Response) => {
        try {
            const parsedBody = validarEntrada(createUserSchema, req.body, res);

            if (!parsedBody) {
                return;
            }

            const { nome, email, acesso, setor, userLogin, senha } = parsedBody;

            await banco.insertUser({
                nome,
                email,
                acesso,
                setor,
                userLogin,
                senha,
            });

            await registrarAuditoriaSeguro("usuario_criar", "sucesso", {
                adminId: (req as AuthRequest).user?.id ?? null,
                userLoginCriado: userLogin,
                ip: getClientIp(req),
                requestId: req.requestId ?? null,
            });

            return res.status(201).json({
                message: "Usuário cadastrado com sucesso",
            });
        } catch (error) {
            console.error("Erro ao cadastrar usuário.", error);
            await registrarAuditoriaSeguro("usuario_criar", "falha", {
                userId: (req as AuthRequest).user?.id ?? null,
                ip: getClientIp(req),
                requestId: req.requestId ?? null,
            });
            return responderErro(res, error, "Erro do servidor");
        }
    }
);

app.get(
    "/usuarios",
    autenticarToken,
    autorizarAdmin,
    async (_req: Request, res: Response) => {
        try {
            const usuarios = await banco.listUser();
            return res.json(usuarios);
        } catch (error) {
            console.error("Erro ao listar usuários.", error);
            return res.status(500).json({ message: "Erro ao listar usuários" });
        }
    }
);

app.get(
    "/usuarios/:id",
    autenticarToken,
    autorizarAdmin,
    async (req: Request, res: Response) => {
        try {
            const parsedParams = validarEntrada(idParamSchema, req.params, res);

            if (!parsedParams) {
                return;
            }

            const usuario = await banco.findUserByid(parsedParams.id);

            if (!usuario) {
                return res.status(404).json({ message: "Usuário não encontrado" });
            }

            return res.json(usuario);
        } catch (error) {
            console.error("Erro ao buscar usuário.", error);
            return responderErro(res, error, "Erro ao buscar usuário");
        }
    }
);

app.put(
    "/usuarios/:id",
    autenticarToken,
    autorizarAdmin,
    async (req: AuthRequest, res: Response) => {
        try {
            const parsedParams = validarEntrada(idParamSchema, req.params, res);

            if (!parsedParams) {
                return;
            }

            const parsedBody = validarEntrada(updateUserSchema, req.body, res);

            if (!parsedBody) {
                return;
            }

            const adminId = req.user?.id;
            const targetId = Number(parsedParams.id);

            if (adminId === targetId && parsedBody.acesso !== "administrador") {
                return res.status(400).json({
                    message: "Você não pode alterar o próprio nível de acesso.",
                });
            }

            const usuarioExistente = await banco.findUserByid(parsedParams.id);

            if (!usuarioExistente) {
                return res.status(404).json({ message: "Usuário não encontrado" });
            }

            const { nome, email, acesso, setor, userLogin, senha } = parsedBody;

            await banco.updateUser(parsedParams.id, {
                nome,
                email,
                acesso,
                setor,
                userLogin,
                senha,
            });

            await registrarAuditoriaSeguro("usuario_atualizar", "sucesso", {
                adminId,
                targetId,
                ip: getClientIp(req),
                requestId: req.requestId ?? null,
            });

            return res.json({ message: "Usuário atualizado" });
        } catch (error) {
            console.error("Erro ao atualizar usuário.", error);
            await registrarAuditoriaSeguro("usuario_atualizar", "falha", {
                adminId: req.user?.id ?? null,
                targetId: req.params.id,
                ip: getClientIp(req),
                requestId: req.requestId ?? null,
            });
            return responderErro(res, error, "Erro ao atualizar usuário");
        }
    }
);

app.delete(
    "/usuarios/:id",
    autenticarToken,
    autorizarAdmin,
    async (req: AuthRequest, res: Response) => {
        try {
            const parsedParams = validarEntrada(idParamSchema, req.params, res);

            if (!parsedParams) {
                return;
            }

            const adminId = req.user?.id;
            const targetId = Number(parsedParams.id);

            if (adminId === targetId) {
                return res.status(400).json({
                    message: "Você não pode excluir a própria conta.",
                });
            }

            const usuarioExistente = await banco.findUserByid(parsedParams.id);

            if (!usuarioExistente) {
                return res.status(404).json({ message: "Usuário não encontrado" });
            }

            await banco.excludeUser(parsedParams.id);

            await registrarAuditoriaSeguro("usuario_excluir", "sucesso", {
                adminId,
                targetId,
                ip: getClientIp(req),
                requestId: req.requestId ?? null,
            });

            return res.json({ message: "Usuário excluído" });
        } catch (error) {
            console.error("Erro ao excluir usuário.", error);
            await registrarAuditoriaSeguro("usuario_excluir", "falha", {
                adminId: req.user?.id ?? null,
                targetId: req.params.id,
                ip: getClientIp(req),
                requestId: req.requestId ?? null,
            });
            return responderErro(res, error, "Erro ao excluir usuário");
        }
    }
);

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error("Erro global.", err.message);

    if (err.message.includes("CORS")) {
        return res.status(403).json({ message: err.message });
    }

    if ((err as any)?.type === "entity.too.large") {
        return res.status(413).json({ message: "Payload muito grande" });
    }

    return res.status(500).json({ message: "Erro interno do servidor" });
});

const PORT = process.env.PORT || 8000;

async function startServer(): Promise<void> {
    await banco.inicializarTabelasSeguranca();

    app.listen(PORT, () => {
        console.log(`Servidor iniciado na porta ${PORT}`);
        console.log("Timezone:", Intl.DateTimeFormat().resolvedOptions().timeZone);
        console.log("Data servidor:", new Date().toString());
    });
}

void startServer().catch((error) => {
    console.error("Falha ao iniciar servidor com segurança reforçada.", error);
    process.exit(1);
});

export default app;
