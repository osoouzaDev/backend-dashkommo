import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import cors, { CorsOptions } from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { banco } from "./db/bancoMysql";
import { autenticarToken, AuthRequest } from "./middlewares/auth";
import { autorizarAdmin } from "./middlewares/autorizarAdmin";
import { tokenBlacklist } from "./middlewares/token-blacklist";

export class ValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ValidationError";
    }
}

const app = express();

function getRequiredEnv(name: string): string {
    const value = process.env[name]?.trim();
    if (!value) {
        throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
    }
    return value;
}

const secret = getRequiredEnv("JWT_SECRET");
const webhookSecret = getRequiredEnv("WEBHOOK_SECRET");

const allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "https://frontend-dashkommo.vercel.app",
];

function isAllowedOrigin(origin: string): boolean {
    if (allowedOrigins.includes(origin)) {
        return true;
    }

    try {
        const url = new URL(origin);

        if (url.protocol !== "https:") {
            return false;
        }

        if (url.hostname === "frontend-dashkommo.vercel.app") {
            return true;
        }

        if (url.hostname.endsWith(".vercel.app")) {
            return true;
        }

        return false;
    } catch {
        return false;
    }
}

const corsOptions: CorsOptions = {
    origin: (origin, callback) => {
        // Postman, Insomnia, curl e chamadas servidor-servidor costumam vir sem Origin
        if (!origin) {
            return callback(null, true);
        }

        if (isAllowedOrigin(origin)) {
            return callback(null, true);
        }

        return callback(new Error(`Origem não permitida pelo CORS: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-webhook-secret"],
    credentials: true,
    optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));

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
    windowMs: 1 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas requisições no webhook.",
    },
});

function comparacaoSegura(a: string, b: string): boolean {
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

const MENSAGENS_VALIDACAO = [
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

function isMensagemValidacao(msg: string): boolean {
    return MENSAGENS_VALIDACAO.some((mensagem) =>
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

app.get("/", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true, message: "Backend funcionando" });
});

app.post("/webhook", webhookLimiter, async (req: Request, res: Response) => {
    const receivedSecret = req.header("x-webhook-secret") ?? "";

    if (!comparacaoSegura(receivedSecret, webhookSecret)) {
        return res.status(403).json({ message: "Webhook não autorizado" });
    }

    try {
        const data = req.body;

        await banco.salvarWebhook("kommo_event", data);

        const leadsAdd: unknown[] = Array.isArray(data?.leads?.add)
            ? data.leads.add
            : [];

        const leadsUpdate: unknown[] = Array.isArray(data?.leads?.update)
            ? data.leads.update
            : [];

        console.log("Webhook recebido.", {
            leadsAdd: leadsAdd.length,
            leadsUpdate: leadsUpdate.length,
            leadDireto: Boolean(
                data?.id &&
                data?.pipeline_id &&
                data?.status_id &&
                data?.responsible_user_id
            ),
        });

        for (const lead of leadsAdd) {
            try {
                await banco.salvarWebhook("lead_add", lead);
                await banco.processarLead(lead);
            } catch {
                console.error("Erro ao processar lead_add.", {
                    leadId: (lead as any)?.id ?? null,
                });
            }
        }

        for (const lead of leadsUpdate) {
            try {
                await banco.salvarWebhook("lead_update", lead);
                await banco.processarLead(lead);
            } catch {
                console.error("Erro ao processar lead_update.", {
                    leadId: (lead as any)?.id ?? null,
                });
            }
        }

        const ehLeadDireto =
            data?.id &&
            data?.pipeline_id &&
            data?.status_id &&
            data?.responsible_user_id;

        if (ehLeadDireto) {
            try {
                await banco.salvarWebhook("lead_direct", data);
                await banco.processarLead(data);
            } catch {
                console.error("Erro ao processar lead direto.", {
                    leadId: data?.id ?? null,
                });
            }
        }

        return res.sendStatus(200);
    } catch (error) {
        console.error("Erro no webhook.", error);
        return res.status(500).json({ message: "Erro no webhook" });
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
        const { userLogin, senha } = req.body;

        if (!userLogin || !senha) {
            return res.status(400).json({
                message: "Login e senha são obrigatórios",
            });
        }

        const usuarios = await banco.findByLogin(String(userLogin));
        const usuario = usuarios[0];

        if (!usuario) {
            return res.status(401).json({
                message: "Usuário ou senha incorretos",
            });
        }

        const senhaValida = await bcrypt.compare(String(senha), usuario.senha);

        if (!senhaValida) {
            return res.status(401).json({
                message: "Usuário ou senha incorretos",
            });
        }

        const token = jwt.sign(
            {
                id: usuario.id,
                userLogin: usuario.userLogin,
                acesso: usuario.acesso,
            },
            secret,
            { expiresIn: "2h" }
        );

        return res.json({
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                acesso: usuario.acesso,
            },
        });
    } catch (error) {
        console.error("Erro no login.", error);
        return res.status(500).json({ message: "Erro no login" });
    }
});

app.post("/logout", autenticarToken, (req: AuthRequest, res: Response) => {
    const token = req.headers["authorization"]?.split(" ")[1];

    if (token) {
        tokenBlacklist.add(token);
    }

    return res.json({ message: "Logout realizado com sucesso" });
});

app.post(
    "/usuarios",
    autenticarToken,
    autorizarAdmin,
    async (req: Request, res: Response) => {
        try {
            const { nome, email, acesso, setor, userLogin, senha } = req.body;

            await banco.insertUser({
                nome,
                email,
                acesso,
                setor,
                userLogin,
                senha,
            });

            return res.status(201).json({
                message: "Usuário cadastrado com sucesso",
            });
        } catch (error) {
            console.error("Erro ao cadastrar usuário.", error);
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
            const usuario = await banco.findUserByid(req.params.id);

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
            const adminId = req.user?.id;
            const targetId = Number(req.params.id);

            if (adminId === targetId && req.body.acesso !== "administrador") {
                return res.status(400).json({
                    message: "Você não pode alterar o próprio nível de acesso.",
                });
            }

            const usuarioExistente = await banco.findUserByid(req.params.id);

            if (!usuarioExistente) {
                return res.status(404).json({ message: "Usuário não encontrado" });
            }

            const { nome, email, acesso, setor, userLogin, senha } = req.body;

            await banco.updateUser(req.params.id, {
                nome,
                email,
                acesso,
                setor,
                userLogin,
                senha,
            });

            return res.json({ message: "Usuário atualizado" });
        } catch (error) {
            console.error("Erro ao atualizar usuário.", error);
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
            const adminId = req.user?.id;
            const targetId = Number(req.params.id);

            if (adminId === targetId) {
                return res.status(400).json({
                    message: "Você não pode excluir a própria conta.",
                });
            }

            const usuarioExistente = await banco.findUserByid(req.params.id);

            if (!usuarioExistente) {
                return res.status(404).json({ message: "Usuário não encontrado" });
            }

            await banco.excludeUser(req.params.id);

            return res.json({ message: "Usuário excluído" });
        } catch (error) {
            console.error("Erro ao excluir usuário.", error);
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

app.listen(PORT, () => {
    console.log(`Servidor iniciado na porta ${PORT}`);
    console.log("Timezone:", Intl.DateTimeFormat().resolvedOptions().timeZone);
    console.log("Data servidor:", new Date().toString());
});

export default app;