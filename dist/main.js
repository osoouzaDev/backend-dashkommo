"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ValidationError = void 0;
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = __importDefault(require("crypto"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const bancoMysql_1 = require("./db/bancoMysql");
const auth_1 = require("./middlewares/auth");
const autorizarAdmin_1 = require("./middlewares/autorizarAdmin");
const token_blacklist_1 = require("./middlewares/token-blacklist");
class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}
exports.ValidationError = ValidationError;
const app = (0, express_1.default)();
function getRequiredEnv(name) {
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
function isAllowedOrigin(origin) {
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
    }
    catch {
        return false;
    }
}
const corsOptions = {
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
    allowedHeaders: ["Content-Type", "Authorization", "x-webhook-secret"],
    credentials: true,
    optionsSuccessStatus: 204,
};
app.use((0, cors_1.default)(corsOptions));
app.options(/.*/, (0, cors_1.default)(corsOptions));
app.use(express_1.default.json({ limit: "200kb" }));
app.use(express_1.default.urlencoded({ extended: true, limit: "200kb" }));
const loginLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas tentativas de login. Tente novamente em alguns minutos.",
    },
});
const webhookLimiter = (0, express_rate_limit_1.default)({
    windowMs: 1 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Muitas requisições no webhook.",
    },
});
function comparacaoSegura(a, b) {
    try {
        return crypto_1.default.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }
    catch {
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
function isMensagemValidacao(msg) {
    return MENSAGENS_VALIDACAO.some((mensagem) => msg.toLowerCase().includes(mensagem.toLowerCase()));
}
function responderErro(res, error, mensagemGenerica) {
    if (error instanceof ValidationError) {
        return res.status(400).json({ message: error.message });
    }
    if (error instanceof Error && isMensagemValidacao(error.message)) {
        return res.status(400).json({ message: error.message });
    }
    return res.status(500).json({ message: mensagemGenerica });
}
app.get("/", (_req, res) => {
    res.status(200).json({ ok: true, message: "Backend funcionando" });
});
app.post("/webhook", webhookLimiter, async (req, res) => {
    const receivedSecret = req.header("x-webhook-secret") ?? "";
    if (!comparacaoSegura(receivedSecret, webhookSecret)) {
        return res.status(403).json({ message: "Webhook não autorizado" });
    }
    try {
        const data = req.body;
        const webhookPrincipalId = await bancoMysql_1.banco.salvarWebhook("kommo_event", data);
        const leadsAdd = Array.isArray(data?.leads?.add)
            ? data.leads.add
            : [];
        const leadsUpdate = Array.isArray(data?.leads?.update)
            ? data.leads.update
            : [];
        const ehLeadDireto = Boolean(data?.id &&
            data?.pipeline_id &&
            data?.status_id &&
            data?.responsible_user_id);
        const diagnostico = {
            webhookPrincipalId,
            leadsAddRecebidos: leadsAdd.length,
            leadsUpdateRecebidos: leadsUpdate.length,
            ehLeadDireto,
            leadDiretoProcessado: false,
            leadDiretoErro: null,
            leadsAddProcessados: 0,
            leadsAddErros: [],
            leadsUpdateProcessados: 0,
            leadsUpdateErros: [],
            dbHost: process.env.DB_HOST,
            dbName: process.env.DB_NAME,
        };
        console.log("Webhook recebido.", diagnostico);
        for (const lead of leadsAdd) {
            try {
                await bancoMysql_1.banco.salvarWebhook("lead_add", lead);
                await bancoMysql_1.banco.processarLead(lead);
                diagnostico.leadsAddProcessados += 1;
            }
            catch (error) {
                const erro = error instanceof Error ? error.message : "Erro desconhecido";
                diagnostico.leadsAddErros.push({
                    leadId: lead?.id ?? null,
                    erro,
                });
                console.error("Erro ao processar lead_add.", {
                    leadId: lead?.id ?? null,
                    erro,
                });
            }
        }
        for (const lead of leadsUpdate) {
            try {
                await bancoMysql_1.banco.salvarWebhook("lead_update", lead);
                await bancoMysql_1.banco.processarLead(lead);
                diagnostico.leadsUpdateProcessados += 1;
            }
            catch (error) {
                const erro = error instanceof Error ? error.message : "Erro desconhecido";
                diagnostico.leadsUpdateErros.push({
                    leadId: lead?.id ?? null,
                    erro,
                });
                console.error("Erro ao processar lead_update.", {
                    leadId: lead?.id ?? null,
                    erro,
                });
            }
        }
        if (ehLeadDireto) {
            try {
                await bancoMysql_1.banco.salvarWebhook("lead_direct", data);
                await bancoMysql_1.banco.processarLead(data);
                diagnostico.leadDiretoProcessado = true;
            }
            catch (error) {
                const erro = error instanceof Error ? error.message : "Erro desconhecido";
                diagnostico.leadDiretoErro = erro;
                console.error("Erro ao processar lead direto.", {
                    leadId: data?.id ?? null,
                    erro,
                });
            }
        }
        return res.status(200).json({
            message: "Webhook processado",
            diagnostico,
        });
    }
    catch (error) {
        console.error("Erro no webhook.", error);
        return res.status(500).json({
            message: "Erro no webhook",
            erro: error instanceof Error ? error.message : "Erro desconhecido",
            dbHost: process.env.DB_HOST,
            dbName: process.env.DB_NAME,
        });
    }
});
app.get("/relatorio", auth_1.autenticarToken, autorizarAdmin_1.autorizarAdmin, async (_req, res) => {
    try {
        const dados = await bancoMysql_1.banco.relatorioLeads();
        return res.json(dados);
    }
    catch (error) {
        console.error("Erro ao gerar relatório.", error);
        return res.status(500).json({ message: "Erro ao gerar relatório" });
    }
});
app.get("/relatorio/total-ganho", auth_1.autenticarToken, autorizarAdmin_1.autorizarAdmin, async (_req, res) => {
    try {
        const total = await bancoMysql_1.banco.totalLeadsGanhos();
        return res.json({ total });
    }
    catch (error) {
        console.error("Erro ao buscar total de leads ganhos.", error);
        return res
            .status(500)
            .json({ message: "Erro ao buscar total de leads ganhos" });
    }
});
app.post("/login", loginLimiter, async (req, res) => {
    try {
        const { userLogin, senha } = req.body;
        if (!userLogin || !senha) {
            return res.status(400).json({
                message: "Login e senha são obrigatórios",
            });
        }
        const usuarios = await bancoMysql_1.banco.findByLogin(String(userLogin));
        const usuario = usuarios[0];
        if (!usuario) {
            return res.status(401).json({
                message: "Usuário ou senha incorretos",
            });
        }
        const senhaValida = await bcryptjs_1.default.compare(String(senha), usuario.senha);
        if (!senhaValida) {
            return res.status(401).json({
                message: "Usuário ou senha incorretos",
            });
        }
        const token = jsonwebtoken_1.default.sign({
            id: usuario.id,
            userLogin: usuario.userLogin,
            acesso: usuario.acesso,
        }, secret, { expiresIn: "2h" });
        return res.json({
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                acesso: usuario.acesso,
            },
        });
    }
    catch (error) {
        console.error("Erro no login.", error);
        return res.status(500).json({ message: "Erro no login" });
    }
});
app.post("/logout", auth_1.autenticarToken, (req, res) => {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (token) {
        token_blacklist_1.tokenBlacklist.add(token);
    }
    return res.json({ message: "Logout realizado com sucesso" });
});
app.post("/usuarios", auth_1.autenticarToken, autorizarAdmin_1.autorizarAdmin, async (req, res) => {
    try {
        const { nome, email, acesso, setor, userLogin, senha } = req.body;
        await bancoMysql_1.banco.insertUser({
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
    }
    catch (error) {
        console.error("Erro ao cadastrar usuário.", error);
        return responderErro(res, error, "Erro do servidor");
    }
});
app.get("/usuarios", auth_1.autenticarToken, autorizarAdmin_1.autorizarAdmin, async (_req, res) => {
    try {
        const usuarios = await bancoMysql_1.banco.listUser();
        return res.json(usuarios);
    }
    catch (error) {
        console.error("Erro ao listar usuários.", error);
        return res.status(500).json({ message: "Erro ao listar usuários" });
    }
});
app.get("/usuarios/:id", auth_1.autenticarToken, autorizarAdmin_1.autorizarAdmin, async (req, res) => {
    try {
        const usuario = await bancoMysql_1.banco.findUserByid(req.params.id);
        if (!usuario) {
            return res.status(404).json({ message: "Usuário não encontrado" });
        }
        return res.json(usuario);
    }
    catch (error) {
        console.error("Erro ao buscar usuário.", error);
        return responderErro(res, error, "Erro ao buscar usuário");
    }
});
app.put("/usuarios/:id", auth_1.autenticarToken, autorizarAdmin_1.autorizarAdmin, async (req, res) => {
    try {
        const adminId = req.user?.id;
        const targetId = Number(req.params.id);
        if (adminId === targetId && req.body.acesso !== "administrador") {
            return res.status(400).json({
                message: "Você não pode alterar o próprio nível de acesso.",
            });
        }
        const usuarioExistente = await bancoMysql_1.banco.findUserByid(req.params.id);
        if (!usuarioExistente) {
            return res.status(404).json({ message: "Usuário não encontrado" });
        }
        const { nome, email, acesso, setor, userLogin, senha } = req.body;
        await bancoMysql_1.banco.updateUser(req.params.id, {
            nome,
            email,
            acesso,
            setor,
            userLogin,
            senha,
        });
        return res.json({ message: "Usuário atualizado" });
    }
    catch (error) {
        console.error("Erro ao atualizar usuário.", error);
        return responderErro(res, error, "Erro ao atualizar usuário");
    }
});
app.delete("/usuarios/:id", auth_1.autenticarToken, autorizarAdmin_1.autorizarAdmin, async (req, res) => {
    try {
        const adminId = req.user?.id;
        const targetId = Number(req.params.id);
        if (adminId === targetId) {
            return res.status(400).json({
                message: "Você não pode excluir a própria conta.",
            });
        }
        const usuarioExistente = await bancoMysql_1.banco.findUserByid(req.params.id);
        if (!usuarioExistente) {
            return res.status(404).json({ message: "Usuário não encontrado" });
        }
        await bancoMysql_1.banco.excludeUser(req.params.id);
        return res.json({ message: "Usuário excluído" });
    }
    catch (error) {
        console.error("Erro ao excluir usuário.", error);
        return responderErro(res, error, "Erro ao excluir usuário");
    }
});
app.use((err, _req, res, _next) => {
    console.error("Erro global.", err.message);
    if (err.message.includes("CORS")) {
        return res.status(403).json({ message: err.message });
    }
    if (err?.type === "entity.too.large") {
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
exports.default = app;
