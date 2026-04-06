import "dotenv/config";
import express, { Request, Response } from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { banco } from "./db/bancoMysql";
import { autenticarToken } from "./middlewares/auth";
import { autorizarAdmin } from "./middlewares/autorizarAdmin";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const secret = process.env.JWT_SECRET as string;

if (!secret) {
    throw new Error("JWT_SECRET não configurado");
}

app.post("/webhook", async (req: Request, res: Response) => {
    try {
        const data = req.body;

        console.log("Webhook recebido:");
        console.log(JSON.stringify(data, null, 2));

        await banco.salvarWebhook("kommo_event", data);

        const leadsAdd = Array.isArray(data?.leads?.add) ? data.leads.add : [];
        const leadsUpdate = Array.isArray(data?.leads?.update) ? data.leads.update : [];

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
            data &&
            data.id &&
            data.pipeline_id &&
            data.status_id &&
            data.responsible_user_id;

        if (ehLeadDireto) {
            try {
                console.log(`Processando lead direto ID=${data.id}`);
                await banco.salvarWebhook("lead_direct", data);
                await banco.processarLead(data);
            } catch (error) {
                console.error(`Erro ao processar lead direto ID=${data?.id}:`, error);
            }
        }

        res.sendStatus(200);
    } catch (error) {
        console.error("ERRO WEBHOOK:", error);

        res.status(500).json({
            message: "Erro no webhook"
        });
    }
});

app.get("/relatorio", autenticarToken, autorizarAdmin, async (req: Request, res: Response) => {
    try {
        const dados = await banco.relatorioLeadsGanhos();
        res.json(dados);
    } catch (error) {
        console.error("ERRO RELATORIO:", error);

        res.status(500).json({
            message: "Erro ao gerar relatório"
        });
    }
});

app.get("/relatorio/total-ganho", autenticarToken, autorizarAdmin, async (req: Request, res: Response) => {
    try {
        const total = await banco.totalLeadsGanhos();

        res.json({ total });
    } catch (error) {
        console.error("ERRO TOTAL GANHO:", error);

        res.status(500).json({
            message: "Erro ao buscar total de leads ganhos"
        });
    }
});

app.post("/login", async (req: Request, res: Response) => {
    try {
        const { userLogin, senha } = req.body;

        if (!userLogin || !senha) {
            return res.status(400).json({
                message: "Login e senha são obrigatórios"
            });
        }

        const usuarios = await banco.findByLogin(userLogin);
        const usuario = usuarios[0];

        if (!usuario) {
            return res.status(401).json({
                message: "Usuário ou senha incorretos"
            });
        }

        const senhaValida = await bcrypt.compare(senha, usuario.senha);

        if (!senhaValida) {
            return res.status(401).json({
                message: "Usuário ou senha incorretos"
            });
        }

        const token = jwt.sign(
            {
                id: usuario.id,
                userLogin: usuario.userLogin,
                acesso: usuario.acesso
            },
            secret,
            { expiresIn: "2h" }
        );

        res.json({
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                acesso: usuario.acesso
            }
        });
    } catch (error) {
        console.error("ERRO LOGIN:", error);

        res.status(500).json({
            message: "Erro no login"
        });
    }
});

app.post("/usuarios", autenticarToken, autorizarAdmin, async (req: Request, res: Response) => {
    try {
        const { acesso } = req.body;

        if (!["administrador", "usuario"].includes(acesso)) {
            return res.status(400).json({
                message: "Acesso inválido"
            });
        }

        await banco.insertUser(req.body);

        res.status(201).json({
            message: "Usuário cadastrado com sucesso"
        });
    } catch (error: any) {
        console.error("ERRO CADASTRO USUARIO:", error);

        if (error.message?.includes("login") || error.message?.includes("email")) {
            return res.status(400).json({
                message: error.message
            });
        }

        res.status(500).json({
            message: "Erro do servidor"
        });
    }
});

app.get("/usuarios", autenticarToken, autorizarAdmin, async (req: Request, res: Response) => {
    try {
        const usuarios = await banco.listUser();
        res.json(usuarios);
    } catch (error) {
        console.error("ERRO LISTAR USUARIOS:", error);
        res.status(500).json({ message: "Erro ao listar usuários" });
    }
});

app.get("/usuarios/:id", autenticarToken, autorizarAdmin, async (req: Request, res: Response) => {
    try {
        const id = req.params.id as string;
        const usuario = await banco.findUserByid(id);

        if (!usuario) {
            return res.status(404).json({
                message: "Usuário não encontrado"
            });
        }

        res.json(usuario);
    } catch (error) {
        console.error("ERRO BUSCAR USUARIO:", error);
        res.status(500).json({ message: "Erro ao buscar usuário" });
    }
});

app.put("/usuarios/:id", autenticarToken, autorizarAdmin, async (req: Request, res: Response) => {
    try {
        const id = req.params.id as string;
        await banco.updateUser(id, req.body);

        res.json({
            message: "Usuário atualizado"
        });
    } catch (error) {
        console.error("ERRO ATUALIZAR USUARIO:", error);
        res.status(500).json({ message: "Erro ao atualizar usuário" });
    }
});

app.delete("/usuarios/:id", autenticarToken, autorizarAdmin, async (req: Request, res: Response) => {
    try {
        const id = req.params.id as string;
        await banco.excludeUser(id);

        res.json({
            message: "Usuário excluído"
        });
    } catch (error) {
        console.error("ERRO EXCLUIR USUARIO:", error);
        res.status(500).json({ message: "Erro ao excluir usuário" });
    }
});

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
    console.log(`SERVIDOR INICIADO NA PORTA ${PORT}`);
    console.log(" ");
    console.log("Timezone:", Intl.DateTimeFormat().resolvedOptions().timeZone);
    console.log(" ");
    console.log("Data servidor:", new Date().toString());
});

export default app;