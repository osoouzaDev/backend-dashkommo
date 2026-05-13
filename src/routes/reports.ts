import { Router } from "express";
import { banco } from "../db/bancoMysql";
import { autenticarToken } from "../middlewares/auth";
import { autorizarAdmin } from "../middlewares/autorizarAdmin";

export const reportsRouter = Router();

reportsRouter.get("/relatorio", autenticarToken, autorizarAdmin, async (_req, res) => {
    try {
        const dados = await banco.relatorioLeads();
        return res.json(dados);
    } catch (error) {
        console.error("Erro ao gerar relatório.", error);
        return res.status(500).json({ message: "Erro ao gerar relatório" });
    }
});

reportsRouter.get("/relatorio/total-ganho", autenticarToken, autorizarAdmin, async (_req, res) => {
    try {
        const total = await banco.totalLeadsGanhos();
        return res.json({ total });
    } catch (error) {
        console.error("Erro ao buscar total de leads ganhos.", error);
        return res.status(500).json({
            message: "Erro ao buscar total de leads ganhos",
        });
    }
});
