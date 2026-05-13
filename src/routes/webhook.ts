import { Router } from "express";
import { banco } from "../db/bancoMysql";
import { webhookLimiter } from "../config/rateLimit";
import { env } from "../config/env";
import { webhookSchema } from "../schemas";
import { registrarAuditoriaSeguro } from "../services/auditoria";
import {
    isWebhookLegacySecretValid,
    isWebhookSignatureValid,
    resumirPayloadWebhook,
} from "../services/webhook";
import { getClientIp, getHeaderString } from "../utils/request";
import { validarEntrada } from "../utils/validation";

type WebhookPayload = {
    leads?: {
        add?: Record<string, unknown>[];
        update?: Record<string, unknown>[];
    };
    id?: unknown;
    pipeline_id?: unknown;
    status_id?: unknown;
    responsible_user_id?: unknown;
};

export const webhookRouter = Router();

webhookRouter.post("/webhook", webhookLimiter, async (req, res) => {
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
        env.webhookAllowLegacySecret && isWebhookLegacySecretValid(legacySecretHeader);
    const webhookAutenticado = hmacValido || legadoValido;

    if (!webhookAutenticado) {
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

        const payload = data as WebhookPayload & Record<string, unknown>;

        console.log("Resumo do payload do webhook.", resumirPayloadWebhook(payload));

        await banco.salvarWebhook("kommo_event", payload);

        const leadsAdd = Array.isArray(payload.leads?.add) ? payload.leads.add : [];
        const leadsUpdate = Array.isArray(payload.leads?.update) ? payload.leads.update : [];

        console.log("Quantidade leads.add:", leadsAdd.length);
        console.log("Quantidade leads.update:", leadsUpdate.length);

        for (const lead of leadsAdd) {
            try {
                console.log(`Processando lead_add ID=${String(lead.id ?? "")}`);
                await banco.salvarWebhook("lead_add", lead);
                await banco.processarLead(lead);
            } catch (error) {
                console.error(`Erro ao processar lead_add ID=${String(lead.id ?? "")}:`, error);
            }
        }

        for (const lead of leadsUpdate) {
            try {
                console.log(`Processando lead_update ID=${String(lead.id ?? "")}`);
                await banco.salvarWebhook("lead_update", lead);
                await banco.processarLead(lead);
            } catch (error) {
                console.error(`Erro ao processar lead_update ID=${String(lead.id ?? "")}:`, error);
            }
        }

        const ehLeadDireto = Boolean(
            payload && payload.id && payload.pipeline_id && payload.status_id && payload.responsible_user_id
        );

        if (ehLeadDireto) {
            try {
                console.log(`Processando lead direto ID=${String(payload.id ?? "")}`);
                await banco.salvarWebhook("lead_direct", payload);
                await banco.processarLead(payload);
            } catch (error) {
                console.error(`Erro ao processar lead direto ID=${String(payload.id ?? "")}:`, error);
            }
        }

        await registrarAuditoriaSeguro("webhook_recebido", "sucesso", {
            ip: getClientIp(req),
            resumo: resumirPayloadWebhook(payload),
            requestId: req.requestId ?? null,
            autenticacao: hmacValido ? "hmac" : legadoValido ? "legado" : "bypass_sem_validacao",
        });

        return res.sendStatus(200);
    } catch (error) {
        console.error("ERRO WEBHOOK:", error);

        await registrarAuditoriaSeguro("webhook_recebido", "falha", {
            ip: getClientIp(req),
            motivo: "erro interno",
            requestId: req.requestId ?? null,
        });

        return res.status(200).json({
            accepted: true,
            warning: "Webhook recebido com erro interno no processamento.",
        });
    }
});
