import { Response } from "express";
import { z } from "zod";
import { ValidationError } from "../config/env";

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

export function responderErro(
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

export function validarEntrada<T>(
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
