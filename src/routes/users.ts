import { Router } from "express";
import { banco } from "../db/bancoMysql";
import { autenticarToken, AuthRequest } from "../middlewares/auth";
import { autorizarAdmin } from "../middlewares/autorizarAdmin";
import { createUserSchema, idParamSchema, updateProfileSchema, updateUserSchema } from "../schemas";
import { registrarAuditoriaSeguro } from "../services/auditoria";
import { getClientIp } from "../utils/request";
import { responderErro, validarEntrada } from "../utils/validation";

export const usersRouter = Router();

usersRouter.put("/perfil", autenticarToken, async (req: AuthRequest, res) => {
    try {
        const parsedBody = validarEntrada(updateProfileSchema, req.body, res);

        if (!parsedBody) {
            return;
        }

        const userId = req.user?.id;

        if (!userId) {
            return res.sendStatus(401);
        }

        await banco.atualizarNomePerfil(userId, parsedBody.nome);

        const usuarioAtualizado = await banco.findUserByid(String(userId));

        if (!usuarioAtualizado) {
            return res.status(404).json({ message: "Usuário não encontrado" });
        }

        await registrarAuditoriaSeguro("perfil_atualizar", "sucesso", {
            userId,
            ip: getClientIp(req),
            requestId: req.requestId ?? null,
        });

        return res.json({
            message: "Perfil atualizado com sucesso",
            usuario: {
                id: usuarioAtualizado.id,
                nome: usuarioAtualizado.nome,
                acesso: usuarioAtualizado.acesso,
                email: usuarioAtualizado.email,
            },
        });
    } catch (error) {
        console.error("Erro ao atualizar perfil.", error);

        await registrarAuditoriaSeguro("perfil_atualizar", "falha", {
            userId: req.user?.id ?? null,
            ip: getClientIp(req),
            requestId: req.requestId ?? null,
        });

        return responderErro(res, error, "Erro ao atualizar perfil");
    }
});

usersRouter.post("/usuarios", autenticarToken, autorizarAdmin, async (req, res) => {
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
});

usersRouter.get("/usuarios", autenticarToken, autorizarAdmin, async (_req, res) => {
    try {
        const usuarios = await banco.listUser();
        return res.json(usuarios);
    } catch (error) {
        console.error("Erro ao listar usuários.", error);
        return res.status(500).json({ message: "Erro ao listar usuários" });
    }
});

usersRouter.get("/usuarios/:id", autenticarToken, autorizarAdmin, async (req, res) => {
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
});

usersRouter.put("/usuarios/:id", autenticarToken, autorizarAdmin, async (req: AuthRequest, res) => {
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
});

usersRouter.delete(
    "/usuarios/:id",
    autenticarToken,
    autorizarAdmin,
    async (req: AuthRequest, res) => {
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
