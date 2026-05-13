import { z } from "zod";

export const loginSchema = z.object({
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

export const createUserSchema = userBaseSchema.extend({
    senha: z.string().min(8).max(255),
});

export const updateUserSchema = userBaseSchema.extend({
    senha: z.string().min(8).max(255).optional(),
});

export const idParamSchema = z.object({
    id: z.string().regex(/^\d+$/),
});

export const webhookSchema = z.unknown();

export const refreshSchema = z.object({
    refreshToken: z.string().trim().min(32).max(512).optional(),
});

export const logoutSchema = z.object({
    refreshToken: z.string().trim().min(32).max(512).optional(),
});
