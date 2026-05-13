import { NextFunction, Request, Response } from "express";

export function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction): Response {
    console.error("Erro global.", err.message);

    if (err.message.includes("CORS")) {
        return res.status(403).json({ message: err.message });
    }

    const errorWithType = err as Error & { type?: string };
    if (errorWithType.type === "entity.too.large") {
        return res.status(413).json({ message: "Payload muito grande" });
    }

    return res.status(500).json({ message: "Erro interno do servidor" });
}
