import { NextFunction, Request, Response } from "express";
import { randomUUID } from "crypto";

export function getHeaderString(value: string | string[] | undefined): string | undefined {
    if (!value) {
        return undefined;
    }

    return Array.isArray(value) ? value[0] : value;
}

export function getClientIp(req: Request): string {
    return req.ip || req.socket.remoteAddress || "desconhecido";
}

export function attachRequestId(req: Request, res: Response, next: NextFunction): void {
    const incomingRequestId = req.headers["x-request-id"];
    const requestIdRaw = Array.isArray(incomingRequestId)
        ? incomingRequestId[0]
        : incomingRequestId;
    const requestId = (requestIdRaw ?? randomUUID()).toString().slice(0, 120);

    req.requestId = requestId;
    res.setHeader("x-request-id", requestId);
    next();
}
