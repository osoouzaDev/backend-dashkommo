import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth";

export function autorizarAdmin(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {

  if (!req.user) {
    return res.sendStatus(401);
  }

  if (req.user.acesso !== "administrador") {
    return res.status(403).json({
      message: "Acesso negado. Apenas administradores."
    });
  }

  next();
}