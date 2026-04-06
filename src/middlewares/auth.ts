import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface TokenPayload {
  id: number;
  userLogin: string;
  acesso: string;
}

export interface AuthRequest extends Request {
  user?: TokenPayload;
}

const secret = process.env.JWT_SECRET as string;

if (!secret) {
  throw new Error("JWT_SECRET não configurado");
}

export function autenticarToken(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {

  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  try {
    const decoded = jwt.verify(token, secret) as TokenPayload
    req.user = decoded
    next();
  } catch {
    return res.sendStatus(403);
  }
}