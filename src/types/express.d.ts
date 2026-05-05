import { TokenPayload } from "../middlewares/auth";

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
      rawBody?: string;
      requestId?: string;
    }
  }
}

export {};
