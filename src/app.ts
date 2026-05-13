import express from "express";
import cors from "cors";
import helmet from "helmet";
import { corsOptions } from "./config/cors";
import { globalLimiter } from "./config/rateLimit";
import { errorHandler } from "./middlewares/errorHandler";
import { authRouter } from "./routes/auth";
import { healthRouter } from "./routes/health";
import { reportsRouter } from "./routes/reports";
import { usersRouter } from "./routes/users";
import { webhookRouter } from "./routes/webhook";
import { attachRequestId } from "./utils/request";

export function createApp() {
    const app = express();

    app.disable("x-powered-by");
    app.set("trust proxy", 1);

    app.use(helmet());
    app.use(cors(corsOptions));
    app.options(/.*/, cors(corsOptions));
    app.use(attachRequestId);
    app.use(
        express.json({
            limit: "200kb",
            verify: (req, _res, buffer) => {
                const request = req as express.Request;
                request.rawBody = buffer.toString("utf-8");
            },
        })
    );
    app.use(
        express.urlencoded({
            extended: true,
            limit: "200kb",
            verify: (req, _res, buffer) => {
                const request = req as express.Request;

                if (!request.rawBody) {
                    request.rawBody = buffer.toString("utf-8");
                }
            },
        })
    );
    app.use(globalLimiter);

    app.use(healthRouter);
    app.use(webhookRouter);
    app.use(authRouter);
    app.use(reportsRouter);
    app.use(usersRouter);

    app.use(errorHandler);

    return app;
}
