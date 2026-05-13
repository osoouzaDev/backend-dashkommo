import "dotenv/config";
import { createApp } from "./app";
import { env } from "./config/env";
import { banco } from "./db/bancoMysql";

const app = createApp();

async function startServer(): Promise<void> {
    await banco.inicializarTabelasSeguranca();

    app.listen(env.port, () => {
        console.log(`Servidor iniciado na porta ${env.port}`);
        console.log("Timezone:", Intl.DateTimeFormat().resolvedOptions().timeZone);
        console.log("Data servidor:", new Date().toString());
    });
}

void startServer().catch((error) => {
    console.error("Falha ao iniciar servidor com segurança reforçada.", error);
    process.exit(1);
});

export default app;
