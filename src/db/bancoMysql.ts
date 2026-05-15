import mysql, { Pool, RowDataPacket, ResultSetHeader } from "mysql2/promise";
import argon2 from "argon2";
import { createHash } from "crypto";
import { readFileSync } from "fs";

export interface Usuario {
    id?: number;
    nome: string;
    email: string;
    acesso: "administrador" | "usuario";
    setor: string;
    userLogin: string;
    senha?: string;
}

interface UsuarioDB extends RowDataPacket {
    id: number;
    nome: string;
    email: string;
    acesso: "administrador" | "usuario";
    setor: string;
    userLogin: string;
    senha: string;
}

interface LoginLockoutDB extends RowDataPacket {
    attempt_key: string;
    fail_count: number;
    lock_until: Date | null;
}

interface RefreshTokenDB extends RowDataPacket {
    id: number;
    token_hash: string;
    user_id: number;
    family_id: string;
    expira_em: Date;
    revogado_em: Date | null;
    substituido_por_hash: string | null;
}

const TIMEZONE = "-04:00";
const MAX_LEAD_NOME = 255;

const STATUS_VALIDOS = new Set<number>([
    100504439,
    100233527,
    84315468,
    81175456,
    73520776,
    72912304,
    72897132,
    72762308,
    72670564,
    72656692,
    72649772,
    68647324,
    68432532,
    68325220,
    68325216,
    66780248,
    66773868,
    143,
    142,
]);

class BancoMysql {
    private pool: Pool;
    private readonly passwordPepper: string;
    private static readonly MAX_WEBHOOK_PAYLOAD_BYTES = 200_000;

    constructor() {
        const host = this.getRequiredEnv("DB_HOST");
        const user = this.getRequiredEnv("DB_USER");
        const password = this.getRequiredEnv("DB_PASSWORD");
        const database = this.getRequiredEnv("DB_NAME");
        const port = process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306;
        const sslMode = this.getDbSslMode();

        this.passwordPepper = this.getStrongSecretEnv("PASSWORD_PEPPER");

        if (!Number.isInteger(port) || port <= 0) {
            throw new Error("DB_PORT inválida.");
        }

        if (process.env.NODE_ENV === "production" && sslMode === "off") {
            throw new Error("DB_SSL_MODE não pode ser off em produção.");
        }

        if (user.toLowerCase() === "root") {
            throw new Error("Não use o usuário root na aplicação.");
        }

        this.pool = mysql.createPool({
            host,
            user,
            password,
            database,
            port,
            waitForConnections: true,
            connectionLimit: 10,
            timezone: TIMEZONE,
            ssl: this.getDbSslConfig(sslMode),
        });
    }

    private getDbSslMode(): "off" | "required" | "verify-ca" {
        const modeRaw = process.env.DB_SSL_MODE?.trim().toLowerCase();
        if (modeRaw) {
            if (modeRaw === "off" || modeRaw === "required" || modeRaw === "verify-ca") {
                return modeRaw;
            }

            throw new Error("DB_SSL_MODE inválido. Use off, required ou verify-ca.");
        }

        const legacyDbSsl = process.env.DB_SSL?.trim().toLowerCase();
        if (legacyDbSsl === "true") {
            return process.env.DB_SSL_REJECT_UNAUTHORIZED === "false"
                ? "required"
                : "verify-ca";
        }

        return "off";
    }

    private getDbSslConfig(
        sslMode: "off" | "required" | "verify-ca"
    ): mysql.PoolOptions["ssl"] | undefined {
        if (sslMode === "off") {
            return undefined;
        }

        const rejectUnauthorized = sslMode === "verify-ca";
        const sslCaPemRaw = process.env.DB_SSL_CA_PEM?.trim();
        const sslCaPem = sslCaPemRaw ? sslCaPemRaw.replace(/\\n/g, "\n") : undefined;
        const sslCaPath = process.env.DB_SSL_CA_PATH?.trim();
        let ca: string | undefined;

        if (sslCaPem) {
            ca = sslCaPem;
        } else if (sslCaPath) {
            ca = readFileSync(sslCaPath, "utf-8");
        }

        if (!ca) {
            return { rejectUnauthorized };
        }

        return {
            rejectUnauthorized,
            ca,
        };
    }

    private getRequiredEnv(name: string): string {
        const value = process.env[name]?.trim();

        if (!value) {
            throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
        }

        return value;
    }

    private getStrongSecretEnv(name: string, minLength = 32): string {
        const value = this.getRequiredEnv(name);

        if (value.length < minLength || value.toLowerCase().includes("change_me")) {
            throw new Error(
                `Variável ${name} fraca. Use um segredo com pelo menos ${minLength} caracteres aleatórios.`
            );
        }

        return value;
    }

    private logInfo(message: string, meta?: Record<string, unknown>): void {
        console.log(message, meta ?? "");
    }

    private logError(message: string, error: unknown, meta?: Record<string, unknown>): void {
        console.error(message, meta ?? "", error);
    }

    private normalizarEmail(email: string): string {
        return email.trim().toLowerCase();
    }

    private normalizarLogin(login: string): string {
        return login.trim();
    }

    private aplicarPepper(senha: string): string {
        return senha + this.passwordPepper;
    }

    private validarEmail(email: string): void {
        const valor = this.normalizarEmail(email);

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(valor)) {
            throw new Error("Email inválido.");
        }

        if (valor.length > 100) {
            throw new Error("Email muito longo.");
        }
    }

    private validarLogin(login: string): void {
        const valor = this.normalizarLogin(login);

        if (!valor) {
            throw new Error("Login obrigatório.");
        }

        if (valor.length < 3 || valor.length > 50) {
            throw new Error("Login deve ter entre 3 e 50 caracteres.");
        }
    }

    private validarNome(nome: string): void {
        const valor = nome.trim();

        if (!valor) {
            throw new Error("Nome obrigatório.");
        }

        if (valor.length > 50) {
            throw new Error("Nome muito longo.");
        }
    }

    private validarSetor(setor: string): void {
        const valor = setor.trim();

        if (!valor) {
            throw new Error("Setor obrigatório.");
        }

        if (valor.length > 50) {
            throw new Error("Setor muito longo.");
        }
    }

    private validarAcesso(acesso: string): asserts acesso is "administrador" | "usuario" {
        if (acesso !== "administrador" && acesso !== "usuario") {
            throw new Error("Nível de acesso inválido.");
        }
    }

    private validarSenha(senha: string): void {
        if (!senha?.trim()) {
            throw new Error("Senha obrigatória.");
        }

        if (senha.length < 8) {
            throw new Error("A senha deve ter no mínimo 8 caracteres.");
        }

        if (senha.length > 255) {
            throw new Error("A senha não pode ter mais de 255 caracteres.");
        }
    }

    private async gerarHashSenha(senha: string): Promise<string> {
        return argon2.hash(this.aplicarPepper(senha), {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 2,
        });
    }

    private validarUsuario(usuario: Usuario, exigirSenha: boolean): void {
        this.validarNome(usuario.nome);
        this.validarEmail(usuario.email);
        this.validarAcesso(usuario.acesso);
        this.validarSetor(usuario.setor);
        this.validarLogin(usuario.userLogin);

        if (exigirSenha) {
            this.validarSenha(usuario.senha ?? "");
        }
    }

    private validarPayloadWebhook(payload: unknown): void {
        if (payload === null || payload === undefined) {
            throw new Error("Payload do webhook ausente.");
        }

        let payloadString: string;

        try {
            payloadString = JSON.stringify(payload);
        } catch {
            throw new Error("Payload do webhook inválido.");
        }

        if (
            Buffer.byteLength(payloadString, "utf-8") >
            BancoMysql.MAX_WEBHOOK_PAYLOAD_BYTES
        ) {
            throw new Error("Payload do webhook excede o tamanho permitido.");
        }
    }

    async salvarWebhook(evento: string, payload: unknown): Promise<number> {
        if (!evento?.trim()) {
            throw new Error("Evento do webhook é obrigatório.");
        }

        this.validarPayloadWebhook(payload);

        const criadoEmLocal = new Date().toLocaleString("sv-SE", {
            timeZone: "America/Cuiaba",
        });

        const [result] = await this.pool.execute<ResultSetHeader>(
            "INSERT INTO webhooks (evento, payload, criado_em_local) VALUES (?, ?, ?)",
            [evento.trim(), JSON.stringify(payload), criadoEmLocal]
        );

        this.logInfo("Webhook salvo.", {
            evento: evento.trim(),
            insertId: result.insertId,
            dbHost: process.env.DB_HOST,
            dbName: process.env.DB_NAME,
        });

        return result.insertId;
    }

    async inicializarTabelasSeguranca(): Promise<void> {
        await this.pool.execute(`
            CREATE TABLE IF NOT EXISTS token_revogados (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                jti VARCHAR(128) NOT NULL UNIQUE,
                expira_em DATETIME NOT NULL,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_expira_em (expira_em)
            )
        `);

        await this.pool.execute(`
            CREATE TABLE IF NOT EXISTS auditoria_eventos (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                evento VARCHAR(100) NOT NULL,
                resultado VARCHAR(50) NOT NULL,
                metadados JSON,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_evento_criado (evento, criado_em)
            )
        `);

        await this.pool.execute(`
            CREATE TABLE IF NOT EXISTS webhook_replay (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                replay_key_hash VARCHAR(128) NOT NULL UNIQUE,
                expira_em DATETIME NOT NULL,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_webhook_replay_expira (expira_em)
            )
        `);

        await this.pool.execute(`
            CREATE TABLE IF NOT EXISTS login_lockouts (
                attempt_key VARCHAR(191) PRIMARY KEY,
                fail_count INT NOT NULL DEFAULT 0,
                lock_until DATETIME NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);

        await this.pool.execute(`
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                token_hash CHAR(64) NOT NULL UNIQUE,
                user_id BIGINT NOT NULL,
                family_id CHAR(36) NOT NULL,
                expira_em DATETIME NOT NULL,
                revogado_em DATETIME NULL,
                substituido_por_hash CHAR(64) NULL,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_refresh_user (user_id),
                INDEX idx_refresh_family (family_id),
                INDEX idx_refresh_expira (expira_em)
            )
        `);

        await this.pool.execute(`
            CREATE TABLE IF NOT EXISTS funil_vendas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                lead_id BIGINT NOT NULL UNIQUE,
                lead_nome VARCHAR(255),
                consultor_id BIGINT NOT NULL,
                consultor_nome VARCHAR(100),
                origem VARCHAR(100),
                pipeline_id BIGINT,
                status_id BIGINT,
                etapa VARCHAR(50),
                valor DECIMAL(10,2) DEFAULT 0,
                data_criacao DATETIME,
                data_atualizacao DATETIME,
                data_venda DATETIME NULL,
                INDEX idx_consultor (consultor_id),
                INDEX idx_status (status_id),
                INDEX idx_data (data_criacao),
                INDEX idx_data_venda (data_venda)
            )
        `);

        const [dataVendaColumns] = await this.pool.execute<RowDataPacket[]>(
            `SELECT COLUMN_NAME
             FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'funil_vendas'
               AND COLUMN_NAME = 'data_venda'
             LIMIT 1`
        );

        if (dataVendaColumns.length === 0) {
            await this.pool.execute(
                `ALTER TABLE funil_vendas
                 ADD COLUMN data_venda DATETIME NULL AFTER data_atualizacao`
            );
        }

        const [dataVendaIndexes] = await this.pool.execute<RowDataPacket[]>(
            `SELECT INDEX_NAME
             FROM INFORMATION_SCHEMA.STATISTICS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'funil_vendas'
               AND INDEX_NAME = 'idx_data_venda'
             LIMIT 1`
        );

        if (dataVendaIndexes.length === 0) {
            await this.pool.execute(
                `ALTER TABLE funil_vendas
                 ADD INDEX idx_data_venda (data_venda)`
            );
        }

        await this.pool.execute(
            `UPDATE funil_vendas
             SET data_venda = data_criacao
             WHERE status_id = 142
               AND data_venda IS NULL
               AND data_criacao IS NOT NULL`
        );

        await this.pool.execute(
            `UPDATE funil_vendas
             SET data_venda = data_criacao
             WHERE status_id = 142
               AND data_venda = data_atualizacao
               AND data_criacao IS NOT NULL
               AND data_atualizacao IS NOT NULL
               AND TIMESTAMPDIFF(DAY, data_criacao, data_atualizacao) >= 30`
        );

        await this.pool.execute(
            `UPDATE funil_vendas
             SET data_venda = NULL
             WHERE status_id <> 142
               AND data_venda IS NOT NULL`
        );
    }

    async revogarTokenPorJti(jti: string, expUnix: number): Promise<void> {
        if (!jti?.trim()) {
            throw new Error("JTI inválido.");
        }

        if (!Number.isFinite(expUnix) || expUnix <= 0) {
            throw new Error("Expiração do token inválida.");
        }

        const expiraEm = new Date(expUnix * 1000);

        await this.pool.execute(
            `INSERT INTO token_revogados (jti, expira_em)
             VALUES (?, ?)
             ON DUPLICATE KEY UPDATE expira_em = VALUES(expira_em)`,
            [jti.trim(), expiraEm]
        );

        await this.pool.execute(
            `DELETE FROM token_revogados
             WHERE expira_em < NOW()`
        );
    }

    async tokenRevogado(jti: string): Promise<boolean> {
        if (!jti?.trim()) {
            return true;
        }

        const [rows] = await this.pool.execute<RowDataPacket[]>(
            `SELECT 1
             FROM token_revogados
             WHERE jti = ?
               AND expira_em >= NOW()
             LIMIT 1`,
            [jti.trim()]
        );

        return rows.length > 0;
    }

    async registrarAuditoria(
        evento: string,
        resultado: "sucesso" | "falha" | "negado",
        metadados: Record<string, unknown>
    ): Promise<void> {
        if (!evento?.trim()) {
            throw new Error("Evento de auditoria inválido.");
        }

        await this.pool.execute(
            `INSERT INTO auditoria_eventos (evento, resultado, metadados)
             VALUES (?, ?, ?)`,
            [evento.trim(), resultado, JSON.stringify(metadados)]
        );
    }

    async registrarWebhookReplay(replayKeyHash: string, expUnix: number): Promise<boolean> {
        if (!replayKeyHash?.trim()) {
            throw new Error("Replay key inválida.");
        }

        if (!Number.isFinite(expUnix) || expUnix <= 0) {
            throw new Error("Expiração de replay inválida.");
        }

        const expiraEm = new Date(expUnix * 1000);

        const [result] = await this.pool.execute<ResultSetHeader>(
            `INSERT IGNORE INTO webhook_replay (replay_key_hash, expira_em)
             VALUES (?, ?)`,
            [replayKeyHash.trim(), expiraEm]
        );

        await this.pool.execute(
            `DELETE FROM webhook_replay
             WHERE expira_em < NOW()`
        );

        return result.affectedRows > 0;
    }

    async getLoginLockRemainingMs(attemptKey: string): Promise<number> {
        if (!attemptKey?.trim()) {
            return 0;
        }

        const [rows] = await this.pool.execute<LoginLockoutDB[]>(
            `SELECT attempt_key, fail_count, lock_until
             FROM login_lockouts
             WHERE attempt_key = ?
             LIMIT 1`,
            [attemptKey.trim()]
        );

        const registro = rows[0];

        if (!registro?.lock_until) {
            return 0;
        }

        const restanteMs = new Date(registro.lock_until).getTime() - Date.now();

        if (restanteMs <= 0) {
            await this.pool.execute(
                `DELETE FROM login_lockouts
                 WHERE attempt_key = ?`,
                [attemptKey.trim()]
            );
            return 0;
        }

        return restanteMs;
    }

    async registrarFalhaLogin(
        attemptKey: string,
        lockBaseMs: number,
        lockMaxMs: number
    ): Promise<void> {
        if (!attemptKey?.trim()) {
            throw new Error("Chave de tentativa inválida.");
        }

        const [rows] = await this.pool.execute<LoginLockoutDB[]>(
            `SELECT attempt_key, fail_count, lock_until
             FROM login_lockouts
             WHERE attempt_key = ?
             LIMIT 1`,
            [attemptKey.trim()]
        );

        const atual = rows[0];
        const failCount = (atual?.fail_count ?? 0) + 1;
        const lockMs = Math.min(lockBaseMs * 2 ** (failCount - 1), lockMaxMs);
        const lockUntil = new Date(Date.now() + lockMs);

        await this.pool.execute(
            `INSERT INTO login_lockouts (attempt_key, fail_count, lock_until)
             VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE
                fail_count = VALUES(fail_count),
                lock_until = VALUES(lock_until)`,
            [attemptKey.trim(), failCount, lockUntil]
        );
    }

    async resetarFalhasLogin(attemptKey: string): Promise<void> {
        if (!attemptKey?.trim()) {
            return;
        }

        await this.pool.execute(
            `DELETE FROM login_lockouts
             WHERE attempt_key = ?`,
            [attemptKey.trim()]
        );
    }

    private hashRefreshToken(token: string): string {
        return createHash("sha256").update(token).digest("hex");
    }

    async criarRefreshToken(
        token: string,
        userId: number,
        familyId: string,
        expUnix: number
    ): Promise<void> {
        if (!token?.trim()) {
            throw new Error("Refresh token inválido.");
        }
        if (!Number.isInteger(userId) || userId <= 0) {
            throw new Error("User ID inválido para refresh token.");
        }
        if (!familyId?.trim()) {
            throw new Error("Family ID inválido.");
        }
        if (!Number.isFinite(expUnix) || expUnix <= 0) {
            throw new Error("Expiração de refresh token inválida.");
        }

        const tokenHash = this.hashRefreshToken(token);
        const expiraEm = new Date(expUnix * 1000);

        await this.pool.execute(
            `INSERT INTO refresh_tokens (token_hash, user_id, family_id, expira_em)
             VALUES (?, ?, ?, ?)`,
            [tokenHash, userId, familyId.trim(), expiraEm]
        );
    }

    async buscarRefreshToken(token: string): Promise<RefreshTokenDB | null> {
        if (!token?.trim()) {
            return null;
        }

        const tokenHash = this.hashRefreshToken(token);

        const [rows] = await this.pool.execute<RefreshTokenDB[]>(
            `SELECT id, token_hash, user_id, family_id, expira_em, revogado_em, substituido_por_hash
             FROM refresh_tokens
             WHERE token_hash = ?
             LIMIT 1`,
            [tokenHash]
        );

        return rows[0] ?? null;
    }

    async rotacionarRefreshToken(
        oldToken: string,
        newToken: string,
        expUnix: number
    ): Promise<boolean> {
        const old = await this.buscarRefreshToken(oldToken);

        if (!old) {
            return false;
        }

        if (old.revogado_em || new Date(old.expira_em).getTime() < Date.now()) {
            return false;
        }

        const newHash = this.hashRefreshToken(newToken);
        const oldHash = this.hashRefreshToken(oldToken);
        const expiraEm = new Date(expUnix * 1000);

        await this.pool.execute(
            `UPDATE refresh_tokens
             SET revogado_em = NOW(), substituido_por_hash = ?
             WHERE token_hash = ?
               AND revogado_em IS NULL`,
            [newHash, oldHash]
        );

        await this.pool.execute(
            `INSERT INTO refresh_tokens (token_hash, user_id, family_id, expira_em)
             VALUES (?, ?, ?, ?)`,
            [newHash, old.user_id, old.family_id, expiraEm]
        );

        return true;
    }

    async revogarRefreshToken(token: string): Promise<void> {
        if (!token?.trim()) {
            return;
        }

        const tokenHash = this.hashRefreshToken(token);
        await this.pool.execute(
            `UPDATE refresh_tokens
             SET revogado_em = COALESCE(revogado_em, NOW())
             WHERE token_hash = ?`,
            [tokenHash]
        );
    }

    async revogarFamiliaRefreshToken(familyId: string): Promise<void> {
        if (!familyId?.trim()) {
            return;
        }

        await this.pool.execute(
            `UPDATE refresh_tokens
             SET revogado_em = COALESCE(revogado_em, NOW())
             WHERE family_id = ?`,
            [familyId.trim()]
        );
    }

    mapearEtapa(statusId: number): string {
        const etapas: Record<number, string> = {
            100504439: "Tenho que descobrir",
            100233527: "Qualificado - Em conversa",
            84315468: "Alinhamento Regulaziração / L. de Pendências",
            81175456: "Gerar Forms",
            73520776: "Movido para Cadência",
            72912304: "Lead novo",
            72897132: "Fazer Ligação",
            72762308: "Funil Nutrição a Longo Prazo",
            72670564: "Fechamento",
            72656692: "Proposta",
            72649772: "Reunião",
            68647324: "Perdido",
            68432532: "Negociação",
            68325220: "Fechamento",
            68325216: "Envio de Proposta",
            66780248: "Conversa",
            66773868: "Venda",
            143: "Perdido",
            142: "Ganho",
        };

        return etapas[statusId] ?? "Desconhecido";
    }

    classificarStatus(statusId: number | null): "ganho" | "perdido" | "andamento" {
        if (statusId === 142) return "ganho";
        if (statusId === 143) return "perdido";
        return "andamento";
    }

    private mapearConsultorNome(consultorId: number | null): string | null {
        const consultores: Record<number, string> = {
            9400123: "Mateus",
            11016288: "Ana",
            1120681: "Ana",
            13637692: "Rafael",
            13661460: "Gabriel | B.O.S Hoss",
            11016300: "Gestor Comercial",
            15050505: "Luís/Testes",
        };

        if (!consultorId) {
            return null;
        }

        return consultores[consultorId] ?? null;
    }

    private normalizarNomeCampo(valor: string): string {
        return valor
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .trim()
            .toLowerCase();
    }

    private extrairValorCampo(campo: any): string | null {
        if (!Array.isArray(campo?.values) || campo.values.length === 0) {
            return null;
        }

        const primeiro = campo.values[0];
        const valorBruto =
            typeof primeiro === "string"
                ? primeiro
                : typeof primeiro === "object" && primeiro !== null
                  ? (primeiro as { value?: unknown }).value
                  : null;

        if (valorBruto === null || valorBruto === undefined) {
            return null;
        }

        const texto = typeof valorBruto === "string" ? valorBruto : String(valorBruto);
        return texto.trim() || null;
    }

    private extrairCampoCustomizado(lead: any, nomeCampo: string): string | null {
        if (!Array.isArray(lead?.custom_fields)) {
            return null;
        }

        const alvo = this.normalizarNomeCampo(nomeCampo);
        const campo = lead.custom_fields.find(
            (field: any) =>
                typeof field?.name === "string" &&
                this.normalizarNomeCampo(field.name) === alvo
        );

        return this.extrairValorCampo(campo);
    }

    private extrairCampoCustomizadoPorNomes(lead: any, nomesCampo: string[]): string | null {
        for (const nome of nomesCampo) {
            const valor = this.extrairCampoCustomizado(lead, nome);
            if (valor) {
                return valor;
            }
        }

        return null;
    }

    async processarLead(lead: any): Promise<void> {
        try {
            const leadId = Number(lead?.id);

            if (!Number.isInteger(leadId) || leadId <= 0) {
                throw new Error("lead.id inválido");
            }

            const nomeRaw =
                typeof lead?.name === "string" && lead.name.trim()
                    ? lead.name.trim()
                    : "Sem nome";

            const leadNome = nomeRaw.substring(0, MAX_LEAD_NOME);

            const consultorId = lead?.responsible_user_id
                ? Number(lead.responsible_user_id)
                : null;

            const consultorNome = this.mapearConsultorNome(consultorId);

            const pipelineId = lead?.pipeline_id ? Number(lead.pipeline_id) : null;
            const statusIdRaw = Number(lead?.status_id);

            if (!Number.isInteger(statusIdRaw)) {
                this.logInfo("Lead ignorado por status inválido.", {
                    leadId,
                    statusId: lead?.status_id ?? null,
                    pipelineId,
                    nome: leadNome,
                });
                return;
            }

            const statusId: number = statusIdRaw;

            if (!STATUS_VALIDOS.has(statusId)) {
                this.logInfo("Lead ignorado por status fora da regra.", {
                    leadId,
                    statusId,
                    pipelineId,
                    nome: leadNome,
                });
                return;
            }

            const etapa = this.mapearEtapa(statusId);

            const valor = Number(lead?.price ?? 0);

            if (!Number.isFinite(valor)) {
                throw new Error("lead.price inválido");
            }

            const criadoTs = Number(lead?.created_at);
            const criado =
                Number.isFinite(criadoTs) && criadoTs > 0
                    ? new Date(criadoTs * 1000)
                    : null;

            const atualizadoTs = Number(lead?.updated_at);
            const atualizado =
                Number.isFinite(atualizadoTs) && atualizadoTs > 0
                    ? new Date(atualizadoTs * 1000)
                    : null;
            const oldStatusId = Number(lead?.old_status_id);
            const mudouParaGanho =
                statusId === 142 &&
                Number.isInteger(oldStatusId) &&
                oldStatusId > 0 &&
                oldStatusId !== 142;
            const dataVenda =
                statusId === 142
                    ? mudouParaGanho
                        ? atualizado ?? criado ?? null
                        : criado ?? atualizado ?? null
                    : null;

            const origem =
                this.extrairCampoCustomizadoPorNomes(lead, [
                    "Origem do lead",
                    "ORIGEM DO LEAD",
                    "Origem TXT",
                    "ORIGEM",
                ]) ?? "Não classificado";

            await this.pool.execute(
                `INSERT INTO funil_vendas
                (
                    lead_id,
                    lead_nome,
                    consultor_id,
                    consultor_nome,
                    origem,
                    pipeline_id,
                    status_id,
                    etapa,
                    valor,
                    data_criacao,
                    data_atualizacao,
                    data_venda
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    lead_nome = VALUES(lead_nome),
                    consultor_id = VALUES(consultor_id),
                    consultor_nome = COALESCE(VALUES(consultor_nome), funil_vendas.consultor_nome),
                    origem = COALESCE(VALUES(origem), funil_vendas.origem),
                    pipeline_id = VALUES(pipeline_id),
                    status_id = VALUES(status_id),
                    etapa = VALUES(etapa),
                    valor = VALUES(valor),
                    data_criacao = COALESCE(funil_vendas.data_criacao, VALUES(data_criacao)),
                    data_atualizacao = VALUES(data_atualizacao),
                    data_venda = CASE
                        WHEN VALUES(status_id) = 142 THEN
                            CASE
                                WHEN funil_vendas.status_id = 142 AND funil_vendas.data_venda IS NOT NULL
                                    THEN funil_vendas.data_venda
                                ELSE COALESCE(VALUES(data_venda), VALUES(data_criacao), VALUES(data_atualizacao))
                            END
                        ELSE NULL
                    END`,
                [
                    leadId,
                    leadNome,
                    consultorId,
                    consultorNome,
                    origem,
                    pipelineId,
                    statusId,
                    etapa,
                    valor,
                    criado,
                    atualizado,
                    dataVenda,
                ]
            );

            this.logInfo("Lead salvo/atualizado.", {
                leadId,
                statusId,
                pipelineId,
            });
        } catch (error) {
            this.logError("Erro ao processar lead.", error, {
                leadId: lead?.id ?? null,
            });
            throw error;
        }
    }

    async relatorioLeads(): Promise<any[]> {
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT
                lead_id,
                lead_nome,
                consultor_id,
                consultor_nome,
                origem,
                pipeline_id,
                status_id,
                etapa,
                valor,
                data_criacao,
                data_atualizacao,
                data_venda
             FROM funil_vendas
             ORDER BY
                CASE
                   WHEN status_id = 142 THEN COALESCE(data_venda, data_criacao, data_atualizacao)
                    ELSE data_criacao
                END DESC`
        );

        return rows.map((item: any) => ({
            ...item,
            categoria: this.classificarStatus(Number(item.status_id)),
        }));
    }

    async relatorioLeadsGanhos(): Promise<any> {
        const [rows] = await this.pool.query(
            `SELECT lead_id, lead_nome, consultor_id, consultor_nome, origem,
                    pipeline_id, status_id, etapa, valor, data_criacao, data_atualizacao, data_venda
             FROM funil_vendas
             WHERE status_id = 142
             ORDER BY COALESCE(data_venda, data_criacao, data_atualizacao) DESC`
        );

        return rows;
    }

    async buscarLeadsPorPeriodo(dataInicio: string, dataFim: string): Promise<any> {
        const [rows] = await this.pool.query(
            `SELECT lead_id, lead_nome, consultor_id, consultor_nome, origem,
                    pipeline_id, status_id, etapa, valor, data_criacao, data_atualizacao, data_venda
             FROM funil_vendas
             WHERE (
                CASE
                   WHEN status_id = 142 THEN COALESCE(data_venda, data_criacao, data_atualizacao)
                    ELSE data_criacao
                END
             ) BETWEEN ? AND ?
             ORDER BY (
                CASE
                   WHEN status_id = 142 THEN COALESCE(data_venda, data_criacao, data_atualizacao)
                    ELSE data_criacao
                END
             ) DESC`,
            [`${dataInicio} 00:00:00`, `${dataFim} 23:59:59`]
        );

        return rows;
    }

    async totalLeadsGanhos(): Promise<number> {
        const [rows] = await this.pool.query<RowDataPacket[]>(
            `SELECT COALESCE(SUM(valor), 0) AS total
             FROM funil_vendas
             WHERE status_id = 142`
        );

        return Number(rows[0]?.total ?? 0);
    }

    async findByLogin(userLogin: string): Promise<UsuarioDB[]> {
        const [rows] = await this.pool.execute<UsuarioDB[]>(
            `SELECT id, nome, email, acesso, setor, userLogin, senha
             FROM usuarios
             WHERE userLogin = ?`,
            [this.normalizarLogin(userLogin)]
        );

        return rows;
    }

    async atualizarHashSenha(userId: number, senha: string): Promise<void> {
        if (!Number.isInteger(userId) || userId <= 0) {
            throw new Error("ID de usuário inválido.");
        }

        this.validarSenha(senha);

        const senhaHash = await this.gerarHashSenha(senha);

        await this.pool.execute(
            `UPDATE usuarios
             SET senha = ?
             WHERE id = ?`,
            [senhaHash, userId]
        );
    }

    async atualizarNomePerfil(userId: number, nome: string): Promise<void> {
        if (!Number.isInteger(userId) || userId <= 0) {
            throw new Error("ID de usuário inválido.");
        }

        this.validarNome(nome);

        const [result] = await this.pool.execute<ResultSetHeader>(
            `UPDATE usuarios
             SET nome = ?
             WHERE id = ?`,
            [nome.trim(), userId]
        );

        if (result.affectedRows === 0) {
            throw new Error("Usuário não encontrado.");
        }
    }

    async insertUser(usuario: Usuario): Promise<number> {
        this.validarUsuario(usuario, true);

        const emailNormalizado = this.normalizarEmail(usuario.email);
        const loginNormalizado = this.normalizarLogin(usuario.userLogin);
        const senhaHash = await this.gerarHashSenha(usuario.senha as string);

        try {
            const [result] = await this.pool.execute<ResultSetHeader>(
                `INSERT INTO usuarios (nome, email, acesso, setor, userLogin, senha)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    usuario.nome.trim(),
                    emailNormalizado,
                    usuario.acesso,
                    usuario.setor.trim(),
                    loginNormalizado,
                    senhaHash,
                ]
            );

            return result.insertId;
        } catch (error: any) {
            if (error?.code === "ER_DUP_ENTRY") {
                throw new Error("Já existe usuário com esse email ou login.");
            }

            throw error;
        }
    }

    async listUser(): Promise<Usuario[]> {
        const [rows] = await this.pool.query<UsuarioDB[]>(
            `SELECT id, nome, email, acesso, setor, userLogin
             FROM usuarios`
        );

        return rows;
    }

    async findUserByid(id: string): Promise<Usuario | null> {
        const userId = Number(id);

        if (!Number.isInteger(userId) || userId <= 0) {
            throw new Error("ID de usuário inválido.");
        }

        const [rows] = await this.pool.execute<UsuarioDB[]>(
            `SELECT id, nome, email, acesso, setor, userLogin
             FROM usuarios
             WHERE id = ?`,
            [userId]
        );

        return rows[0] ?? null;
    }

    async updateUser(id: string, usuario: Usuario): Promise<void> {
        const userId = Number(id);

        if (!Number.isInteger(userId) || userId <= 0) {
            throw new Error("ID de usuário inválido.");
        }

        this.validarUsuario(usuario, false);

        const emailNormalizado = this.normalizarEmail(usuario.email);
        const loginNormalizado = this.normalizarLogin(usuario.userLogin);
        const atualizarSenha = Boolean(usuario.senha?.trim());

        let sql: string;
        let campos: any[];

        if (atualizarSenha) {
            this.validarSenha(usuario.senha!);

            const senhaHash = await this.gerarHashSenha(usuario.senha!);

            sql = `UPDATE usuarios
                   SET nome=?, email=?, acesso=?, setor=?, userLogin=?, senha=?
                   WHERE id=?`;

            campos = [
                usuario.nome.trim(),
                emailNormalizado,
                usuario.acesso,
                usuario.setor.trim(),
                loginNormalizado,
                senhaHash,
                userId,
            ];
        } else {
            sql = `UPDATE usuarios
                   SET nome=?, email=?, acesso=?, setor=?, userLogin=?
                   WHERE id=?`;

            campos = [
                usuario.nome.trim(),
                emailNormalizado,
                usuario.acesso,
                usuario.setor.trim(),
                loginNormalizado,
                userId,
            ];
        }

        try {
            await this.pool.execute(sql, campos);
        } catch (error: any) {
            if (error?.code === "ER_DUP_ENTRY") {
                throw new Error("Já existe usuário com esse email ou login.");
            }

            throw error;
        }
    }

    async excludeUser(id: string): Promise<void> {
        const userId = Number(id);

        if (!Number.isInteger(userId) || userId <= 0) {
            throw new Error("ID de usuário inválido.");
        }

        await this.pool.execute("DELETE FROM usuarios WHERE id = ?", [userId]);
    }
}

export const banco = new BancoMysql();
export default BancoMysql;
