import mysql, { Pool, RowDataPacket, ResultSetHeader } from "mysql2/promise";
import bcrypt from "bcryptjs";

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

// Cuiabá (MT) não observa horário de verão — UTC-4 é fixo o ano todo.
const TIMEZONE = "-04:00";

const MAX_LEAD_NOME = 255;

class BancoMysql {
    private pool: Pool;
    private static readonly BCRYPT_ROUNDS = 12;
    private static readonly MAX_WEBHOOK_PAYLOAD_BYTES = 200_000;

    constructor() {
        const host     = this.getRequiredEnv("DB_HOST");
        const user     = this.getRequiredEnv("DB_USER");
        const password = this.getRequiredEnv("DB_PASSWORD");
        const database = this.getRequiredEnv("DB_NAME");
        const port     = process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306;
        const useSSL   = process.env.DB_SSL === "true";

        if (!Number.isInteger(port) || port <= 0) {
            throw new Error("DB_PORT inválida.");
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
            ssl: useSSL ? {} : undefined,
        });
    }

    // ─── Env ─────────────────────────────────────────────────────────────────

    private getRequiredEnv(name: string): string {
        const value = process.env[name]?.trim();
        if (!value) throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
        return value;
    }

    // ─── Log ─────────────────────────────────────────────────────────────────

    private logInfo(message: string, meta?: Record<string, unknown>): void {
        console.log(message, meta ?? "");
    }

    private logError(message: string, error: unknown, meta?: Record<string, unknown>): void {
        console.error(message, meta ?? "", error);
    }

    // ─── Normalização ─────────────────────────────────────────────────────────

    private normalizarEmail(email: string): string {
        return email.trim().toLowerCase();
    }

    private normalizarLogin(login: string): string {
        return login.trim();
    }

    // ─── Validação ────────────────────────────────────────────────────────────

    private validarEmail(email: string): void {
        const v = this.normalizarEmail(email);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) throw new Error("Email inválido.");
        if (v.length > 100) throw new Error("Email muito longo.");
    }

    private validarLogin(login: string): void {
        const v = this.normalizarLogin(login);
        if (!v) throw new Error("Login obrigatório.");
        if (v.length < 3 || v.length > 50) throw new Error("Login deve ter entre 3 e 50 caracteres.");
    }

    private validarNome(nome: string): void {
        const v = nome.trim();
        if (!v) throw new Error("Nome obrigatório.");
        if (v.length > 50) throw new Error("Nome muito longo.");
    }

    private validarSetor(setor: string): void {
        const v = setor.trim();
        if (!v) throw new Error("Setor obrigatório.");
        if (v.length > 50) throw new Error("Setor muito longo.");
    }

    private validarAcesso(acesso: string): asserts acesso is "administrador" | "usuario" {
        if (acesso !== "administrador" && acesso !== "usuario") {
            throw new Error("Nível de acesso inválido.");
        }
    }

    private validarSenha(senha: string): void {
        if (!senha?.trim()) throw new Error("Senha obrigatória.");
        if (senha.length < 8)  throw new Error("A senha deve ter no mínimo 8 caracteres.");
        if (senha.length > 72) throw new Error("A senha não pode ter mais de 72 caracteres.");
    }

    private validarUsuario(usuario: Usuario, exigirSenha: boolean): void {
        this.validarNome(usuario.nome);
        this.validarEmail(usuario.email);
        this.validarAcesso(usuario.acesso);
        this.validarSetor(usuario.setor);
        this.validarLogin(usuario.userLogin);
        if (exigirSenha) this.validarSenha(usuario.senha ?? "");
    }

    private validarPayloadWebhook(payload: unknown): void {
        if (payload === null || payload === undefined) {
            throw new Error("Payload do webhook ausente.");
        }
        let str: string;
        try {
            str = JSON.stringify(payload);
        } catch {
            throw new Error("Payload do webhook inválido.");
        }
        if (Buffer.byteLength(str, "utf-8") > BancoMysql.MAX_WEBHOOK_PAYLOAD_BYTES) {
            throw new Error("Payload do webhook excede o tamanho permitido.");
        }
    }

    // ─── Webhook ──────────────────────────────────────────────────────────────

    async salvarWebhook(evento: string, payload: unknown): Promise<void> {
        if (!evento?.trim()) throw new Error("Evento do webhook é obrigatório.");

        this.validarPayloadWebhook(payload);

        const criadoEmLocal = new Date()
            .toLocaleString("sv-SE", { timeZone: "America/Cuiaba" });

        await this.pool.execute(
            "INSERT INTO webhooks (evento, payload, criado_em_local) VALUES (?, ?, ?)",
            [evento.trim(), JSON.stringify(payload), criadoEmLocal]
        );

        this.logInfo("Webhook salvo.", { evento: evento.trim() });
    }

    // ─── Mapeamentos ──────────────────────────────────────────────────────────

    mapearEtapa(statusId: number): string {
        const etapas: Record<number, string> = {
            100504439: "Tenho que descobrir",
            100233527: "Qualificado - Em conversa",
            84315468:  "Alinhamento Regulaziração / L. de Pendências",
            83852672:  "Vaga de Emprego",
            81175456:  "Gerar Forms",
            78136192:  "IRPF 2025",
            73520776:  "Movido para Cadência",
            72912304:  "Lead novo",
            72897132:  "Fazer Ligação",
            72762308:  "Funil Nutrição a Longo Prazo",
            72670564:  "Fechamento",
            72656692:  "Proposta",
            72649772:  "Reunião",
            68647324:  "Perdido",
            68432532:  "Negociação",
            68325220:  "Fechamento",
            68325216:  "Envio de Proposta",
            66780248:  "Conversa",
            66773868:  "Venda",
            143: "Perdido",
            142: "Ganho",
        };
        return etapas[statusId] ?? "Desconhecido";
    }

    private mapearConsultorNome(consultorId: number | null): string | null {
        const consultores: Record<number, string> = {
            9400123:  "Mateus",
            11016288: "Ana",
            1120681:  "Ana",
            13637692: "Rafael",
            13661460: "Gabriel | B.O.S Hoss",
            11016300: "Anderson Maisse",
        };
        if (!consultorId) return null;
        return consultores[consultorId] ?? null;
    }

    // ─── Lead ─────────────────────────────────────────────────────────────────

    private extrairCampoCustomizado(lead: any, nomeCampo: string): string | null {
        if (!Array.isArray(lead?.custom_fields)) return null;

        const campo = lead.custom_fields.find((f: any) => f.name === nomeCampo);
        if (!campo?.values?.length) return null;

        const valor = campo.values[0]?.value;
        if (valor === null || valor === undefined) return null;

        const str = typeof valor === "string" ? valor : String(valor);
        return str.trim() || null;
    }

    async processarLead(lead: any): Promise<void> {
        try {
            const leadId = Number(lead?.id);
            if (!Number.isInteger(leadId) || leadId <= 0) {
                throw new Error("lead.id inválido");
            }

            // Comprimento limitado a MAX_LEAD_NOME para não estourar a coluna
            const nomeRaw = typeof lead?.name === "string" && lead.name.trim()
                ? lead.name.trim()
                : "Sem nome";
            const leadNome = nomeRaw.substring(0, MAX_LEAD_NOME);

            const consultorId   = lead?.responsible_user_id ? Number(lead.responsible_user_id) : null;
            const consultorNome = this.mapearConsultorNome(consultorId);

            const pipelineId = lead?.pipeline_id ? Number(lead.pipeline_id) : null;
            const statusId   = lead?.status_id   ? Number(lead.status_id)   : null;
            const etapa      = statusId ? this.mapearEtapa(statusId) : "Desconhecido";

            const valor = Number(lead?.price ?? 0);
            if (!Number.isFinite(valor)) throw new Error("lead.price inválido");

            // Datas validadas com isFinite para evitar new Date(NaN)
            const criadoTs  = Number(lead?.created_at);
            const criado    = Number.isFinite(criadoTs)  && criadoTs  > 0 ? new Date(criadoTs  * 1000) : null;

            const atualizadoTs = Number(lead?.updated_at);
            const atualizado   = Number.isFinite(atualizadoTs) && atualizadoTs > 0 ? new Date(atualizadoTs * 1000) : null;

            const origem = this.extrairCampoCustomizado(lead, "Origem do lead") ?? "Não qualificado";

            await this.pool.execute(
                `INSERT INTO funil_vendas
                (lead_id, lead_nome, consultor_id, consultor_nome, origem,
                 pipeline_id, status_id, etapa, valor, data_criacao, data_atualizacao)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    lead_nome        = VALUES(lead_nome),
                    consultor_id     = VALUES(consultor_id),
                    consultor_nome   = COALESCE(VALUES(consultor_nome), funil_vendas.consultor_nome),
                    origem           = COALESCE(VALUES(origem), funil_vendas.origem),
                    pipeline_id      = VALUES(pipeline_id),
                    status_id        = VALUES(status_id),
                    etapa            = VALUES(etapa),
                    valor            = VALUES(valor),
                    data_criacao     = COALESCE(funil_vendas.data_criacao, VALUES(data_criacao)),
                    data_atualizacao = VALUES(data_atualizacao)`,
                [leadId, leadNome, consultorId, consultorNome, origem,
                 pipelineId, statusId, etapa, valor, criado, atualizado]
            );

            this.logInfo("Lead salvo/atualizado.", { leadId, statusId, pipelineId });
        } catch (error) {
            this.logError("Erro ao processar lead.", error, { leadId: lead?.id ?? null });
            throw error;
        }
    }

    // ─── Relatórios ───────────────────────────────────────────────────────────

    async relatorioLeadsGanhos(): Promise<any> {
        const [rows] = await this.pool.query(
            `SELECT lead_id, lead_nome, consultor_id, consultor_nome, origem,
                    pipeline_id, status_id, etapa, valor, data_criacao, data_atualizacao
             FROM funil_vendas
             WHERE status_id = 142
             ORDER BY data_criacao DESC`
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

    // ─── Usuários ─────────────────────────────────────────────────────────────

    // Retorna colunas explícitas incluindo senha (necessária apenas para autenticação)
    async findByLogin(userLogin: string): Promise<UsuarioDB[]> {
        const [rows] = await this.pool.execute<UsuarioDB[]>(
            `SELECT id, nome, email, acesso, setor, userLogin, senha
             FROM usuarios
             WHERE userLogin = ?`,
            [this.normalizarLogin(userLogin)]
        );
        return rows;
    }

    async insertUser(usuario: Usuario): Promise<number> {
        this.validarUsuario(usuario, true);

        const emailNorm = this.normalizarEmail(usuario.email);
        const loginNorm = this.normalizarLogin(usuario.userLogin);
        const senhaHash = await bcrypt.hash(usuario.senha as string, BancoMysql.BCRYPT_ROUNDS);

        try {
            const [result] = await this.pool.execute<ResultSetHeader>(
                `INSERT INTO usuarios (nome, email, acesso, setor, userLogin, senha)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [usuario.nome.trim(), emailNorm, usuario.acesso, usuario.setor.trim(), loginNorm, senhaHash]
            );
            return result.insertId;
        } catch (error: any) {
            if (error?.code === "ER_DUP_ENTRY") throw new Error("Já existe usuário com esse email ou login.");
            throw error;
        }
    }

    async listUser(): Promise<Usuario[]> {
        const [rows] = await this.pool.query<UsuarioDB[]>(
            `SELECT id, nome, email, acesso, setor, userLogin FROM usuarios`
        );
        return rows;
    }

    async findUserByid(id: string): Promise<Usuario | null> {
        const userId = Number(id);
        if (!Number.isInteger(userId) || userId <= 0) throw new Error("ID de usuário inválido.");

        const [rows] = await this.pool.execute<UsuarioDB[]>(
            `SELECT id, nome, email, acesso, setor, userLogin
             FROM usuarios WHERE id = ?`,
            [userId]
        );
        return rows[0] ?? null;
    }

    async updateUser(id: string, usuario: Usuario): Promise<void> {
        const userId = Number(id);
        if (!Number.isInteger(userId) || userId <= 0) throw new Error("ID de usuário inválido.");

        this.validarUsuario(usuario, false);

        const emailNorm = this.normalizarEmail(usuario.email);
        const loginNorm = this.normalizarLogin(usuario.userLogin);
        const atualizarSenha = Boolean(usuario.senha?.trim());

        let sql: string;
        let campos: any[];

        if (atualizarSenha) {
            this.validarSenha(usuario.senha!);
            const senhaHash = await bcrypt.hash(usuario.senha!, BancoMysql.BCRYPT_ROUNDS);
            sql = `UPDATE usuarios
                   SET nome=?, email=?, acesso=?, setor=?, userLogin=?, senha=?
                   WHERE id=?`;
            campos = [usuario.nome.trim(), emailNorm, usuario.acesso, usuario.setor.trim(), loginNorm, senhaHash, userId];
        } else {
            sql = `UPDATE usuarios
                   SET nome=?, email=?, acesso=?, setor=?, userLogin=?
                   WHERE id=?`;
            campos = [usuario.nome.trim(), emailNorm, usuario.acesso, usuario.setor.trim(), loginNorm, userId];
        }

        try {
            await this.pool.execute(sql, campos);
        } catch (error: any) {
            if (error?.code === "ER_DUP_ENTRY") throw new Error("Já existe usuário com esse email ou login.");
            throw error;
        }
    }

    async excludeUser(id: string): Promise<void> {
        const userId = Number(id);
        if (!Number.isInteger(userId) || userId <= 0) throw new Error("ID de usuário inválido.");

        await this.pool.execute("DELETE FROM usuarios WHERE id = ?", [userId]);
    }
}

export const banco = new BancoMysql();
export default BancoMysql;