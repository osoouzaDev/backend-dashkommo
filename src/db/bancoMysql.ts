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

class BancoMysql {
    private pool: Pool;

    constructor() {
        this.pool = mysql.createPool({
            host: process.env.DB_HOST || "localhost",
            user: process.env.DB_USER || "root",
            password: process.env.DB_PASSWORD || "",
            database: process.env.DB_NAME || "dbdefault",
            port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
            waitForConnections: true,
            connectionLimit: 10,
            timezone: "-04:00"
        });
    }

    async salvarWebhook(evento: string, payload: any): Promise<void> {
        const criadoEmLocal = new Date()
            .toLocaleString("sv-SE", { timeZone: "America/Cuiaba" })
            .replace(" ", " ");

        await this.pool.execute(
            "INSERT INTO webhooks (evento, payload, criado_em_local) VALUES (?, ?, ?)",
            [evento, JSON.stringify(payload), criadoEmLocal]
        );
    }

    mapearEtapa(statusId: number): string {
        const etapas: Record<number, string> = {
            100504439: "Tenho que descobrir",
            100233527: "Qualificado - Em conversa",
            84315468: "Alinhamento Regulaziração / L. de Pendências",
            81175456: "Gerar Forms",
            78136192: "IRPF 2025",
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
            142: "Ganho"
        };

        return etapas[statusId] || "Desconhecido";
    }

    private mapearConsultorNome(consultorId: number | null): string | null {
        const consultores: Record<number, string> = {
            9400123: "Mateus",
            11016288: "Ana",
            1120681: "Ana",
            13637692: "Rafael",
            13661460: "Gabriel | B.O.S Hoss",
            11016300: "Anderson Maisse",
        };

        if (!consultorId) {
            return null;
        }

        return consultores[consultorId] || null;
    }

    private extrairCampoCustomizado(lead: any, nomeCampo: string): string | null {
        if (!lead?.custom_fields || !Array.isArray(lead.custom_fields)) {
            return null;
        }

        const campo = lead.custom_fields.find((field: any) => field.name === nomeCampo);
        if (!campo?.values?.length) {
            return null;
        }

        return campo.values[0]?.value ?? null;
    }

    async processarLead(lead: any): Promise<void> {
        try {
            console.log("PROCESSANDO LEAD:", JSON.stringify(lead, null, 2));

            const leadId = Number(lead.id);
            if (!leadId) {
                throw new Error("lead.id inválido");
            }

            const leadNome = lead.name?.trim() || "Sem nome";

            const consultorId = lead.responsible_user_id
                ? Number(lead.responsible_user_id)
                : null;

            const consultorNome = this.mapearConsultorNome(consultorId);

            const pipelineId = lead.pipeline_id ? Number(lead.pipeline_id) : null;
            const statusId = lead.status_id ? Number(lead.status_id) : null;

            const etapa = statusId ? this.mapearEtapa(statusId) : "Desconhecido";

            const valor = Number(lead.price || 0);

            const criado = lead.created_at
                ? new Date(Number(lead.created_at) * 1000)
                : null;

            const atualizado = lead.updated_at
                ? new Date(Number(lead.updated_at) * 1000)
                : null;

            const origem =
                this.extrairCampoCustomizado(lead, "Origem do lead") ||
                "Não qualificado";

            console.log("DADOS EXTRAÍDOS:", {
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
                atualizado
            });

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
                    data_atualizacao
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    data_atualizacao = VALUES(data_atualizacao)`,
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
                    atualizado
                ]
            );

            console.log(`LEAD ${leadId} salvo/atualizado em funil_vendas com sucesso.`);
        } catch (error) {
            console.error("ERRO AO PROCESSAR LEAD:", error);
            throw error;
        }
    }

    async relatorioLeadsGanhos(): Promise<any> {
        const [rows] = await this.pool.query(
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
            data_atualizacao
         FROM funil_vendas
         WHERE status_id
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

        return Number(rows[0].total || 0);
    }

    async findByLogin(userLogin: string): Promise<UsuarioDB[]> {
        const [rows] = await this.pool.execute<UsuarioDB[]>(
            "SELECT * FROM usuarios WHERE userLogin = ?",
            [userLogin]
        );
        return rows;
    }

    async insertUser(usuario: Usuario): Promise<number> {
        if (!usuario.senha) {
            throw new Error("Senha obrigatória");
        }

        const loginExistente = await this.findByLogin(usuario.userLogin);
        if (loginExistente.length > 0) {
            throw new Error("Já existe um usuário com esse login");
        }

        const [emailRows] = await this.pool.execute<RowDataPacket[]>(
            "SELECT id FROM usuarios WHERE email = ?",
            [usuario.email]
        );
        if (emailRows.length > 0) {
            throw new Error("Já existe um usuário com esse email");
        }

        const senhaHash = await bcrypt.hash(usuario.senha, 10);

        const [result] = await this.pool.execute<ResultSetHeader>(
            `INSERT INTO usuarios
            (nome, email, acesso, setor, userLogin, senha)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [
                usuario.nome,
                usuario.email,
                usuario.acesso,
                usuario.setor,
                usuario.userLogin,
                senhaHash
            ]
        );

        return result.insertId;
    }

    async listUser(): Promise<Usuario[]> {
        const [rows] = await this.pool.query<UsuarioDB[]>(
            `SELECT
                id,
                nome,
                email,
                acesso,
                setor,
                userLogin
             FROM usuarios`
        );

        return rows;
    }

    async findUserByid(id: string): Promise<Usuario | null> {
        const [rows] = await this.pool.execute<UsuarioDB[]>(
            `SELECT
                id,
                nome,
                email,
                acesso,
                setor,
                userLogin
             FROM usuarios
             WHERE id = ?`,
            [id]
        );

        if (rows.length === 0) return null;
        return rows[0];
    }

    async updateUser(id: string, usuario: Usuario): Promise<void> {
        if (usuario.senha && usuario.senha !== "") {
            const senhaHash = await bcrypt.hash(usuario.senha, 10);

            await this.pool.execute(
                `UPDATE usuarios
                 SET nome=?, email=?, acesso=?, setor=?, userLogin=?, senha=?
                 WHERE id=?`,
                [
                    usuario.nome,
                    usuario.email,
                    usuario.acesso,
                    usuario.setor,
                    usuario.userLogin,
                    senhaHash,
                    id
                ]
            );
        } else {
            await this.pool.execute(
                `UPDATE usuarios
                 SET nome=?, email=?, acesso=?, setor=?, userLogin=?
                 WHERE id=?`,
                [
                    usuario.nome,
                    usuario.email,
                    usuario.acesso,
                    usuario.setor,
                    usuario.userLogin,
                    id
                ]
            );
        }
    }

    async excludeUser(id: string): Promise<void> {
        await this.pool.execute(
            "DELETE FROM usuarios WHERE id = ?",
            [id]
        );
    }
}

export const banco = new BancoMysql();
export default BancoMysql;