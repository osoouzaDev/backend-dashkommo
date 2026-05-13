import { banco } from "../db/bancoMysql";

export async function registrarAuditoriaSeguro(
    evento: string,
    resultado: "sucesso" | "falha" | "negado",
    metadados: Record<string, unknown>
): Promise<void> {
    try {
        await banco.registrarAuditoria(evento, resultado, metadados);
    } catch (error) {
        console.error("Falha ao registrar auditoria.", error);
    }
}
