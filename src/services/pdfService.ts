import { jsPDF } from "jspdf";
import "jspdf-autotable";

export interface LeadRelatorio {
    lead_id: number;
    lead_nome: string;
    consultor_nome: string | null;
    origem: string;
    valor: number;
    etapa: string;
    data_criacao: string | Date;
}

export class PdfService {
    static async gerarRelatorioLeads(leads: LeadRelatorio[], dataInicio: string, dataFim: string): Promise<Buffer> {
        const doc = new jsPDF();
        
        // Título
        doc.setFontSize(18);
        doc.text("DashKommo - Resumo de Leads", 14, 22);
        
        // Período
        doc.setFontSize(11);
        doc.text(`Período: ${dataInicio} a ${dataFim}`, 14, 30);
        
        // Tabela
        const head = [["ID", "Nome", "Consultor", "Valor", "Etapa", "Origem"]];
        const body = leads.map(lead => [
            lead.lead_id,
            lead.lead_nome,
            lead.consultor_nome || "N/A",
            new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(lead.valor),
            lead.etapa,
            lead.origem
        ]);

        (doc as any).autoTable({
            head: head,
            body: body,
            startY: 35,
            theme: 'grid',
            headStyles: { fillColor: [41, 128, 185], textColor: 255 },
            styles: { fontSize: 8 },
        });

        const arrayBuffer = doc.output("arraybuffer");
        return Buffer.from(arrayBuffer);
    }
}
