import nodemailer from "nodemailer";

export class EmailService {
    private static transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === "true",
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });

    static async enviarRelatorioComAnexo(
        emailDestino: string,
        assunto: string,
        corpo: string,
        nomeArquivo: string,
        conteudoArquivo: Buffer
    ): Promise<void> {
        if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
            throw new Error("Configurações de SMTP não encontradas nas variáveis de ambiente.");
        }

        await this.transporter.sendMail({
            from: `"DashKommo" <${process.env.SMTP_USER}>`,
            to: emailDestino,
            subject: assunto,
            text: corpo,
            attachments: [
                {
                    filename: nomeArquivo,
                    content: conteudoArquivo,
                    contentType: "application/pdf",
                },
            ],
        });
    }
}
