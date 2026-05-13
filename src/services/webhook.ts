import { createHash, createHmac, timingSafeEqual } from "crypto";
import { banco } from "../db/bancoMysql";
import { env } from "../config/env";

function normalizeWebhookSignature(signature: string): string {
    return signature.startsWith("sha256=") ? signature.slice(7) : signature;
}

function isTimestampWithinTolerance(timestampSeconds: number): boolean {
    const nowSeconds = Math.floor(Date.now() / 1000);
    return Math.abs(nowSeconds - timestampSeconds) <= env.webhookToleranceSeconds;
}

export function isWebhookLegacySecretValid(receivedSecret: string | undefined): boolean {
    if (!receivedSecret) {
        return false;
    }

    const receivedBuffer = Buffer.from(receivedSecret, "utf-8");
    const expectedBuffer = Buffer.from(env.webhookSecret, "utf-8");

    if (receivedBuffer.length !== expectedBuffer.length) {
        return false;
    }

    return timingSafeEqual(receivedBuffer, expectedBuffer);
}

export async function isWebhookSignatureValid(
    signatureHeader: string | undefined,
    timestampHeader: string | undefined,
    rawBody: string
): Promise<boolean> {
    if (!signatureHeader || !timestampHeader || !rawBody) {
        return false;
    }

    const timestampSeconds = Number(timestampHeader);

    if (!Number.isFinite(timestampSeconds) || !isTimestampWithinTolerance(timestampSeconds)) {
        return false;
    }

    const payloadToSign = `${timestampHeader}.${rawBody}`;
    const expectedSignature = createHmac("sha256", env.webhookSecret)
        .update(payloadToSign)
        .digest("hex");

    const normalizedSignature = normalizeWebhookSignature(signatureHeader.trim());
    const receivedBuffer = Buffer.from(normalizedSignature, "utf-8");
    const expectedBuffer = Buffer.from(expectedSignature, "utf-8");

    if (receivedBuffer.length !== expectedBuffer.length) {
        return false;
    }

    const isValid = timingSafeEqual(receivedBuffer, expectedBuffer);

    if (!isValid) {
        return false;
    }

    const replayKeyHash = createHash("sha256")
        .update(`${timestampHeader}:${normalizedSignature}`)
        .digest("hex");
    const expUnix = Math.floor(Date.now() / 1000) + env.webhookToleranceSeconds;

    return banco.registrarWebhookReplay(replayKeyHash, expUnix);
}

export function resumirPayloadWebhook(payload: unknown): Record<string, unknown> {
    const maybePayload = payload as {
        leads?: { add?: unknown[]; update?: unknown[] };
        id?: unknown;
        pipeline_id?: unknown;
        status_id?: unknown;
        responsible_user_id?: unknown;
    };

    const leadsAdd = Array.isArray(maybePayload?.leads?.add) ? maybePayload.leads.add.length : 0;
    const leadsUpdate = Array.isArray(maybePayload?.leads?.update)
        ? maybePayload.leads.update.length
        : 0;

    return {
        leadsAdd,
        leadsUpdate,
        possuiLeadDireto: Boolean(
            maybePayload?.id &&
                maybePayload?.pipeline_id &&
                maybePayload?.status_id &&
                maybePayload?.responsible_user_id
        ),
    };
}
