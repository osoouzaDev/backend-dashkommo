# Guia Rapido de Deploy

Documento curto para operacao do backend em ambiente de producao.

## 1. Antes do deploy

- Confirmar que o banco MySQL esta acessivel.
- Confirmar que o webhook externo ja esta configurado para HMAC.
- Garantir que segredos novos foram gerados.

## 2. Variaveis obrigatorias

Preencher no ambiente:

- `PORT`
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `DB_SSL=true`
- `DB_SSL_REJECT_UNAUTHORIZED=true`
- `DB_SSL_CA_PEM` (recomendado no Render)
- `JWT_SECRET` (forte)
- `JWT_ISSUER`
- `JWT_AUDIENCE`
- `PASSWORD_PEPPER` (forte)
- `WEBHOOK_SECRET` (forte)
- `WEBHOOK_SIGNATURE_TOLERANCE_SEC=300`
- `WEBHOOK_ALLOW_LEGACY_SECRET=false`
- `REFRESH_TOKEN_TTL_DAYS=30`

Se banco usar CA customizado:

- Preferir `DB_SSL_CA_PEM` com o conteudo PEM completo.
- Alternativa: `DB_SSL_CA_PATH` + arquivo no container.

## 3. Segredos (regra)

- Nunca commitar `.env`.
- Nunca compartilhar segredos em chat ou print.
- Rotacionar periodicamente:
  - `JWT_SECRET`
  - `WEBHOOK_SECRET`
  - `PASSWORD_PEPPER`
  - `DB_PASSWORD`

## 4. Deploy

```bash
npm ci
npm run build
npm start
```

## 5. Checklist pos-deploy

- `GET /` responde `200`.
- `POST /login` responde `200` com `token` e `refreshToken`.
- `POST /auth/refresh` responde `200`.
- `POST /logout` responde `200`.
- `POST /webhook` sem assinatura responde `401`.
- `POST /webhook` com HMAC valido responde `200`.

## 6. Sinais de problema

- `EADDRINUSE`: porta ocupada.
- `self-signed certificate in certificate chain`: CA/TLS mal configurado.
- `401` em login com senha correta: verificar `PASSWORD_PEPPER`.

## 7. Plano de rollback rapido

- Voltar para ultima versao estavel do backend.
- Restaurar variaveis da versao anterior.
- Verificar conectividade de banco e webhook.
- Reexecutar checklist pos-deploy.
