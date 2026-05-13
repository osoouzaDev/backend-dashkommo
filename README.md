# Backend DashKommo

API backend principal do projeto em `Node.js + TypeScript + Express`, responsável por autenticação, usuários, ingestão de webhook da Kommo e relatórios.

## Arquitetura Atual

Este repositório tem dois backends:

- `src/`: backend principal em `Express`, usado pelo sistema atual.
- `nest-backend/`: backend separado em `NestJS`, criado sem remover nada do projeto original.

O banco real do projeto é `MySQL` hospedado no `Aiven`, com conexão via `mysql2/promise`.

## Stack

- Node.js
- TypeScript
- Express
- MySQL (`mysql2/promise`)
- JWT (`jsonwebtoken`)
- `argon2` com suporte a hashes legados em `bcrypt`
- `zod`
- `helmet`
- `express-rate-limit`

## Funcionalidades

- Login com `access token` e `refresh token` rotativo
- Logout com revogação persistente de `jti`
- CRUD de usuários com controle de acesso por perfil
- Recebimento e processamento de webhook da Kommo
- Anti-replay para webhook
- Relatórios sobre o `funil_vendas`
- Auditoria de eventos de segurança

## Estrutura de Pastas

```txt
src/
  config/
    cors.ts
    env.ts
    rateLimit.ts
  db/
    bancoMysql.ts
  middlewares/
    auth.ts
    autorizarAdmin.ts
    errorHandler.ts
  routes/
    auth.ts
    health.ts
    reports.ts
    users.ts
    webhook.ts
  schemas/
    index.ts
  services/
    auditoria.ts
    auth.ts
    webhook.ts
  types/
    express.d.ts
  utils/
    cookies.ts
    request.ts
    validation.ts
  app.ts
  main.ts
```

## Responsabilidades dos Arquivos Principais

- `src/main.ts`: bootstrap do servidor.
- `src/app.ts`: cria e configura a aplicação Express.
- `src/db/bancoMysql.ts`: conexão com MySQL e regras de persistência.
- `src/routes/`: define as rotas HTTP por domínio.
- `src/services/`: concentra lógica reutilizável de auth, auditoria e webhook.
- `src/config/`: centraliza env, CORS e rate limits.

## Requisitos

- Node.js 20+ (recomendado 22)
- Banco MySQL acessível
- Variáveis de ambiente configuradas

## Instalação

```bash
npm install
```

## Variáveis de Ambiente

Use `.env` local e mantenha `.env.example` no repositório apenas com placeholders.

Principais variáveis:

- `PORT`
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `DB_SSL`
- `DB_SSL_REJECT_UNAUTHORIZED`
- `DB_SSL_MODE` (`off`, `required`, `verify-ca`)
- `DB_SSL_CA_PEM`
- `DB_SSL_CA_PATH`
- `JWT_SECRET`
- `JWT_ISSUER`
- `JWT_AUDIENCE`
- `PASSWORD_PEPPER`
- `WEBHOOK_SECRET`
- `WEBHOOK_SIGNATURE_TOLERANCE_SEC`
- `WEBHOOK_ALLOW_LEGACY_SECRET`
- `REFRESH_TOKEN_TTL_DAYS`
- `AUTH_COOKIES_ENABLED`
- `ACCESS_TOKEN_COOKIE_NAME`
- `REFRESH_TOKEN_COOKIE_NAME`
- `ACCESS_TOKEN_COOKIE_MAX_AGE_SEC`
- `REFRESH_TOKEN_COOKIE_MAX_AGE_SEC`
- `AUTH_COOKIE_DOMAIN`
- `AUTH_COOKIE_SAMESITE`
- `AUTH_COOKIE_SECURE`
- `CORS_ALLOWED_ORIGINS`

## SSL/CA do Aiven

Para MySQL com Aiven, o recomendado é:

- `DB_SSL_MODE=verify-ca`
- `DB_SSL_CA_PEM` com o certificado PEM completo

Exemplo:

```env
DB_SSL_CA_PEM=-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----
```

Alternativa local com arquivo:

```powershell
$env:NODE_EXTRA_CA_CERTS='C:\caminho\para\certs\ca.pem'
npm run dev
```

## Scripts

```bash
npm run dev
npm run dev:ca-file
npm run build
npm start
```

## Como Rodar

Desenvolvimento:

```bash
npm run dev
```

Produção:

```bash
npm run build
npm start
```

## Rotas Principais

Públicas:

- `GET /`
- `POST /login`
- `POST /auth/refresh`
- `POST /webhook`

Protegidas:

- `POST /logout`
- `GET /relatorio`
- `GET /relatorio/total-ganho`
- `POST /usuarios`
- `GET /usuarios`
- `GET /usuarios/:id`
- `PUT /usuarios/:id`
- `DELETE /usuarios/:id`

## Fluxo de Autenticação

1. `POST /login` retorna `token` e `refreshToken`.
2. Se `AUTH_COOKIES_ENABLED=true`, os tokens também são enviados em cookie `HttpOnly`.
3. As rotas protegidas aceitam `Authorization: Bearer <token>` ou cookie.
4. O refresh é feito em `POST /auth/refresh`.
5. O logout revoga `access token` e `refresh token`.

## Webhook

Headers esperados para HMAC:

- `x-webhook-timestamp`
- `x-webhook-signature`

Assinatura:

```txt
HMAC_SHA256(WEBHOOK_SECRET, "<timestamp>.<rawBody>")
```

Observações:

- `rawBody` precisa ser preservado exatamente como recebido.
- O replay é bloqueado em banco pela tabela `webhook_replay`.
- O modo legado com `x-webhook-secret` ainda pode ser habilitado por flag.

## Banco de Dados

Tabelas principais:

- `usuarios`
- `webhooks`
- `funil_vendas`
- `token_revogados`
- `auditoria_eventos`
- `webhook_replay`
- `login_lockouts`
- `refresh_tokens`

O schema base está em `banco.sql`, e as tabelas de segurança também são garantidas no startup.

## Segurança Aplicada

- JWT com `issuer`, `audience`, `jti` e expiração curta
- Revogação persistente de token
- Refresh token rotativo
- Lock progressivo por `login + IP`
- Rate limit global e por rotas sensíveis
- CORS restrito
- `helmet`
- Auditoria em banco
- TLS/CA configurável para MySQL no Aiven

## Nest Backend

O projeto `nest-backend/` não substitui o backend Express atual. Ele foi criado em pasta separada para uma arquitetura paralela em `NestJS`, também conectada a `MySQL/Aiven`. Veja `nest-backend/README.md`.

## Troubleshooting

### `self-signed certificate in certificate chain`

- Preferir `DB_SSL_MODE=verify-ca`
- Configurar `DB_SSL_CA_PEM` ou `DB_SSL_CA_PATH`
- Em desenvolvimento local, usar `NODE_EXTRA_CA_CERTS` quando necessário

### `EADDRINUSE: address already in use :::8000`

- Já existe processo usando a porta
- Troque `PORT` ou encerre o processo atual

### Login retorna `401` com credenciais corretas

- Verifique `PASSWORD_PEPPER`
- Se ele mudou, hashes antigos podem falhar até serem migrados

## Boas Práticas

- Nunca versionar `.env`
- Nunca commitar segredos reais
- Rotacionar segredos periodicamente
- Preferir `DB_SSL_MODE=verify-ca` em produção
- Usar usuário de banco dedicado, nunca `root`
