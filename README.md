# Backend DashKommo

API backend em Node.js + TypeScript para autenticacao, gestao de usuarios (com perfil admin), ingestao de webhook e relatorios.

## Stack

- Node.js
- TypeScript
- Express
- MySQL (`mysql2/promise`)
- JWT (`jsonwebtoken`)
- Hash de senha com `argon2` (e migracao de hashes legados)
- Validacao de entrada com `zod`

## Funcionalidades

- Login com `token` (access token) e `refreshToken` rotativo
- Logout com revogacao de token (`jti`) persistente em banco
- Controle de acesso por perfil (`administrador` e `usuario`)
- Protecao de webhook por assinatura HMAC (com opcao de legado por flag)
- Anti-replay de webhook (persistente em banco)
- Rate limit global e por rotas sensiveis
- Auditoria de eventos de seguranca

## Estrutura de pastas

```txt
src/
  db/
    bancoMysql.ts
  middlewares/
    auth.ts
    autorizarAdmin.ts
  types/
    express.d.ts
  main.ts
```

## Requisitos

- Node.js 20+ (recomendado 22)
- Banco MySQL acessivel
- Variaveis de ambiente configuradas

## Instalacao

```bash
npm install
```

## Variaveis de ambiente

Use `.env` local (nao versionar) e mantenha `.env.example` no repositorio.

Variaveis principais:

- `PORT` (ex.: `8000`)
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `DB_SSL` (legado; prefira `DB_SSL_MODE`)
- `DB_SSL_REJECT_UNAUTHORIZED` (legado; usado com `DB_SSL=true`)
- `DB_SSL_MODE` (`off`, `required` ou `verify-ca`)
- `DB_SSL_CA_PEM` (recomendado no Render; CA em PEM, aceita `\n`)
- `DB_SSL_CA_PATH` (opcional, caminho para CA customizado)
- `JWT_SECRET` (segredo forte, minimo 32 chars)
- `JWT_ISSUER`
- `JWT_AUDIENCE`
- `PASSWORD_PEPPER` (segredo forte, minimo 32 chars)
- `WEBHOOK_SECRET` (segredo forte, minimo 32 chars)
- `WEBHOOK_SIGNATURE_TOLERANCE_SEC` (ex.: `300`)
- `WEBHOOK_ALLOW_LEGACY_SECRET` (`false` recomendado apos migracao)
- `REFRESH_TOKEN_TTL_DAYS` (ex.: `30`)
- `AUTH_COOKIES_ENABLED` (`true` para habilitar cookie HttpOnly)
- `ACCESS_TOKEN_COOKIE_NAME` / `REFRESH_TOKEN_COOKIE_NAME`
- `ACCESS_TOKEN_COOKIE_MAX_AGE_SEC` / `REFRESH_TOKEN_COOKIE_MAX_AGE_SEC`
- `AUTH_COOKIE_DOMAIN` (opcional)
- `AUTH_COOKIE_SAMESITE` (`lax`, `strict` ou `none`)
- `AUTH_COOKIE_SECURE` (`true` em producao; obrigatorio com `SameSite=None`)

## Certificado CA (MySQL SSL)

Se seu provedor exigir CA customizado:

1. Preferencial (Render): usar env `DB_SSL_CA_PEM` com o conteudo completo do certificado PEM.
2. Opcional: salvar em arquivo e usar `DB_SSL_CA_PATH`.

Exemplo de `DB_SSL_CA_PEM`:

```env
DB_SSL_CA_PEM=-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----
```

Opcao alternativa com arquivo:

```powershell
$env:NODE_EXTRA_CA_CERTS='C:\caminho\para\certs\ca.pem'
npm run dev
```

## Scripts

```bash
npm run dev
npm run build
npm start
```

## Subindo o projeto

Dev:

```bash
npm run dev
```

Producao:

```bash
npm run build
npm start
```

## Rotas principais

Publicas:

- `GET /`
- `POST /login`
- `POST /auth/refresh`
- `POST /webhook`

Protegidas:

- `POST /logout`
- `GET /relatorio` (admin)
- `GET /relatorio/total-ganho` (admin)
- `POST /usuarios` (admin)
- `GET /usuarios` (admin)
- `GET /usuarios/:id` (admin)
- `PUT /usuarios/:id` (admin)
- `DELETE /usuarios/:id` (admin)

## Fluxo de autenticacao

1. `POST /login` retorna:
   - `token` (access token)
   - `refreshToken`
2. Se `AUTH_COOKIES_ENABLED=true`, os mesmos tokens tambem sao enviados via cookie `HttpOnly`.
3. Use `Authorization: Bearer <token>` nas rotas protegidas (ou cookie quando habilitado).
4. Quando o access token expirar, use `POST /auth/refresh` com:
   - `{ "refreshToken": "..." }`
   - ou sem body quando `refresh_token` estiver em cookie
5. No logout, envie:
   - Header `Authorization: Bearer <token>`
   - Body `{ "refreshToken": "..." }`
   - ou apenas cookie quando auth por cookie estiver habilitada

## Webhook com HMAC

Headers esperados:

- `x-webhook-timestamp`: unix timestamp em segundos
- `x-webhook-signature`: `sha256=<assinatura_hex>`

Assinatura:

```txt
HMAC_SHA256( WEBHOOK_SECRET, "<timestamp>.<rawBody>" )
```

Notas:

- `rawBody` deve ser exatamente o JSON enviado (mesmo espaco e ordem de bytes)
- Requisicoes repetidas com mesma assinatura/timestamp sao bloqueadas (anti-replay)
- Se `WEBHOOK_ALLOW_LEGACY_SECRET=true`, o header legado `x-webhook-secret` ainda e aceito

## Teste rapido (Postman)

1. `POST /login` -> salvar `token` e `refreshToken`
2. `GET /usuarios` com `Bearer <token>`
3. `POST /auth/refresh` com `refreshToken`
4. `POST /logout` com `Bearer` + `refreshToken`
5. `POST /webhook` sem assinatura -> deve retornar `401`
6. `POST /webhook` com HMAC valido -> deve retornar `200`

## Seguranca aplicada

- JWT com `issuer`, `audience`, `jti`, expiracao curta
- Revogacao persistente de access token (`token_revogados`)
- Refresh token rotativo com revogacao de familia em caso suspeito
- Lock progressivo de login por `login + IP`
- Rate limit global e por rotas sensiveis
- CORS restrito
- `helmet`
- Auditoria de eventos em banco
- CI de seguranca em `.github/workflows/security.yml`

## Banco de dados

As tabelas de seguranca sao criadas no startup (`CREATE TABLE IF NOT EXISTS`), incluindo:

- `token_revogados`
- `auditoria_eventos`
- `webhook_replay`
- `login_lockouts`
- `refresh_tokens`

Tambem estao declaradas em `banco.sql`.

## Troubleshooting

### Erro `self-signed certificate in certificate chain`

- Preferir `DB_SSL_MODE=verify-ca` + `DB_SSL_CA_PATH` (ou `NODE_EXTRA_CA_CERTS`)
- Em dev local apenas, use `DB_SSL_MODE=off` (ou `required` se quiser TLS sem validar CA)

### Erro `EADDRINUSE: address already in use :::8000`

- Ja existe processo usando a porta 8000
- Encerre o processo ou altere `PORT`

### Login retorna sempre `401` com credenciais corretas

- Verifique `PASSWORD_PEPPER`
- Se o pepper mudou, hashes antigos podem nao validar

## Boas praticas

- Nunca versionar `.env`
- Nunca commitar segredos reais
- Rotacionar segredos periodicamente
- Manter `WEBHOOK_ALLOW_LEGACY_SECRET=false` apos migracao
- Em producao, manter `DB_SSL=true` e `DB_SSL_REJECT_UNAUTHORIZED=true`
