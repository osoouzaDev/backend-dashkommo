# DashKommo — Backend

API backend do painel **DashKommo**, construída em **Node.js + TypeScript + Express**.
É responsável por:

- autenticação de usuários (access token + refresh token rotativo);
- CRUD de usuários com controle de acesso por perfil;
- ingestão e processamento do **webhook da Kommo** (CRM);
- consolidação de leads no funil de vendas;
- geração de relatórios gerenciais;
- auditoria de eventos de segurança.

O banco de dados é um **MySQL** (compatível com **Aiven**), acessado via `mysql2/promise`.

---

## Sumário

- [Visão Geral](#visão-geral)
- [Stack](#stack)
- [Arquitetura](#arquitetura)
- [Estrutura de Pastas](#estrutura-de-pastas)
- [Responsabilidades dos Arquivos](#responsabilidades-dos-arquivos)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Variáveis de Ambiente](#variáveis-de-ambiente)
- [SSL/CA do Aiven](#sslca-do-aiven)
- [Scripts](#scripts)
- [Como Rodar](#como-rodar)
- [Rotas da API](#rotas-da-api)
- [Autenticação](#autenticação)
- [Webhook da Kommo](#webhook-da-kommo)
- [Regras de Negócio](#regras-de-negócio)
- [Banco de Dados](#banco-de-dados)
- [Segurança Aplicada](#segurança-aplicada)
- [Observações e Limitações](#observações-e-limitações)
- [Troubleshooting](#troubleshooting)
- [Boas Práticas](#boas-práticas)

---

## Visão Geral

O projeto é um **monólito de API única** em Express. Todo o código de aplicação vive em `src/`,
organizado por camadas (`config`, `db`, `middlewares`, `routes`, `schemas`, `services`, `utils`, `types`).

Principais fluxos:

1. **Autenticação**: `POST /login` valida credenciais, aplica *lock* progressivo por falha e emite um
   `access token` (JWT) e um `refresh token` (opaco, rotativo, persistido em hash).
2. **Ingestão de webhook**: a Kommo envia eventos de leads para `POST /webhook`. Os leads são
   normalizados e persistidos na tabela `funil_vendas`.
3. **Relatórios**: rotas administrativas leem o `funil_vendas` e retornam os dados de funil/total ganho.

## Stack

| Camada | Tecnologia |
| --- | --- |
| Runtime | Node.js (20+, recomendado 22) |
| Linguagem | TypeScript (`strict`) |
| Servidor HTTP | Express 4 |
| Banco | MySQL via `mysql2/promise` |
| Autenticação | `jsonwebtoken` (JWT HS256) |
| Hash de senha | `argon2` (argon2id) + migração de hashes legados `bcryptjs` |
| Validação | `zod` |
| Hardening HTTP | `helmet`, `cors`, `express-rate-limit` |
| Config | `dotenv` |
| Dev | `tsx` (watch), `cross-env`, `typescript` |

## Arquitetura

Componentes principais:

```txt
[Cliente / Frontend]-→[Express API]─┬─→[Middleware: CORS / Helmet / RateLimit / RequestId]
                                     ├─→[Routes]──→ auth | webhook | reports | users | health
                                     ├─→[Services]─ auth | webhook | auditoria
                                     └─→[BancoMysql]──→ MySQL (Aiven)
[Kommo CRM]-→POST /webhook────────────────┘
```

- `src/main.ts` faz o *bootstrap*: carrega o `env`, garante as tabelas de segurança no startup e sobe o servidor.
- `src/app.ts` monta o pipeline Express e registra os routers.
- `src/db/bancoMysql.ts` centraliza **toda** a persistência (uma classe `BancoMysql`, exportada como singleton `banco`).
- `src/services/*` concentra regras reutilizáveis (token/senha, assinatura do webhook, auditoria).
- `src/middlewares/*` faz autenticação (`auth`), autorização por perfil (`autorizarAdmin`) e tratamento global de erro.

> Observação: versões anteriores deste repositório continham um `nest-backend/` experimental (NestJS).
> Ele **não existe mais** neste repositório — o backend ativo é exclusivamente o `src/` em Express.

## Estrutura de Pastas

```txt
src/
  config/
    cors.ts          # política de CORS por origem
    env.ts           # leitura + validação de variáveis de ambiente
    rateLimit.ts     # limitadores globais e por rota
  db/
    bancoMysql.ts    # pool MySQL e todos os métodos de persistência
  middlewares/
    auth.ts          # autenticação via JWT (header ou cookie)
    autorizarAdmin.ts# exigência de perfil administrador
    errorHandler.ts  # tratamento global de erros
  routes/
    auth.ts          # login, refresh, logout
    health.ts        # healthcheck
    reports.ts       # relatórios (admin)
    users.ts         # CRUD de usuários + perfil
    webhook.ts       # ingestão do webhook da Kommo
  schemas/
    index.ts         # schemas zod de validação de entrada
  services/
    auditoria.ts     # registro de auditoria (à prova de falha)
    auth.ts          # token de acesso, refresh, verificação de senha
    webhook.ts       # assinatura HMAC, anti-replay, resumo de payload
  types/
    express.d.ts     # extensões de tipo do Request
  utils/
    cookies.ts       # escrita/leitura/limpeza de cookies de auth
    request.ts       # x-request-id e IP do cliente
    validation.ts    # helper de validação + resposta de erro
  app.ts             # montagem da aplicação Express
  main.ts            # bootstrap do servidor
banco.sql            # schema base + seed do usuário administrador
.env.example         # template de variáveis de ambiente
```

## Responsabilidades dos Arquivos

| Arquivo | Responsabilidade |
| --- | --- |
| `src/main.ts` | Carrega `dotenv`, garante tabelas de segurança e inicia o `app.listen`. |
| `src/app.ts` | Instancia o Express, aplica helmet/CORS/parsers/limiter e monta os routers. |
| `src/config/env.ts` | Lê e valida as envs (segredos fortes, tolerância de webhook, cookies). Exporta `env` e `ValidationError`. |
| `src/config/cors.ts` | Define as origens permitidas (produção vs. desenvolvimento) e as opções do CORS com `credentials`. |
| `src/config/rateLimit.ts` | Exporta `globalLimiter`, `loginLimiter`, `webhookLimiter`, `refreshLimiter`, `logoutLimiter` e as constantes de lock. |
| `src/db/bancoMysql.ts` | Pool MySQL e todos os métodos (usuários, auth, webhook, leads, relatórios, auditoria). |
| `src/middlewares/auth.ts` | Valida o JWT (algoritmo, issuer, audience, `jti`, expiração) e checa revogação no banco. |
| `src/middlewares/autorizarAdmin.ts` | Bloqueia rotas para quem não é `administrador`. |
| `src/middlewares/errorHandler.ts` | Converte erros (CORS, payload grande, demais) em respostas JSON. |
| `src/routes/auth.ts` | `POST /login`, `POST /auth/refresh`, `POST /logout`. |
| `src/routes/health.ts` | `GET /` — healthcheck. |
| `src/routes/reports.ts` | `GET /relatorio`, `GET /relatorio/total-ganho`. |
| `src/routes/users.ts` | `PUT /perfil` e CRUD de usuários (rotas admin). |
| `src/routes/webhook.ts` | `POST /webhook` — recepção, autenticação e processamento dos leads. |
| `src/schemas/index.ts` | Schemas zod de login, refresh, logout, usuário e webhook. |
| `src/services/auth.ts` | Geração de access/refresh token, verificação de senha (argon2/bcrypt) e migração de hash. |
| `src/services/webhook.ts` | Validação de assinatura HMAC, secret legado, anti-replay e resumo de payload. |
| `src/services/auditoria.ts` | `registrarAuditoriaSeguro()` — persiste auditoria sem quebrar o fluxo em caso de erro. |
| `src/utils/cookies.ts` | `writeAuthCookies()` / `clearAuthCookies()` / `getCookie()`. |
| `src/utils/request.ts` | `attachRequestId()`, `getClientIp()`, `getHeaderString()`. |
| `src/utils/validation.ts` | `validarEntrada()` (zod) e `responderErro()` (mapeia erro para status). |

## Requisitos

- Node.js 20+ (recomendado 22)
- Banco MySQL acessível (ex.: Aiven)
- Variáveis de ambiente configuradas

## Instalação

```bash
npm install
```

## Variáveis de Ambiente

Use um `.env` local. O repositório mantém apenas `.env.example` com placeholders.

| Variável | Descrição | Padrão |
| --- | --- | --- |
| `PORT` | Porta HTTP do servidor | `8000` |
| `DB_HOST` | Host do MySQL | — (obrigatório) |
| `DB_PORT` | Porta do MySQL | `3306` |
| `DB_USER` | Usuário do banco (não pode ser `root`) | — (obrigatório) |
| `DB_PASSWORD` | Senha do banco | — (obrigatório) |
| `DB_NAME` | Nome do banco | — (obrigatório) |
| `DB_SSL` | Flag legada de SSL | `false` |
| `DB_SSL_REJECT_UNAUTHORIZED` | Usada no modo legado | `true` |
| `DB_SSL_MODE` | `off` \| `required` \| `verify-ca` | `off` |
| `DB_SSL_CA_PEM` | Certificado CA em PEM (aceita `\n`) | — |
| `DB_SSL_CA_PATH` | Caminho para arquivo CA | — |
| `JWT_SECRET` | Segredo do JWT (≥ 32 chars, alta entropia) | — (obrigatório) |
| `JWT_ISSUER` | Emissor esperado no JWT | `backend-dashkommo` |
| `JWT_AUDIENCE` | Audiência esperada no JWT | `frontend-dashkommo` |
| `PASSWORD_PEPPER` | Pepper somado à senha antes do hash (≥ 32 chars) | — (obrigatório) |
| `WEBHOOK_SECRET` | Segredo do HMAC do webhook (≥ 32 chars) | — (obrigatório) |
| `WEBHOOK_SIGNATURE_TOLERANCE_SEC` | Janela de tolerância do timestamp (s) | `300` |
| `WEBHOOK_ALLOW_LEGACY_SECRET` | Habilita `x-webhook-secret` legado | `false` |
| `REFRESH_TOKEN_TTL_DAYS` | Validade do refresh token (dias) | `30` |
| `AUTH_COOKIES_ENABLED` | Ativa cookies HttpOnly de auth | `false` |
| `ACCESS_TOKEN_COOKIE_NAME` | Nome do cookie de access token | `access_token` |
| `REFRESH_TOKEN_COOKIE_NAME` | Nome do cookie de refresh token | `refresh_token` |
| `ACCESS_TOKEN_COOKIE_MAX_AGE_SEC` | Max-Age do cookie de access | `1800` |
| `REFRESH_TOKEN_COOKIE_MAX_AGE_SEC` | Max-Age do cookie de refresh | `2592000` |
| `AUTH_COOKIE_DOMAIN` | Domínio do cookie | — |
| `AUTH_COOKIE_SAMESITE` | `lax` \| `strict` \| `none` | `lax` (dev) / `none` (prod) |
| `AUTH_COOKIE_SECURE` | Flag `Secure` do cookie | `true` em produção |
| `CORS_ALLOWED_ORIGINS` | Origens extras permitidas (CSV) | — |
| `NODE_ENV` | Ambiente da aplicação | — |

Regras de validação relevantes em [env.ts](file:///c:/Users/HP/Documents/GitHub/backend-dashkommo/src/config/env.ts):

- `JWT_SECRET`, `PASSWORD_PEPPER` e `WEBHOOK_SECRET` precisam ter **≥ 32 caracteres** e **não** conter `change_me`.
- `AUTH_COOKIE_SAMESITE=none` exige `AUTH_COOKIE_SECURE=true`.
- Em produção, `DB_SSL_MODE` não pode ser `off` e o usuário do banco não pode ser `root`.

## SSL/CA do Aiven

Configuração recomendada para MySQL no Aiven:

```env
DB_SSL_MODE=verify-ca
DB_SSL_CA_PEM=-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----
```

Alternativa com arquivo local:

```powershell
$env:NODE_EXTRA_CA_CERTS='C:\caminho\para\certs\ca.pem'
npm run dev
```

## Scripts

```bash
npm run dev        # tsx watch em src/main.ts
npm run dev:ca-file# dev com NODE_EXTRA_CA_CERTS=./certs/ca.pem
npm run build      # compila TypeScript para dist/
npm start          # executa dist/main.js
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

O schema base está em [banco.sql](file:///c:/Users/HP/Documents/GitHub/backend-dashkommo/banco.sql). As tabelas
de segurança (`token_revogados`, `auditoria_eventos`, `webhook_replay`, `login_lockouts`, `refresh_tokens`)
e a tabela `funil_vendas` são **garantidas automaticamente no startup** por `inicializarTabelasSeguranca()`.

## Rotas da API

| Método | Rota | Acesso | Descrição |
| --- | --- | --- | --- |
| `GET` | `/` | Público | Healthcheck (`{ ok: true, message }`). |
| `POST` | `/webhook` | Público (assinado) | Recebe eventos da Kommo. |
| `POST` | `/login` | Público | Autentica e retorna `token` + `refreshToken`. |
| `POST` | `/auth/refresh` | Público | Rotaciona o refresh token e emite novo access token. |
| `POST` | `/logout` | Autenticado | Revoga o access token (jti) e o refresh token. |
| `PUT` | `/perfil` | Autenticado | Atualiza o próprio nome. |
| `POST` | `/usuarios` | Admin | Cria usuário. |
| `GET` | `/usuarios` | Admin | Lista usuários. |
| `GET` | `/usuarios/:id` | Admin | Busca usuário por ID. |
| `PUT` | `/usuarios/:id` | Admin | Atualiza usuário. |
| `DELETE` | `/usuarios/:id` | Admin | Exclui usuário. |
| `GET` | `/relatorio` | Admin | Retorna os leads do `funil_vendas` com a categoria. |
| `GET` | `/relatorio/total-ganho` | Admin | Soma o valor dos leads com `status_id = 142` (ganho). |

Regras de proteção nos usuários:

- Um admin **não** pode alterar o próprio nível de acesso.
- Um admin **não** pode excluir a própria conta.
- Login/e-mail duplicados resultam em erro de conflito.

## Autenticação

Fluxo:

1. `POST /login` retorna `{ token, refreshToken, usuario }`.
2. Se `AUTH_COOKIES_ENABLED=true`, os dois tokens também são enviados como cookies `HttpOnly`.
3. Rotas protegidas aceitam `Authorization: Bearer <token>` **ou** o cookie de access token.
4. `POST /auth/refresh` gera um **novo** access token e rotaciona o refresh token.
5. `POST /logout` revoga o `jti` do access token e o refresh token.

Detalhes dos tokens:

- **Access token (JWT)**: HS256, expiração de **30 minutos**, `issuer`/`audience` validados,
  `jti` (UUID) e `subject` = id do usuário. A revogação é verificada a cada requisição na tabela `token_revogados`.
- **Refresh token**: 48 bytes aleatórios em hex. O banco guarda apenas o **hash SHA-256**.
  Há **rotação** a cada uso (via `family_id`); se um token já usado for reapresentado, **toda a família é revogada**.
- **Lock de login**: após falhas, o par `login + IP` é bloqueado com backoff exponencial
  (base 5 min, teto 60 min), persistido em `login_lockouts`.

Senhas:

- Hash **argon2id** (memoryCost 65536, timeCost 3, parallelism 2) com `PASSWORD_PEPPER`.
- Hashes legados em **bcrypt** continuam válidos e são **migrados automaticamente** para argon2 no próximo login bem-sucedido.

## Webhook da Kommo

Headers usados na assinatura HMAC:

- `x-webhook-timestamp` (ou `x-timestamp`)
- `x-webhook-signature` (ou `x-signature`), aceitando prefixo `sha256=`

Assinatura:

```txt
HMAC_SHA256(WEBHOOK_SECRET, "<timestamp>.<rawBody>")
```

Regras:

- O `rawBody` é preservado exatamente como recebido (parser customizado em [app.ts](file:///c:/Users/HP/Documents/GitHub/backend-dashkommo/src/app.ts)).
- O `timestamp` precisa estar dentro da tolerância (`WEBHOOK_SIGNATURE_TOLERANCE_SEC`).
- **Anti-replay**: a chave `sha256("<timestamp>:<assinatura>")` é gravada em `webhook_replay`; se já existir, a requisição é tratada como replay.
- Modo legado (`x-webhook-secret`) só é aceito se `WEBHOOK_ALLOW_LEGACY_SECRET=true` (método `isWebhookLegacySecretValid()`, comparação em tempo constante).

Payloads aceitos:

- `leads.add[]` e `leads.update[]` — arrays de leads;
- **lead direto**: objeto com `id`, `pipeline_id`, `status_id` e `responsible_user_id`.

Cada lead é gravado em `webhooks` (histórico bruto) e processado por `processarLead()`, que atualiza `funil_vendas`.
O endpoint sempre responde `200` para a Kommo, mesmo em falha de processamento (evita reenvio em loop).

## Regras de Negócio

### Vínculo consultor → nome

| `responsible_user_id` | Consultor |
| --- | --- |
| `9400123` | Mateus |
| `11016288`, `1120681` | Ana |
| `13637692` | Rafael |
| `13661460` | Gabriel \| B.O.S Hoss |
| `11016300` | Gestor Comercial |
| `15050505` | Luís/Testes |

### Status/etapa do funil

| `status_id` | Etapa |
| --- | --- |
| `100504439` | Tenho que descobrir |
| `100233527` | Qualificado - Em conversa |
| `96885212` | Pronto para Falar |
| `84315468` | Alinhamento Regulaziração / L. de Pendências |
| `82988164` | Desqualificado |
| `81175456` | Gerar Forms |
| `73520776` | Movido para Cadência |
| `72912304` | Lead novo |
| `72897132` | Fazer Ligação |
| `72762308` | Funil Nutrição a Longo Prazo |
| `72670564` | Fechamento |
| `72656692` | Proposta |
| `72649772` | Reunião |
| `68647324` | Perdido |
| `68432532` | Negociação |
| `68325220` | Fechamento |
| `68325216` | Envio de Proposta |
| `66780248` | Conversa |
| `66773868` | Venda |
| `143` | Perdido |
| `142` | Ganho |

- **Classificação**: `142` → `ganho`; `143` → `perdido`; qualquer outro status válido → `andamento`.
- Status fora dessa lista são **ignorados** (logados e descartados).
- **`data_venda`**: preenchida apenas quando o lead está em `ganho` (`status_id = 142`). Se houve transição para ganho (`old_status_id` diferente de 142), usa-se `updated_at`; caso contrário, `created_at`.
- **Origem**: extraída dos campos customizados `Origem do lead` / `ORIGEM DO LEAD` / `Origem TXT` / `ORIGEM`; se ausente, usa `Não classificado`.

## Banco de Dados

| Tabela | Função |
| --- | --- |
| `usuarios` | Contas de acesso (nome, email, setor, `userLogin`, `acesso`, senha). |
| `webhooks` | Histórico bruto dos eventos recebidos (`evento`, `payload` JSON, timestamps UTC/local). |
| `funil_vendas` | Leads consolidados (etapa, consultor, origem, valor, datas de criação/atualização/venda). |
| `token_revogados` | JTIs de access tokens revogados (até expirarem). |
| `auditoria_eventos` | Trilha de auditoria (evento, resultado, metadados). |
| `webhook_replay` | Chaves de replay do webhook (anti-replay). |
| `login_lockouts` | Estado de bloqueio progressivo de login por `login + IP`. |
| `refresh_tokens` | Refresh tokens em hash, com `family_id`, expiração e revogação. |

- O pool MySQL usa `timezone: "-04:00"`; o campo `criado_em_local` é gravado no fuso `America/Cuiaba`.
- `banco.sql` cria o schema base e faz *seed* do usuário administrador inicial.

## Segurança Aplicada

- JWT com `issuer`, `audience`, `jti` e expiração curta (30 min), algoritmo fixado em HS256.
- Revogação persistente de access token e refresh token rotativo com detecção de reuso por família.
- Lock progressivo de login por `login + IP`.
- Rate limit global e por rota sensível (ver tabela abaixo).
- CORS restrito por origem, com `credentials`.
- `helmet` para cabeçalhos de segurança.
- `PASSWORD_PEPPER` + argon2id e migração automática de hashes legados.
- Comparações de segredo em tempo constante (`timingSafeEqual`).
- Auditoria persistida em banco para login, refresh, logout, webhook e operações de usuário.
- Limite de payload de `200kb` por requisição (e teto de 200.000 bytes no webhook).
- TLS/CA configurável para o MySQL no Aiven.

Limites de rate limit:

| Limiter | Janela | Máx. requisições |
| --- | --- | --- |
| global | 15 min | 200 |
| login | 15 min | 10 |
| webhook | 15 min | 60 |
| refresh | 15 min | 30 |
| logout | 15 min | 60 |

## Observações e Limitações

- **Bypass de assinatura no webhook**: atualmente, quando a assinatura HMAC **não** é válida, a requisição ainda
  é aceita — é emitido apenas um `console.warn` e o campo `autenticacao` na auditoria registra
  `bypass_sem_validacao`. Recomenda-se tornar a rejeição obrigatória em produção
  (ver [webhook.ts](file:///c:/Users/HP/Documents/GitHub/backend-dashkommo/src/routes/webhook.ts#L40-L50)).
- **Mapeamentos "hardcoded"**: etapas, consultores e status válidos estão fixos em
  [bancoMysql.ts](file:///c:/Users/HP/Documents/GitHub/backend-dashkommo/src/db/bancoMysql.ts#L45-L67).
- **Dependências não utilizadas**: `mongodb`, `jspdf` e `jspdf-autotable` estão declaradas no
  `package.json` mas não são referenciadas no código.
- **Arquivo `.gitignore`** contém `*.md`, o que impediria o versionamento de novos arquivos Markdown
  (o `README.md` já estava rastreado antes da regra).

## Troubleshooting

### `self-signed certificate in certificate chain`

- Preferir `DB_SSL_MODE=verify-ca`.
- Configurar `DB_SSL_CA_PEM` ou `DB_SSL_CA_PATH`.
- Em desenvolvimento local, usar `NODE_EXTRA_CA_CERTS` quando necessário.

### `EADDRINUSE: address already in use :::8000`

- Já existe um processo usando a porta. Troque `PORT` ou encerre o processo.

### `Variável JWT_SECRET fraca` (ou outro segredo)

- O valor precisa ter ≥ 32 caracteres e não pode conter `change_me`.

### Login retorna `401` com credenciais corretas

- Verifique `PASSWORD_PEPPER`. Se ele mudou, hashes antigos podem falhar até serem migrados.
- Verifique se o par `login + IP` não está temporariamente bloqueado (`login_lockouts`).

### `DB_SSL_MODE não pode ser off em produção`

- Em `NODE_ENV=production`, configure `DB_SSL_MODE=required` ou `verify-ca`.

## Boas Práticas

- Nunca versionar `.env` nem commitar segredos reais.
- Rotacionar segredos periodicamente.
- Preferir `DB_SSL_MODE=verify-ca` em produção.
- Usar um usuário de banco dedicado (nunca `root`).
- Manter os mapeamentos de status/consultor sincronizados com o CRM ao mudar o funil.
