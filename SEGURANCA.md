# Seguranca do Projeto

Este documento descreve, em detalhe, as medidas de seguranca implementadas no backend, incluindo:

- o que e utilizado,
- como e utilizado,
- para que e utilizado.

O objetivo e servir como referencia tecnica para desenvolvimento, operacao e auditoria.

## 1. Visao Geral de Seguranca

O projeto adota uma estrategia de defesa em camadas:

- endurecimento de borda HTTP (`helmet`, CORS, limites),
- autenticacao forte com JWT e revogacao persistente,
- autorizacao por perfil para rotas sensiveis,
- protecao de webhook com assinatura HMAC e anti-replay,
- controles anti-forca-bruta no login,
- auditoria de eventos de seguranca,
- validacao de entrada e reducao de superficie de ataque.

## 2. Segredos e Variaveis de Ambiente

### 2.1 Segredos obrigatorios fortes

As variaveis abaixo sao obrigatorias e validadas como segredos fortes:

- `JWT_SECRET`
- `PASSWORD_PEPPER`
- `WEBHOOK_SECRET`

Regra aplicada no startup:

- tamanho minimo de 32 caracteres,
- bloqueio de placeholders fracos (ex.: contendo `change_me`).

**Para que serve:** impedir inicializacao com configuracao insegura.

### 2.2 Separacao de configuracao sensivel

- `.env` e local e nao deve ser versionado.
- `.env.example` documenta a estrutura esperada sem segredos reais.

**Para que serve:** reduzir risco de vazamento acidental de segredo em repositorio.

## 3. Seguranca HTTP na Borda

### 3.1 `helmet`

O backend usa `helmet()` globalmente.

**Para que serve:** aplicar cabecalhos HTTP de seguranca (hardening contra classes comuns de ataques no navegador/proxy).

### 3.2 Remocao de fingerprint

- `x-powered-by` e desabilitado.

**Para que serve:** reduzir exposicao de informacao de stack para atacantes.

### 3.3 CORS restrito

- Lista de origens confiaveis (`allowlist`) no codigo.
- Suporte a origens extras por env (`CORS_ALLOWED_ORIGINS`).
- Bloqueio de origem nao permitida com erro explicito.

**Para que serve:** impedir chamadas de frontends nao autorizados em contexto browser.

## 4. Rate Limiting e Anti-Abuso

### 4.1 Limite global

Rate limit global para reduzir abuso generalizado.

### 4.2 Limites por rota sensivel

- `/login`: limite de tentativas por janela.
- `/webhook`: limite proprio.
- `/auth/refresh`: limite proprio.
- `/logout`: limite proprio.

**Para que serve:** reduzir brute force, spray e abuso de endpoints de alto impacto.

## 5. Autenticacao (JWT)

### 5.1 Emissao de access token

No login, o access token e emitido com:

- algoritmo `HS256`,
- expiracao curta (`30m`),
- `issuer` (`JWT_ISSUER`),
- `audience` (`JWT_AUDIENCE`),
- `jwtid` (`jti`) unico,
- `subject` com ID do usuario.

**Para que serve:** token curto e rastreavel, com validacao contextual.

### 5.2 Validacao de token no middleware

O middleware de autenticacao valida:

- formato `Bearer`,
- assinatura JWT,
- algoritmo permitido,
- `issuer` e `audience`,
- existencia/validade de `jti` e `exp`,
- revogacao persistente no banco.

**Para que serve:** impedir uso de token invalido, adulterado, fora de contexto ou revogado.

## 6. Revogacao de Sessao

### 6.1 Revogacao de access token por `jti`

No logout, o `jti` do access token e gravado em `token_revogados` com expiracao.

O middleware consulta essa tabela a cada request protegida.

**Para que serve:** encerrar sessao imediatamente sem depender do tempo de expiracao natural do JWT.

### 6.2 Refresh token rotativo

Fluxo implementado:

- login gera `refreshToken` aleatorio + `family_id`,
- token e armazenado de forma hash (`sha256`) em `refresh_tokens`,
- endpoint `/auth/refresh` rotaciona token (revoga antigo e cria novo),
- tentativa suspeita de reuse pode levar a revogacao da familia.

**Para que serve:** reduzir impacto de vazamento de refresh token e endurecer persistencia de sessao.

## 7. Senhas e Credenciais

### 7.1 Hash de senha

- Hash principal: `argon2id` com parametros robustos.
- `PASSWORD_PEPPER` aplicado antes do hash.
- Suporte de migracao de hash legado no login.

**Para que serve:** aumentar custo de quebra offline e elevar resiliencia em caso de vazamento de banco.

### 7.2 Politica basica

Validacoes de senha no dominio:

- obrigatoria,
- tamanho minimo de 8,
- tamanho maximo de 255.

## 8. Protecao de Webhook

### 8.1 Assinatura HMAC

O endpoint `/webhook` exige:

- `x-webhook-timestamp`,
- `x-webhook-signature` no formato `sha256=<hex>`.

Assinatura esperada:

`HMAC_SHA256(WEBHOOK_SECRET, "<timestamp>.<rawBody>")`

### 8.2 Janela temporal

Timestamp e validado contra tolerancia configurada:

- `WEBHOOK_SIGNATURE_TOLERANCE_SEC` (ex.: 300s).

### 8.3 Anti-replay

Requisicoes com mesma combinacao assinatura/timestamp sao bloqueadas.

Implementacao:

- hash da chave de replay em `webhook_replay`,
- expiracao automatica por tempo.

### 8.4 Compatibilidade legada (opcional)

Se `WEBHOOK_ALLOW_LEGACY_SECRET=true`, header legado `x-webhook-secret` e aceito.

**Recomendacao:** apos migracao completa de emissor, manter `false`.

**Para que serve:** transicao sem indisponibilidade durante mudanca de protocolo.

## 9. Autorizacao (RBAC)

Controle por perfil em middleware:

- `administrador`
- `usuario`

Rotas administrativas exigem:

- token valido,
- `acesso === "administrador"`.

**Para que serve:** impedir elevacao de privilegio e acesso indevido a operacoes sensiveis.

## 10. Validacao de Entrada

`zod` e utilizado para:

- validar body de login,
- validar body de refresh/logout,
- validar payloads de criacao/edicao de usuario,
- validar params (`id`) em rotas de usuario.

**Para que serve:** reduzir ataque por payload malformado, inconsistencias e bypass por dados inesperados.

## 11. Banco de Dados e TLS

### 11.1 Conexao segura

Suporte de modo SSL:

- `DB_SSL_MODE=off|required|verify-ca`
- compatibilidade legado com `DB_SSL` + `DB_SSL_REJECT_UNAUTHORIZED`

CA customizado:

- `DB_SSL_CA_PEM` (recomendado em plataforma cloud),
- fallback opcional `DB_SSL_CA_PATH`.

### 11.2 Protecoes de configuracao

- bloqueio de usuario `root` na aplicacao,
- validacao de porta,
- em producao, nao permite SSL desligado.

### 11.3 Queries parametrizadas

Operacoes SQL usam placeholders (`?`) via `mysql2`.

**Para que serve:** reduzir risco de SQL injection por interpolacao direta.

## 12. Auditoria e Rastreabilidade

Tabela `auditoria_eventos` registra eventos como:

- login (sucesso/falha/negado),
- refresh token (sucesso/falha/negado),
- logout,
- webhook (sucesso/falha/negado),
- operacoes de usuario.

Metadados incluem, quando aplicavel:

- IP,
- `requestId`,
- motivo da falha/negacao.

**Para que serve:** investigacao de incidente, deteccao de padrao suspeito e trilha de compliance.

## 13. Tabelas de Seguranca no Banco

Criacao automatica (`CREATE TABLE IF NOT EXISTS`) no startup:

- `token_revogados`
- `auditoria_eventos`
- `webhook_replay`
- `login_lockouts`
- `refresh_tokens`

Tambem declaradas em `banco.sql`.

## 14. CI e Governanca Tecnica

Workflow de seguranca em CI:

- build TypeScript,
- `npm audit --omit=dev`.

**Para que serve:** prevenir regressao de seguranca em merge/deploy.

## 15. Controles de Operacao Recomendados

Para ambiente de producao:

- `DB_SSL_MODE=verify-ca`
- `DB_SSL_CA_PEM` configurado com CA valido do provedor
- `WEBHOOK_ALLOW_LEGACY_SECRET=false`
- rotacao periodica de segredos
- monitoramento de `auditoria_eventos`
- backups e testes de restauracao
- principio de menor privilegio para usuario de banco

## 16. Limites e Observacoes

Seguranca nao e estado final; e processo continuo.

Pontos importantes:

- troca de `PASSWORD_PEPPER` sem estrategia de migracao pode invalidar login de usuarios existentes;
- refresh e lockouts estao persistidos em banco (robusto para restart), mas observabilidade e tuning de thresholds devem evoluir com trafego real;
- migracao de legado de webhook deve ser planejada para evitar indisponibilidade.

## 17. Checklist Rapido de Verificacao

- [ ] Startup sem erro de segredo fraco
- [ ] Conexao DB com TLS valida
- [ ] Login retorna `token` + `refreshToken`
- [ ] Refresh rotaciona token corretamente
- [ ] Logout revoga sessao
- [ ] Webhook invalido retorna `401`
- [ ] Webhook HMAC valido retorna `200`
- [ ] Rotas admin bloqueiam usuario nao admin
- [ ] Auditoria registra eventos esperados

---

Se este documento for atualizado, manter alinhamento com:

- `README.md`
- `GUIA-DEPLOY.md`
- `.env.example`
- implementacao real em `src/main.ts`, `src/middlewares/auth.ts` e `src/db/bancoMysql.ts`.
