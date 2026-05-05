# Documentacao Tecnica do Sistema DashKommo (Modelo para TCC)

## 1. Identificacao do Projeto

- **Nome do sistema:** DashKommo
- **Tipo:** Aplicacao web full stack
- **Frontend:** Next.js + React + TypeScript
- **Backend:** Node.js + Express + TypeScript
- **Banco de dados:** MySQL
- **Data de referencia desta documentacao:** 2026-05-04

---

## 2. Resumo

O sistema DashKommo foi desenvolvido para apoiar operacoes de acompanhamento comercial, com foco em autenticacao de usuarios, controle de permissao por perfil, ingestao de eventos via webhook e consolidacao de relatorios. A solucao e dividida em duas camadas principais: frontend web para interacao do usuario e backend API para regras de negocio, seguranca e persistencia.

---

## 3. Objetivo Geral

Disponibilizar uma plataforma segura e organizada para:

- autenticacao e autorizacao de usuarios;
- consulta e administracao de usuarios;
- processamento de eventos externos recebidos via webhook;
- visualizacao de indicadores e relatorios operacionais.

### 3.1 Objetivos Especificos

- Implementar login com access token e refresh token.
- Restringir recursos administrativos apenas a perfil `administrador`.
- Reduzir riscos de abuso com rate limiting e auditoria.
- Integrar captura de eventos da Kommo por assinatura HMAC.
- Permitir operacao local e em producao com variaveis de ambiente.

---

## 4. Escopo Funcional

### 4.1 Modulos do Frontend

- Tela de login.
- Dashboard principal.
- Gestao de usuarios.
- Modulo de leads.
- Relatorios.
- Configuracoes.

### 4.2 Modulos do Backend

- Autenticacao (`/login`, `/auth/refresh`, `/logout`).
- CRUD de usuarios (rotas protegidas, perfil admin).
- Recepcao e validacao de webhook (`/webhook`).
- Relatorios (`/relatorio`, `/relatorio/total-ganho`).

---

## 5. Arquitetura do Sistema

### 5.1 Visao em Camadas

1. **Camada de Apresentacao (Frontend):** Next.js renderiza telas e chama API.
2. **Camada de Aplicacao (Backend):** Express aplica regras, autenticacao e validacoes.
3. **Camada de Dados (MySQL):** persistencia de usuarios, tokens, auditoria e eventos.

### 5.2 Fluxo Resumido

```text
Usuario -> Frontend (Next.js) -> API (Express) -> MySQL
                               -> Integracao Webhook (Kommo)
```

---

## 6. Tecnologias Utilizadas

### 6.1 Frontend

- Next.js 16
- React 19
- TypeScript
- Tailwind CSS
- ESLint

### 6.2 Backend

- Node.js
- Express
- TypeScript
- mysql2/promise
- jsonwebtoken
- argon2 / bcryptjs (migracao de hash legado)
- zod
- helmet
- express-rate-limit
- cors

---

## 7. Modelo de Seguranca

### 7.1 Autenticacao e Sessao

- Login retorna `token` (access token) e `refreshToken`.
- Refresh token rotativo com revogacao de familia em comportamento suspeito.
- Logout revoga `jti` do access token e invalida refresh token.
- Backend suporta:
  - modo tradicional por `Authorization: Bearer <token>`;
  - modo com cookies `HttpOnly` (quando habilitado por ambiente).

### 7.2 Controle de Acesso

- Middleware de autenticacao em rotas protegidas.
- Middleware de autorizacao para perfil `administrador`.

### 7.3 Endurecimento de API

- `helmet` para headers de seguranca.
- CORS restrito por lista de origens permitidas.
- Limite de taxa global e por rotas sensiveis (`login`, `refresh`, `logout`, `webhook`).
- Auditoria de eventos de seguranca em banco.
- Lock progressivo de tentativas de login por combinacao login + IP.

### 7.4 Seguranca de Webhook

- Assinatura HMAC SHA-256 com timestamp.
- Validacao de tolerancia temporal.
- Anti-replay persistente em banco.

### 7.5 Seguranca no Frontend

- Consumo autenticado centralizado.
- Renovacao automatica de token em respostas `401/403`.
- Timeout de requisicao para evitar travamentos.
- Preparado para `credentials: include` (compatibilidade com cookie `HttpOnly`).

---

## 8. Persistencia e Estruturas de Dados

Entidades e tabelas de seguranca relevantes:

- `usuarios`
- `refresh_tokens`
- `token_revogados`
- `auditoria_eventos`
- `webhook_replay`
- `login_lockouts`

Essas estruturas suportam rastreabilidade, revogacao de sessao e protecao contra abuso.

---

## 9. API Principal

### 9.1 Rotas Publicas

- `GET /`
- `POST /login`
- `POST /auth/refresh`
- `POST /webhook`

### 9.2 Rotas Protegidas

- `POST /logout`
- `GET /usuarios`
- `GET /usuarios/:id`
- `POST /usuarios`
- `PUT /usuarios/:id`
- `DELETE /usuarios/:id`
- `GET /relatorio`
- `GET /relatorio/total-ganho`

---

## 10. Configuracao de Ambiente

### 10.1 Frontend

- Variavel principal: `NEXT_PUBLIC_API_URL`
- Em desenvolvimento: `http://localhost:8000`
- Em producao: obrigatoriamente HTTPS

### 10.2 Backend

Principais grupos:

- conexao banco (`DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`);
- SSL do banco (`DB_SSL_MODE`, `DB_SSL_CA_PEM`, `DB_SSL_CA_PATH`);
- JWT (`JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`);
- protecao de webhook (`WEBHOOK_SECRET`, tolerancia e legado);
- cookies de autenticacao (`AUTH_COOKIES_ENABLED`, `AUTH_COOKIE_*`).

---

## 11. Implantacao e Execucao

### 11.1 Ambiente local

1. Subir banco MySQL.
2. Configurar `.env` no backend e `.env.local` no frontend.
3. Executar backend (`npm run dev`).
4. Executar frontend (`npm run dev`).
5. Acessar `http://localhost:3000`.

### 11.2 Build de producao

- Frontend: `npm run build` e `npm run start`.
- Backend: `npm run build` e `npm start`.

---

## 12. Qualidade e Validacao

- Projeto frontend com verificacao de lint e build.
- Projeto backend com build TypeScript validado.
- Fluxo critico validado: login -> uso de rota protegida -> refresh -> logout.

---

## 13. Limitacoes Atuais

- Dependencia de correta configuracao de variaveis de ambiente.
- Qualidade da seguranca final depende de operacao segura em producao (segredos, SSL e CORS corretos).
- Integracao com webhook depende do segredo compartilhado e sincronismo de tempo.

---

## 14. Trabalhos Futuros

- Cobertura automatizada de testes E2E para fluxo completo.
- Observabilidade com dashboards de auditoria e alertas.
- Politicas mais estritas de CSP no frontend.
- Pipeline CI/CD com scans de seguranca adicionais.

---

## 15. Conclusao

O DashKommo apresenta arquitetura coerente para um sistema web corporativo, com separacao de responsabilidades entre frontend e backend, controles de seguranca relevantes para autenticacao moderna e trilha de auditoria para operacao. A solucao atende ao objetivo de centralizar autenticacao, operacao administrativa e ingestao de eventos, mantendo base tecnica adequada para evolucao futura em contexto academico e profissional.

---

## 16. Referencias de Codigo (Projeto)

- Frontend: `c:\Users\HP\Documents\GitHub\frontend-dashkommo`
- Backend: `c:\Users\HP\Documents\GitHub\backend-dashkommo`
- Configuracao de API no frontend: `services/api.ts`
- Fluxo autenticado no frontend: `services/authFetch.ts`
- API principal no backend: `src/main.ts`
- Acesso a dados e seguranca no backend: `src/db/bancoMysql.ts`

