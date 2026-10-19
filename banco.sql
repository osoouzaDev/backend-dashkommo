USE dbdefault;

CREATE TABLE IF NOT EXISTS usuarios (
	id BIGINT PRIMARY KEY AUTO_INCREMENT,
    nome varchar(50) NOT NULL,
    email varchar(100) NOT NULL UNIQUE,
    acesso ENUM('administrador', 'usuario') NOT NULL,
    setor VARCHAR(50) NOT NULL,
    userLogin VARCHAR(50) NOT NULL UNIQUE,
    senha VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Crie o primeiro administrador manualmente com uma senha forte.
-- A senha é armazenada em argon2id (com PASSWORD_PEPPER) ou bcrypt legado.
-- Gere o hash e insira abaixo, ou crie o usuário pelo fluxo da aplicação.
-- INSERT INTO dbdefault.usuarios (nome, email, acesso, setor, userLogin, senha)
-- VALUES ('Admin', 'admin@example.com', 'administrador', 'TI', 'admin',
--         '<hash-da-senha>');

CREATE TABLE webhooks (
 id INT AUTO_INCREMENT PRIMARY KEY,
 evento VARCHAR(100),
 payload JSON,
 criado_em_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 criado_em_local DATETIME,
 INDEX idx_evento (evento),
 INDEX idx_data (criado_em_utc)
);

CREATE TABLE funil_vendas (
 id INT AUTO_INCREMENT PRIMARY KEY,
 lead_id BIGINT NOT NULL UNIQUE,
 lead_nome VARCHAR(255),
 consultor_id BIGINT NOT NULL,
 consultor_nome VARCHAR(100),
 origem VARCHAR(100),
 pipeline_id BIGINT,
 status_id BIGINT,
 etapa VARCHAR(50),
 valor DECIMAL(10,2) DEFAULT 0,
 data_criacao DATETIME,
 data_atualizacao DATETIME,
 data_venda DATETIME NULL,
 INDEX idx_consultor (consultor_id),
 INDEX idx_status (status_id),
 INDEX idx_data (data_criacao),
 INDEX idx_data_venda (data_venda)
);

CREATE TABLE IF NOT EXISTS token_revogados (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    jti VARCHAR(128) NOT NULL UNIQUE,
    expira_em DATETIME NOT NULL,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_expira_em (expira_em)
);

CREATE TABLE IF NOT EXISTS auditoria_eventos (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    evento VARCHAR(100) NOT NULL,
    resultado VARCHAR(50) NOT NULL,
    metadados JSON,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_evento_criado (evento, criado_em)
);

CREATE TABLE IF NOT EXISTS webhook_replay (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    replay_key_hash VARCHAR(128) NOT NULL UNIQUE,
    expira_em DATETIME NOT NULL,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_webhook_replay_expira (expira_em)
);

CREATE TABLE IF NOT EXISTS login_lockouts (
    attempt_key VARCHAR(191) PRIMARY KEY,
    fail_count INT NOT NULL DEFAULT 0,
    lock_until DATETIME NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token_hash CHAR(64) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    family_id CHAR(36) NOT NULL,
    expira_em DATETIME NOT NULL,
    revogado_em DATETIME NULL,
    substituido_por_hash CHAR(64) NULL,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_refresh_user (user_id),
    INDEX idx_refresh_family (family_id),
    INDEX idx_refresh_expira (expira_em)
);
