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

INSERT INTO dbdefault.usuarios (nome, email, acesso, setor, userLogin, senha)
VALUES ('Souza', 'admin@example.com', 'administrador', 'TI', 'souza.dev', 'REDACTED');

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
 INDEX idx_consultor (consultor_id),
 INDEX idx_status (status_id),
 INDEX idx_data (data_criacao)
);