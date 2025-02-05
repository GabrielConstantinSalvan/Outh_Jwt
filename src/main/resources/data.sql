
-- Criação da tabela tb_roles, se ainda não existir
CREATE TABLE IF NOT EXISTS tb_roles (
    role_id INT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

-- Inserção de dados na tabela
INSERT IGNORE INTO tb_roles (role_id, name) VALUES (1, 'admin');
INSERT IGNORE INTO tb_roles (role_id, name) VALUES (2, 'basic');
