CREATE TABLE citizens (
    id BIGINT(9) NOT NULL PRIMARY KEY,
    first_name VARCHAR(50),
    surname VARCHAR(50),
    date_of_birth DATE,
    salt TEXT,
    verifier TEXT,
    polling_station INT,
    isVotingKeyReceived BOOLEAN
);

INSERT INTO citizens (id, first_name, surname, date_of_birth, salt, verifier, polling_station, isVotingKeyReceived)
VALUES
(123456789, 'John', 'Doe', '1980-01-01', '', '', 0, 0),
(987654321, 'Jane', 'Doe', '1985-02-02', '', '', 0, 0),
(456789123, 'Emily', 'Smith', '1990-03-03', '', '', 0, 0),
(456734545, 'Van', 'Hellsing', '1990-03-03', '', '', 0, 0);

-- Создание таблицы votes
CREATE TABLE votes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    vote TEXT NOT NULL,
    validator VARCHAR(255) NOT NULL,
    polling_station VARCHAR(255) NOT NULL
);

-- Создание таблицы used_tokens
CREATE TABLE used_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE encryption_keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
);


CREATE TABLE admin_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'stakeholder') NOT NULL,
    polling_station INT DEFAULT 0
);

