-- Create the citizens table
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

-- Insert test data into the citizens table
INSERT INTO citizens (id, first_name, surname, date_of_birth, salt, verifier, polling_station, isVotingKeyReceived)
VALUES
(123456789, 'John', 'Doe', '1980-01-01', '', '', 0, 0),
(987654321, 'Jane', 'Doe', '1985-02-02', '', '', 0, 0),
(456789123, 'Emily', 'Smith', '1990-03-03', '', '', 0, 0),
(456734545, 'Van', 'Hellsing', '1990-03-03', '', '', 0, 0),
(111111111, 'Alice', 'Johnson', '1970-04-04', '', '', 0, 0),
(222222222, 'Bob', 'Williams', '1975-05-05', '', '', 0, 0),
(333333333, 'Charlie', 'Brown', '1982-06-06', '', '', 0, 0),
(444444444, 'David', 'Lee', '1987-07-07', '', '', 0, 0),
(555555555, 'Eve', 'Clark', '1992-08-08', '', '', 0, 0),
(666666666, 'Frank', 'Lewis', '1995-09-09', '', '', 0, 0),
(777777777, 'Grace', 'Walker', '1998-10-10', '', '', 0, 0),
(888888888, 'Helen', 'Hall', '2000-11-11', '', '', 0, 0),
(999999999, 'Ivy', 'Green', '2002-12-12', '', '', 0, 0),
(121212121, 'Jack', 'Adams', '2003-01-13', '', '', 0, 0),
(131313131, 'Karen', 'Baker', '2004-02-14', '', '', 0, 0),
(141414141, 'Leo', 'Carter', '2005-03-15', '', '', 0, 0),
(151515151, 'Mia', 'Davis', '2006-04-16', '', '', 0, 0),
(161616161, 'Nina', 'Evans', '2007-05-17', '', '', 0, 0),
(171717171, 'Oscar', 'Foster', '2008-06-18', '', '', 0, 0),
(181818181, 'Paul', 'Garcia', '2009-07-19', '', '', 0, 0);

-- Create the votes table
CREATE TABLE votes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    vote TEXT NOT NULL,
    validator VARCHAR(255) NOT NULL,
    polling_station VARCHAR(255) NOT NULL
);

-- Create the used_tokens table
CREATE TABLE used_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(255) UNIQUE NOT NULL
);

-- Create the encryption_keys table
CREATE TABLE encryption_keys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
);

-- Create the admin_users table
CREATE TABLE admin_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'stakeholder') NOT NULL,
    polling_station INT DEFAULT 0
);
