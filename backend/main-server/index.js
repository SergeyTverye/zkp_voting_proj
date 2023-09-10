const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const srp = require('secure-remote-password/server');
const session = require('express-session');
const mysql = require('mysql2/promise');
const keySignLib = require('./keySignLib'); // for vote validator generation
const jwt = require('jsonwebtoken'); // one time token generation for voting on another server
const crypto = require('crypto');
const bcrypt = require('bcrypt');


const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '8954132016',
    database: 'voting-system',
    insecureAuth : true
});

const app = express();
app.use(bodyParser.json());
app.use(cors({
    origin: 'http://localhost:3000',  // frontend url
    credentials: true
}));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // true if using HTTPS
}));

// Signup
app.post('/signup', async (req, res) => {
    const { username, salt, verifier } = req.body;
    try {
        // Check if the username (id) exists in the database
        const [rows] = await db.query('SELECT * FROM citizens WHERE id = ?', [username]);
        if (rows.length === 0) {
            return res.status(400).send({ status: 'error', message: 'ID not found' });
        }
        // Check if verifier and salt are already set
        const [userRow] = rows;
        if (userRow.verifier !== '' || userRow.salt !== '') {
            return res.status(400).send({ status: 'error', message: 'User already registered' });
        }
        // Check if the user is over 18 years old
        const [dobRow] = rows;
        const dob = new Date(dobRow.date_of_birth);
        const today = new Date();
        const age = today.getFullYear() - dob.getFullYear();
        if (age < 18) {
            return res.status(400).send({ status: 'error', message: 'User is not over 18' });
        }
        // Store salt and verifier in the database
        const polling_station = Math.floor(Math.random() * 4) + 1;  // Random number between 1 and 4
        await db.query('UPDATE citizens SET salt = ?, verifier = ?, polling_station = ? WHERE id = ?', [salt, verifier, polling_station, username]);
        res.send({ status: 'ok' });
    } catch (err) {
        console.error(err);
        res.status(500).send({ status: 'error', message: 'Internal Server Error' });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { username, clientPublicEphemeral } = req.body;
    //console.log("Login: \nUser name: " + username + "\nclientPublicEphemeral: " + clientPublicEphemeral);
    try {
        // Get salt and verifier from the database
        const [rows] = await db.query('SELECT salt, verifier FROM citizens WHERE id = ?', [username]);
        if (rows.length === 0) {
            return res.status(400).send({ status: 'error', message: 'ID not found' });
        }

        const { salt, verifier } = rows[0];

        //console.log("Salt : " + salt + "\nVerifier: " + verifier);

        const serverEphemeral = srp.generateEphemeral(verifier);
        req.session.clientPublicEphemeral = clientPublicEphemeral;
        req.session.serverEphemeralSecret = serverEphemeral.secret;

        console.log("Saved clientPublicEphemeral : " + req.session.serverEphemeralSecret + "\nSaved serverEphemeral.secret: " + req.session.clientPublicEphemeral);

        // Store `serverEphemeral.secret` for later use (e.g., in a session store)
        // Send `salt` and `serverEphemeral.public` to the client
        res.send({ salt, serverPublicEphemeral: serverEphemeral.public });

    } catch (err) {
        console.error(err);
        res.status(500).send({ status: 'error', message: 'Internal Server Error' });
    }
});


// Validate client proof and send server proof
app.post('/login/validate', async (req, res) => {
    const { username, clientSessionProof } = req.body;

    try {
        // Получение данных из базы данных
        const [rows] = await db.query('SELECT salt, verifier, polling_station FROM citizens WHERE id = ?', [username]);

        // Проверка на наличие данных
        if (rows.length === 0) {
            return res.status(400).send({ status: 'error', message: 'ID not found' });
        }

        const { salt, verifier, polling_station} = rows[0];

        // Получение сохраненных данных из сессии
        const serverSecretEphemeral = req.session.serverEphemeralSecret;
        const clientPublicEphemeral = req.session.clientPublicEphemeral;

        // Принудительное сохранение сессии
        req.session.save((err) => {
            if (err) {
                console.error(err);
            }
        });

        // Получение публичного ключа из базы данных (в send отдадим клиенту)
        const [keyRows] = await db.query('SELECT public_key FROM encryption_keys LIMIT 1');
        const publicKey = keyRows[0].public_key;

        try {
            const serverSession = srp.deriveSession( // если не упало, то мы авторизованы
                serverSecretEphemeral,
                clientPublicEphemeral,
                salt,
                username,
                verifier,
                clientSessionProof
            );

            // Устанавливаем флаг в сессии, указывающий на успешную авторизацию
            req.session.isAuthenticated = true;
            req.session.username = username;

            // Получение значения isVotingKeyReceived из базы данных

            const [isVotingRows] = await db.query('SELECT isVotingKeyReceived FROM citizens WHERE id = ?', [username]);
            const isVotingKeyReceived = isVotingRows[0].isVotingKeyReceived;

            // Если isVotingKeyReceived равно 1, устанавливаем token в null
            let token = null;
            if (isVotingKeyReceived !== 1) {
                const secret = 'your-secret-key-for-jwt';
                // Generate a one-time token for voting on another server
                token = jwt.sign({}, secret, { expiresIn: '1h' });
            }

            // Generate a validator using keySignLib
            const validator = keySignLib.generateSign();

            res.send({ serverSessionProof: serverSession.proof, token, validator, polling_station, publicKey });
            try {
                // Установка значения isVotingKeyReceived в 1 для данного пользователя
                await db.query('UPDATE citizens SET isVotingKeyReceived = 1 WHERE id = ?', [username]);
            } catch (error) {
                console.error('Error with setting isVotingKeyReceived:', error);
            }
        } catch (e) {
            // Устанавливаем флаг в сессии, указывающий на неуспешную авторизацию
            req.session.isAuthenticated = false;
            console.error('Failed to derive server session', e);
            res.status(400).send({ status: 'error', message: 'Failed to validate session' });
        }
    } catch (err) {
        console.error('Database error', err);
        res.status(500).send({ status: 'error', message: 'Internal Server Error' });
    }
});

// just example
app.get('/protected', (req, res) => {
    if (req.session.isAuthenticated) {
        // Выполняем какие-то действия для авторизованных пользователей
    } else {
        // Возвращаем ошибку 401 (Unauthorized)
        res.status(401).send('Unauthorized');
    }
});

async function getOrGenerateKeys() { // либо возьмем из базы, либо сгенерируем новые ключи для RSA для голосов
    let publicKey, privateKey;

    // Try to get keys from the database
    const [rows] = await db.query('SELECT public_key, private_key FROM encryption_keys LIMIT 1');
    if (rows.length > 0) {
        publicKey = rows[0].public_key;
        privateKey = rows[0].private_key;
    } else {
        // Generate new key pair if not found
        const keys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
        privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });

        // Save new keys to the database
        await db.query('INSERT INTO encryption_keys (public_key, private_key) VALUES (?, ?)', [publicKey, privateKey]);
    }

    return { publicKey, privateKey };
}

async function decryptVote(encryptedVoteBase64) {
    const encryptedVoteBuffer = Buffer.from(encryptedVoteBase64, 'base64');

    // Получение приватного ключа из базы данных
    const [keyRows] = await db.query('SELECT private_key FROM encryption_keys LIMIT 1');
    const privateKeyPem = keyRows[0].private_key;

    const decryptedVote = crypto.privateDecrypt(
        {
            key: privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        encryptedVoteBuffer
    );

    return decryptedVote.toString('utf8');
}

// Обработчик для получения результатов голосования
app.get('/results', async (req, res) => {
    try {
        // Получение всех строк из таблицы votes
        const [rows] = await db.query('SELECT * FROM votes');

        // Получение количества строк, где isVotingKeyReceived = 1
        const [keyReceivedRows] = await db.query('SELECT COUNT(*) as count FROM citizens WHERE isVotingKeyReceived = 1');
        const keyReceivedCount = keyReceivedRows[0].count;

        // Получение суммарного количества голосов по участкам
        const [pollingStationRows] = await db.query('SELECT polling_station, COUNT(*) as count FROM citizens WHERE isVotingKeyReceived = 1 GROUP BY polling_station');

        const pollingStationCounts = {};
        pollingStationRows.forEach(row => {
            pollingStationCounts[row.polling_station] = row.count;
        });

        // Счетчик для подсчета поврежденных голосов
        let corruptedVotes = 0;

        // Объект для хранения результатов по участкам
        const pollingStations = {};

        let forDemocrats = 0;
        let forRepublicans = 0;

        console.log("получение расшифрованных голосов:")
        // Расшифровка каждого голоса
        for (const row of rows) {
            const decryptedVote = await decryptVote(row.vote);
            const check = keySignLib.checkSign(row.validator);
            if (!check) {
                corruptedVotes++;
            }
            if (decryptedVote === 'Democrats') {
                forDemocrats++;
            } else if (decryptedVote === 'Republicans') {
                forRepublicans++;
            }
            // Инициализация объекта для нового участка
            if (!pollingStations[row.polling_station]) {
                pollingStations[row.polling_station] = {
                    forDemocrats: 0,
                    forRepublicans: 0
                };
            }
            // Подсчет голосов для участка
            if (decryptedVote === 'Democrats') {
                pollingStations[row.polling_station].forDemocrats++;
            } else if (decryptedVote === 'Republicans') {
                pollingStations[row.polling_station].forRepublicans++;
            }
        }

        // Проверка количества голосов
        const totalVotes = forDemocrats + forRepublicans;
        if (keyReceivedCount > totalVotes) {
            return res.status(400).json({ status: 'error', message: 'Mismatch in vote counts' });
        }
        // Проверка количества голосов по участкам
        for (const [pollingStation, counts] of Object.entries(pollingStations)) {
            const totalStationVotes = counts.forDemocrats + counts.forRepublicans;
            if (pollingStationCounts[pollingStation] < totalStationVotes) {
                return res.status(400).json({ status: 'error', message: `Mismatch in vote counts for polling station ${pollingStation}` });
            }
        }

        console.log({ pollingStations, forDemocrats, forRepublicans, corruptedVotes });
        // Возвращение расшифрованных голосов
        res.send({ pollingStations, forDemocrats, forRepublicans, corruptedVotes });
        //res.json({ status: 'success', decryptedVotes });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});


// Signup
app.post('/api/admin/signup', async (req, res) => {
    try {
        const { username, password, role, polling_station } = req.body;

        // Вывод входных данных в консоль
        console.log("Received signup request:", { username, role, polling_station });

        // Хэширование пароля
        const passwordHash = await bcrypt.hash(password, 10);
        console.log("Password hash generated:", passwordHash);

        // Вставка данных в базу
        const [rows] = await db.query('INSERT INTO admin_users (username, password_hash, role, polling_station) VALUES (?, ?, ?, ?)', [username, passwordHash, role, polling_station]);

        // Вывод информации о вставленной строке
        console.log("Inserted row:", rows);

        // Отправка успешного ответа
        res.json({ status: 'success' });
    } catch (error) {
        // Вывод ошибки в консоль
        console.error("Error during signup:", error);

        // Отправка ошибки клиенту
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});


// Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [users] = await db.query('SELECT * FROM admin_users WHERE username = ?', [username]);
        const user = users[0];

        if (!user) {
            return res.status(400).json({ status: 'error', message: 'User not found' });
        }

        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) {
            return res.status(400).json({ status: 'error', message: 'Invalid password' });
        }

        // Сохранение данных в сессии
        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.polling_station = user.polling_station;

        console.log("login \n req.session.userId  " + req.session.userId + "\nreq.session.role " + req.session.role + "\nreq.session.polling_station " + req.session.polling_station)

        // Принудительное сохранение сессии
        req.session.save((err) => {
            if (err) {
                console.error(err);
            }
        });

        res.json({ status: 'success', role: user.role, polling_station: user.polling_station });
    } catch (error) {
        console.error('An error occurred:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

// для стейкхолдера возвращает данные по участку
app.get('/api/admin/session', async (req, res) => {
    console.log(" get session\n req.session.userId " + req.session.userId + "\nreq.session.role " + req.session.role + "\nreq.session.polling_station " + req.session.polling_station)

    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', message: 'Not authenticated' });
    }

    let theoreticalVotes = 0;
    let actualVotes = 0;

    if (req.session.role === 'stakeholder') {
        const [theoreticalRows] = await db.query('SELECT COUNT(*) as count FROM citizens WHERE polling_station = ? AND isVotingKeyReceived = 1', [req.session.polling_station]);
        theoreticalVotes = theoreticalRows[0].count;

        const [actualRows] = await db.query('SELECT COUNT(*) as count FROM votes WHERE polling_station = ?', [req.session.polling_station]);
        actualVotes = actualRows[0].count;
    }

    res.json({
        status: 'success',
        role: req.session.role,
        polling_station: req.session.polling_station,
        theoreticalVotes,
        actualVotes
    });
});


app.get('/api/admin/check_votes', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'stakeholder') {
        return res.status(401).json({ status: 'error', message: 'Not authenticated or not a stakeholder' });
    }

    try {
        const pollingStation = req.session.polling_station;

        // Получение всех строк из таблицы votes для данного участка
        const [rows] = await db.query('SELECT * FROM votes WHERE polling_station = ?', [pollingStation]);

        let corruptedVotes = 0;
        let forDemocrats = 0;
        let forRepublicans = 0;

        // Расшифровка каждого голоса
        for (const row of rows) {
            const decryptedVote = await decryptVote(row.vote);
            const check = keySignLib.checkSign(row.validator);

            if (!check || (decryptedVote !== 'Democrats' && decryptedVote !== 'Republicans')) {
                corruptedVotes++;
                continue;
            }

            if (decryptedVote === 'Democrats') {
                forDemocrats++;
            } else if (decryptedVote === 'Republicans') {
                forRepublicans++;
            }
        }

        if (corruptedVotes > 0) {
            return res.status(400).json({ status: 'error', message: 'Some votes are corrupted' });
        }

        res.json({ status: 'success', forDemocrats, forRepublicans });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});



// Initialize server
(async () => {
    const { publicKey, privateKey } = await getOrGenerateKeys();
    // console.log('Public Key:', publicKey);
    // console.log('Private Key:', privateKey);

    // Now start the server
    app.listen(3001, () => {
        console.log('Server running on http://localhost:3001/');
    });
})();
