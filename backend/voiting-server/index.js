const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const port = 3003;

// Настройка базы данных
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '8954132016',
    database: 'voting-system',
    insecureAuth: true
});

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',  // frontend url
    credentials: true
}));
app.use(bodyParser.json());

// Проверка токена и запись голоса
app.post('/vote', async (req, res) => {
    const { encryptedVote, token, validator, pooling_station } = req.body;
    console.log("encryptedVote: " + encryptedVote + " token: " + token + " validator: " + validator + " pooling_station: " + pooling_station);
    const secret = 'your-secret-key-for-jwt';

    try {
        // Проверка валидности токена
        let decoded = null;
        if (token == null) {
            return res.status(400).json({ status: 'error', message: 'You have already voted!' });
        }
        else decoded = jwt.verify(token, secret);

        if (decoded) {
            // Проверка, использовался ли токен ранее
            console.log("token: " + token)
            const [rows] = await db.query('SELECT token FROM used_tokens WHERE token = ?', [token]);
            if (rows.length > 0) {
                return res.status(400).json({ status: 'error', message: 'You have already voted!' });
            }
            // Запись голоса в таблицу votes
            await db.query('INSERT INTO votes (vote, validator, polling_station) VALUES (?, ?, ?)', [encryptedVote, validator, pooling_station]);

            // Запись использованного токена в таблицу used_tokens
            await db.query('INSERT INTO used_tokens (token) VALUES (?)', [token]);

            res.json({ status: 'success', message: 'Vote recorded successfully' });
        } else {
            res.status(401).json({ status: 'error', message: 'Invalid token' });
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
