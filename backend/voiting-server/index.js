const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const port = 3003;
const JWT_SECRET = 'your-secret-key-for-jwt';

// Database configuration
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '8954132016',
    database: 'voting-system',
    insecureAuth: true
});

// Middleware setup
app.use(cors({
    origin: 'http://localhost:3000',  // URL of the frontend
    credentials: true
}));
app.use(bodyParser.json());

// Endpoint to validate token and record vote
app.post('/vote', async (req, res) => {
    const { encryptedVote, token, validator, pooling_station } = req.body;
    try {
        // Validate the JWT token
        let decoded = null;
        if (token == null) {
            return res.status(400).json({ status: 'error', message: 'You have already voted!' });
        }
        else decoded = jwt.verify(token, JWT_SECRET);

        if (decoded) {
            // Check if the token has been used before
            const [rows] = await db.query('SELECT token FROM used_tokens WHERE token = ?', [token]);
            if (rows.length > 0) {
                return res.status(400).json({ status: 'error', message: 'You have already voted!' });
            }
            // Record the vote in the 'votes' table
            await db.query('INSERT INTO votes (vote, validator, polling_station) VALUES (?, ?, ?)', [encryptedVote, validator, pooling_station]);
            // Record the used token in the 'used_tokens' table
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

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
