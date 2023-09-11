// Importing required modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const srp = require('secure-remote-password/server');
const session = require('express-session');
const mysql = require('mysql2/promise');
const keySignLib = require('./keySignLib');  // For vote validator generation
const jwt = require('jsonwebtoken');  // For one-time token generation for voting on another server
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Some settings
const SERVER_PORT = 3001;
const NUMBER_OF_POLLING_STATIONS = 4;
const JWT_SECRET = 'your-secret-key-for-jwt';

// Database connection setup
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '8954132016',
    database: 'voting-system',
    insecureAuth : true
});

// Express app setup
const app = express();
app.use(bodyParser.json());
app.use(cors({
    origin: 'http://localhost:3000',  // Frontend URL
    credentials: true
}));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Set to true if using HTTPS
}));

// Signup route
app.post('/signup', async (req, res) => {
    const { username, salt, verifier } = req.body;
    try {
        // Check if the username (ID) exists in the database
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
        // Random number between 1 and number of polling stations
        const polling_station = Math.floor(Math.random() * NUMBER_OF_POLLING_STATIONS) + 1;
        await db.query('UPDATE citizens SET salt = ?, verifier = ?, polling_station = ? WHERE id = ?', [salt, verifier, polling_station, username]);
        res.send({ status: 'ok' });
    } catch (err) {
        console.error(err);
        res.status(500).send({ status: 'error', message: 'Internal Server Error' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, clientPublicEphemeral } = req.body;
    try {
        // Get salt and verifier from the database
        const [rows] = await db.query('SELECT salt, verifier FROM citizens WHERE id = ?', [username]);
        if (rows.length === 0) {
            return res.status(400).send({ status: 'error', message: 'ID not found' });
        }
        const { salt, verifier } = rows[0];
        const serverEphemeral = srp.generateEphemeral(verifier);
        req.session.clientPublicEphemeral = clientPublicEphemeral;
        req.session.serverEphemeralSecret = serverEphemeral.secret;
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
        // Retrieving data from the database
        const [rows] = await db.query('SELECT salt, verifier, polling_station FROM citizens WHERE id = ?', [username]);
        // Check for data existence
        if (rows.length === 0) {
            return res.status(400).send({ status: 'error', message: 'ID not found' });
        }
        const { salt, verifier, polling_station} = rows[0];
        // Retrieve saved data from the session
        const serverSecretEphemeral = req.session.serverEphemeralSecret;
        const clientPublicEphemeral = req.session.clientPublicEphemeral;
        // Getting the public key from the database (in send we will send it to the client)
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
            // Set a flag in the session indicating successful authorisation
            req.session.isAuthenticated = true;
            req.session.username = username;
            // Getting isVotingKeyReceived value from the database
            const [isVotingRows] = await db.query('SELECT isVotingKeyReceived FROM citizens WHERE id = ?', [username]);
            const isVotingKeyReceived = isVotingRows[0].isVotingKeyReceived;
            // If isVotingKeyReceived is 1, set token to null, otherwise generate a one-time token for voting on another server
            let token = null;
            if (isVotingKeyReceived !== 1) {
                token = jwt.sign({}, JWT_SECRET, { expiresIn: '1h' });
            }
            // Generate a validator using keySignLib
            const validator = keySignLib.generateSign();
            res.send({ serverSessionProof: serverSession.proof, token, validator, polling_station, publicKey });
            try {
                // Set isVotingKeyReceived to 1 for this user
                await db.query('UPDATE citizens SET isVotingKeyReceived = 1 WHERE id = ?', [username]);
            } catch (error) {
                console.error('Error with setting isVotingKeyReceived:', error);
            }
        } catch (e) {
            // Set a flag in the session indicating unsuccessful authorisation
            req.session.isAuthenticated = false;
            console.error('Failed to derive server session', e);
            res.status(400).send({ status: 'error', message: 'Failed to validate session' });
        }
    } catch (err) {
        console.error('Database error', err);
        res.status(500).send({ status: 'error', message: 'Internal Server Error' });
    }
});

// Function to get or generate RSA keys for voting
async function getOrGenerateKeys() {
    let publicKey, privateKey;
    // Attempt to retrieve keys from the database
    const [rows] = await db.query('SELECT public_key, private_key FROM encryption_keys LIMIT 1');
    if (rows.length > 0) {
        publicKey = rows[0].public_key;
        privateKey = rows[0].private_key;
    } else {
        // Generate a new key pair if none are found in the database
        const keys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
        privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
        // Save the new keys to the database
        await db.query('INSERT INTO encryption_keys (public_key, private_key) VALUES (?, ?)', [publicKey, privateKey]);
    }
    return { publicKey, privateKey };
}

// Function to decrypt a vote
async function decryptVote(encryptedVoteBase64) {
    const encryptedVoteBuffer = Buffer.from(encryptedVoteBase64, 'base64');
    // Retrieve the private key from the database
    const [keyRows] = await db.query('SELECT private_key FROM encryption_keys LIMIT 1');
    const privateKeyPem = keyRows[0].private_key;
    // Decrypt the vote
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

// Endpoint to fetch voting results
app.get('/results', async (req, res) => {
    try {
        // Retrieve all rows from the votes table
        const [rows] = await db.query('SELECT * FROM votes');
        // Getting the number of rows where isVotingKeyReceived = 1
        const [keyReceivedRows] = await db.query('SELECT COUNT(*) as count FROM citizens WHERE isVotingKeyReceived = 1');
        const keyReceivedCount = keyReceivedRows[0].count;
        // Obtaining the total number of votes by polling station
        const [pollingStationRows] = await db.query('SELECT polling_station, COUNT(*) as count FROM citizens WHERE isVotingKeyReceived = 1 GROUP BY polling_station');
        const pollingStationCounts = {};
        pollingStationRows.forEach(row => {
            pollingStationCounts[row.polling_station] = row.count;
        });
        // Counter for counting corrupted votes
        let corruptedVotes = 0;
        // Object for storing the results of the plots
        const pollingStations = {};
        let forDemocrats = 0;
        let forRepublicans = 0;
        // Decoding, verification and counting of votes
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
            // Initialise the object for the new site
            if (!pollingStations[row.polling_station]) {
                pollingStations[row.polling_station] = {
                    forDemocrats: 0,
                    forRepublicans: 0
                };
            }
            // Counting of votes for a polling station
            if (decryptedVote === 'Democrats') {
                pollingStations[row.polling_station].forDemocrats++;
            } else if (decryptedVote === 'Republicans') {
                pollingStations[row.polling_station].forRepublicans++;
            }
        }

        // Check the number of votes
        const totalVotes = forDemocrats + forRepublicans;
        if (keyReceivedCount > totalVotes) {
            return res.status(400).json({ status: 'error', message: 'Mismatch in vote counts' });
        }
        // Check the number of votes by precinct
        for (const [pollingStation, counts] of Object.entries(pollingStations)) {
            const totalStationVotes = counts.forDemocrats + counts.forRepublicans;
            if (pollingStationCounts[pollingStation] < totalStationVotes) {
                return res.status(400).json({ status: 'error', message: `Mismatch in vote counts for polling station ${pollingStation}` });
            }
        }
        // Return full voting results
        res.send({ pollingStations, forDemocrats, forRepublicans, corruptedVotes });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

// Endpoint for admin signup
app.post('/api/admin/signup', async (req, res) => {
    try {
        const { username, password, role, polling_station } = req.body;
        // Hash the password
        const passwordHash = await bcrypt.hash(password, 10);
        // Insert data into the database
        const [rows] = await db.query('INSERT INTO admin_users (username, password_hash, role, polling_station) VALUES (?, ?, ?, ?)', [username, passwordHash, role, polling_station]);
        // Send a successful response
        res.json({ status: 'success' });
    } catch (error) {
        // Log and send the error to the client
        console.error("Error during signup:", error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});


// Endpoint for admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [users] = await db.query('SELECT * FROM admin_users WHERE username = ?', [username]);
        const user = users[0];
        if (!user) { return res.status(400).json({ status: 'error', message: 'User not found' }); }
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) { return res.status(400).json({ status: 'error', message: 'Invalid password' }); }
        // Save data in session
        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.polling_station = user.polling_station;
        // Force session save
        req.session.save((err) => {if (err) {console.error(err); } });
        res.json({ status: 'success', role: user.role, polling_station: user.polling_station });
    } catch (error) {
        console.error('An error occurred:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

// Endpoint to return polling station data for a stakeholder
app.get('/api/admin/session', async (req, res) => {
    if (!req.session.userId) {return res.status(401).json({ status: 'error', message: 'Not authenticated' }); }
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

// Endpoint to check votes for a stakeholder
app.get('/api/admin/check_votes', async (req, res) => {
    if (!req.session.userId || req.session.role !== 'stakeholder') {
        return res.status(401).json({ status: 'error', message: 'Not authenticated or not a stakeholder' });
    }
    try {
        const pollingStation = req.session.polling_station;
        // Retrieve all rows from the votes table for this polling station
        const [rows] = await db.query('SELECT * FROM votes WHERE polling_station = ?', [pollingStation]);

        let corruptedVotes = 0;
        let forDemocrats = 0;
        let forRepublicans = 0;
        // Decrypt each vote and check the validator and vote value
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
        //If there is even one corrupted voice, we return an error
        if (corruptedVotes > 0) {
            return res.status(400).json({ status: 'error', message: 'Some votes are corrupted' });
        }
        res.json({ status: 'success', forDemocrats, forRepublicans });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

app.post('/api/admin/restart_voting', async (req, res) => {
    try {
        // Deleting all rows from tables
        await db.query('DELETE FROM citizens');
        await db.query('DELETE FROM votes');
        await db.query('DELETE FROM used_tokens');
        await db.query('DELETE FROM encryption_keys');

        // Inserting initial data into the citizens table
        const insertQuery = `
            INSERT INTO citizens (id, first_name, surname, date_of_birth, salt, verifier, polling_station, isVotingKeyReceived)
            VALUES ?`;

        const values = [
            [123456789, 'John', 'Doe', '1980-01-01', '', '', 0, 0],
            [987654321, 'Jane', 'Doe', '1985-02-02', '', '', 0, 0],
            [456789123, 'Emily', 'Smith', '1990-03-03', '', '', 0, 0],
            [456734545, 'Van', 'Hellsing', '1990-03-03', '', '', 0, 0],
            [111111111, 'Alice', 'Johnson', '1970-04-04', '', '', 0, 0],
            [222222222, 'Bob', 'Williams', '1975-05-05', '', '', 0, 0],
            [333333333, 'Charlie', 'Brown', '1982-06-06', '', '', 0, 0],
            [444444444, 'David', 'Lee', '1987-07-07', '', '', 0, 0],
            [555555555, 'Eve', 'Clark', '1992-08-08', '', '', 0, 0],
            [666666666, 'Frank', 'Lewis', '1995-09-09', '', '', 0, 0],
            [777777777, 'Grace', 'Walker', '1998-10-10', '', '', 0, 0],
            [888888888, 'Helen', 'Hall', '2000-11-11', '', '', 0, 0],
            [999999999, 'Ivy', 'Green', '2002-12-12', '', '', 0, 0],
            [121212121, 'Jack', 'Adams', '2003-01-13', '', '', 0, 0],
            [131313131, 'Karen', 'Baker', '2004-02-14', '', '', 0, 0],
            [141414141, 'Leo', 'Carter', '2005-03-15', '', '', 0, 0],
            [151515151, 'Mia', 'Davis', '2006-04-16', '', '', 0, 0],
            [161616161, 'Nina', 'Evans', '2007-05-17', '', '', 0, 0],
            [171717171, 'Oscar', 'Foster', '2008-06-18', '', '', 0, 0],
            [181818181, 'Paul', 'Garcia', '2009-07-19', '', '', 0, 0]
        ];

        await db.query(insertQuery, [values]);

        res.json({ status: 'success', message: 'Voting restarted successfully' });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

// Initialize server
(async () => {
    await getOrGenerateKeys();
    // Now start the server
    app.listen(SERVER_PORT, () => {
        console.log('Server running on http://localhost:3001/');
    });
})();
