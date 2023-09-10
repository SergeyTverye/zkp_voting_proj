import React from 'react';
import { Button, Container, Typography } from '@mui/material';
import axios from 'axios';
import AuthStore from '../stores/AuthStore'; // Импорт AuthStore
import { CryptoEngine, setEngine } from "pkijs";
import { Snackbar, Alert } from '@mui/material';
import { Link } from 'react-router-dom';
import { makeStyles } from '@mui/styles';

const useStyles = makeStyles({
    customButton: {
        backgroundColor: '#FF5733',
        color: 'white',
        '&:hover': {
            backgroundColor: '#FF2E00',
        },
    },
});



// Инициализация PKIjs с Web Crypto
setEngine("newEngine", window.crypto, new CryptoEngine({ name: "", crypto: window.crypto, subtle: window.crypto.subtle }));

const Vote = () => {
    const [open, setOpen] = React.useState(false);
    const [message, setMessage] = React.useState('');
    const [severity, setSeverity] = React.useState('success');
    const [hasVoted, setHasVoted] = React.useState(false); // Cостояние для отслеживания голосования
    const classes = useStyles();

    const openSnackbar = (message, severity) => {
        setMessage(message);
        setSeverity(severity);
        setOpen(true);
    };

    async function convertPemToJwk(pem) {
        console.log("Original PEM:", pem);
        const crypto = window.crypto.subtle;
        if (!crypto) {
            throw new Error("No crypto");
        }

        const clearPem = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n|\s+/g, "");
        console.log("Cleared PEM:", clearPem);

        const publicKeyBuffer = new Uint8Array(atob(clearPem).split("").map(c => c.charCodeAt(0))).buffer;
        console.log("Public Key Buffer:", publicKeyBuffer);

        const publicKey = await crypto.importKey("spki", publicKeyBuffer, { name: "RSA-OAEP", hash: { name: "SHA-256" } }, true, ["encrypt"]);

        return publicKey;  // Возвращаем CryptoKey, а не JWK
    }

     async function encryptVote(vote) {
        const pemPublicKey = AuthStore.publicKey;
        const jwkPublicKey = await convertPemToJwk(pemPublicKey);

        const textEncoder = new TextEncoder();
        const voteBuffer = textEncoder.encode(vote);

        const encryptedVote = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP",
            },
            jwkPublicKey,
            voteBuffer
        );

        const encryptedVoteArray = new Uint8Array(encryptedVote);
        const encryptedVoteBase64 = btoa(String.fromCharCode(...encryptedVoteArray));

        return encryptedVoteBase64;
    }

    const handleVote = async (party) => {
        try {
            const { token, validator, pooling_station } = AuthStore; // Получение token, validator, pooling_station из AuthStore
            console.log("token", token, "validator", validator, "pooling_station", pooling_station);
            // Отправка данных на сервер
            const encryptedVote = await encryptVote(party); // Добавлено await
            const response = await axios.post('http://localhost:3003/vote', {
                encryptedVote,
                token,
                validator,
                pooling_station
            });

            // Обработка ответа от сервера
            if (response.data.status === 'success') {
                openSnackbar('Your vote has been successfully recorded.', 'success');
                setHasVoted(true);
            } else {
                openSnackbar(response.data.message || 'Something went wrong. Please try again.', 'error');
                setHasVoted(true);
            }
        } catch (error) {
            console.error('Error while voting:', error);
            openSnackbar(error.response?.data?.message || 'An error occurred. Please try again.', 'error');
            setHasVoted(true);
        }
    };

    return (
        <Container component="main" maxWidth="xs">
            <Typography variant="h5" align="center">Vote for a Party</Typography>
            <Button
                variant="contained"
                color="primary"
                fullWidth
                style={{ margin: '10px 0' }}
                onClick={() => handleVote('Democrats')}
            >
                Vote for Democrats
            </Button>
            <Button
                variant="contained"
                color="secondary"
                fullWidth
                style={{ margin: '10px 0' }}
                onClick={() => handleVote('Republicans')}
            >
                Vote for Republicans
            </Button>
            {hasVoted && ( // Отображение кнопки только если пользователь проголосовал
                <Button
                    variant="contained"
                    className={classes.customButton}
                    fullWidth
                    style={{ margin: '10px 0' }}
                    component={Link}
                    to="/results"
                >
                    View Voting Results
                </Button>
            )}
            <Snackbar open={open} autoHideDuration={6000} onClose={() => setOpen(false)}>
                <Alert onClose={() => setOpen(false)} severity={severity}>
                    {message}
                </Alert>
            </Snackbar>
        </Container>
    );
};

export default Vote;
