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

// Setting up a new cryptographic engine for the application.
// window.crypto: The native Web Crypto API object, which provides cryptographic operations.
setEngine("newEngine", window.crypto, new CryptoEngine({ name: "", crypto: window.crypto, subtle: window.crypto.subtle }));

const Vote = () => {
    const [open, setOpen] = React.useState(false);
    const [message, setMessage] = React.useState('');
    const [severity, setSeverity] = React.useState('success');
    const [hasVoted, setHasVoted] = React.useState(false);
    const classes = useStyles();

    const openSnackbar = (message, severity) => {
        setMessage(message);
        setSeverity(severity);
        setOpen(true);
    };

    async function convertPemToJwk(pem) {
        const crypto = window.crypto.subtle;
        if (!crypto) {
            throw new Error("No crypto");
        }
        // Removes the PEM header, footer, and any whitespace or newlines.
        const clearPem = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n|\s+/g, "");
        // Decodes the base64 PEM string to a binary array and then converts it to an ArrayBuffer.
        const publicKeyBuffer = new Uint8Array(atob(clearPem).split("").map(c => c.charCodeAt(0))).buffer;
        // Imports the public key into a format that can be used by the Web Crypto API.
        const publicKey = await crypto.importKey("spki", publicKeyBuffer, { name: "RSA-OAEP", hash: { name: "SHA-256" } }, true, ["encrypt"]);
        // Returns the imported public key as a CryptoKey object.
        return publicKey;
    }

     async function encryptVote(vote) {
        // Retrieves the PEM-formatted public key from AuthStore
        const pemPublicKey = AuthStore.publicKey;
        // Converts the PEM public key to a CryptoKey object
        const jwkPublicKey = await convertPemToJwk(pemPublicKey);
        // Creates a new TextEncoder instance for converting text to a byte array.
        const textEncoder = new TextEncoder();
        // Encodes the vote string into a byte array.
        const voteBuffer = textEncoder.encode(vote);
        // Encrypts the vote using RSA-OAEP algorithm.
        const encryptedVote = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP",
            },
            jwkPublicKey,
            voteBuffer
        );
        // Converts the encrypted vote into a Uint8Array.
        const encryptedVoteArray = new Uint8Array(encryptedVote);
        // Converts the Uint8Array to a base64 string.
        const encryptedVoteBase64 = btoa(String.fromCharCode(...encryptedVoteArray));
        // Returns the encrypted vote as a base64 string.
        return encryptedVoteBase64;
    }

    const handleVote = async (party) => {
        try {
            const { token, validator, pooling_station } = AuthStore;
            const encryptedVote = await encryptVote(party);
            const response = await axios.post('http://localhost:3003/vote', {
                encryptedVote,
                token,
                validator,
                pooling_station
            });

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
            {hasVoted && ( // Display the button only if the user has voted
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
