import React, { useState } from 'react';
import axios from 'axios';
import srp from 'secure-remote-password/client';
import { Container, TextField, Button, Typography, Snackbar } from '@mui/material';
import { Alert } from '@mui/material';
import { useNavigate } from 'react-router-dom';

function Signup() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const navigate = useNavigate();

    const handleSignup = async () => {
        const salt = srp.generateSalt();
        const privateKey = srp.derivePrivateKey(salt, username, password);
        const verifier = srp.deriveVerifier(privateKey);

        try {
            const { data } = await axios.post('http://localhost:3001/signup',
                {
                    username,
                    salt,
                    verifier
                },
                {
                    withCredentials: true
                }
            );
            console.log(data.status);
            navigate('/');
        } catch (error) {
            console.error(error);
            if (error.response && error.response.data) {
                setError(error.response.data.message);
            } else {
                setError("Signup failed");
            }
        }
    };


    return (
        <Container component="main" maxWidth="xs">
            <Typography variant="h5" align="center">Sign Up</Typography>
            <TextField
                variant="outlined"
                margin="normal"
                fullWidth
                label="Username"
                onChange={(e) => setUsername(e.target.value)}
            />
            <TextField
                variant="outlined"
                margin="normal"
                fullWidth
                label="Password"
                type="password"
                onChange={(e) => setPassword(e.target.value)}
            />
            <Button
                type="submit"
                fullWidth
                variant="contained"
                color="primary"
                onClick={handleSignup}
            >
                Sign Up
            </Button>
            <Typography variant="body2" align="center">
                Already have an account? <a href="/login">Log in</a>
            </Typography>
            <Snackbar open={error !== null} autoHideDuration={6000} onClose={() => setError(null)}>
                <Alert onClose={() => setError(null)} severity="error">
                    {error}
                </Alert>
            </Snackbar>
        </Container>
    );
}

export default Signup;
