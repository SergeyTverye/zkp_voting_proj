import React, { useState } from 'react';
import axios from 'axios';
import srp from 'secure-remote-password/client';
import { Container, TextField, Button, Typography, Snackbar } from '@mui/material';
import { Alert } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { observer } from 'mobx-react';
import AuthStore from '../stores/AuthStore'; // Импорт AuthStore
import { useNavigate } from 'react-router-dom';

function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const navigate = useNavigate();

    const handleLogin = async () => {
        const clientEphemeral = srp.generateEphemeral();

        try {
            let { data } = await axios.post('http://localhost:3001/login',
                {
                    username,
                    clientPublicEphemeral: clientEphemeral.public,
                },
                {
                    withCredentials: true
                }
            );
            // Step 1
            const { salt, serverPublicEphemeral } = data;
            const privateKey = srp.derivePrivateKey(salt, username, password);
            const clientSession = srp.deriveSession(
                clientEphemeral.secret,
                serverPublicEphemeral,
                salt,
                username,
                privateKey
            );
            // Step 2
            let { data: validateData } = await axios.post('http://localhost:3001/login/validate',
                {
                    username,
                    clientSessionProof: clientSession.proof,
                    clientPublicEphemeral: clientEphemeral.public
                },
                {
                    withCredentials: true
                }
            );
            try {
                srp.verifySession(clientEphemeral.public, clientSession, validateData.serverSessionProof);
                alert('Login successful');
                // Saving token and validator to MobX store
                AuthStore.setToken(validateData.token);
                AuthStore.setValidator(validateData.validator);
                AuthStore.setPollingStation(validateData.polling_station);
                AuthStore.setPublicKey(validateData.publicKey);
                if (validateData.token === null) navigate('/results'); // if the user has already voted, redirect to /results
                else navigate('/vote'); // Otherwise redirects to /vote

            } catch (error) {
                console.error('Failed to verify session', error);
                setError("Login failed");
            }
        } catch (error) {
            console.error(error);
            if (error.response && error.response.data && error.response.data.message) {
                setError(error.response.data.message);
            } else {
                setError("Internal Server Error");
            }
        }
    };

    return (
        <Container component="main" maxWidth="xs">
            <Typography variant="h5" align="center">Login</Typography>
            <TextField
                variant="outlined"
                margin="normal"
                fullWidth
                label="National ID"
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
                onClick={handleLogin}
            >
                Login
            </Button>
            <Typography variant="body2" align="center">
                Don't have an account? <RouterLink to="/signup">Sign Up</RouterLink>
            </Typography>
            <Snackbar open={error !== null} autoHideDuration={6000} onClose={() => setError(null)}>
                <Alert onClose={() => setError(null)} severity="error">
                    {error}
                </Alert>
            </Snackbar>
        </Container>
    );
}

export default observer(Login);
