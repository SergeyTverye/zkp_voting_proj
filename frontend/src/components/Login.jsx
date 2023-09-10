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
    const navigate = useNavigate(); // Инициализация navigate

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
            const { salt, serverPublicEphemeral } = data;
            console.log("Step 1:", salt, serverPublicEphemeral);

            const privateKey = srp.derivePrivateKey(salt, username, password);
            const clientSession = srp.deriveSession(
                clientEphemeral.secret,
                serverPublicEphemeral,
                salt,
                username,
                privateKey
            );

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
                // Сохранение токена и валидатора в MobX store
                AuthStore.setToken(validateData.token);
                AuthStore.setValidator(validateData.validator);
                console.log("save polling_station", validateData.polling_station);
                AuthStore.setPollingStation(validateData.polling_station);
                console.log("save publicKey", validateData.publicKey)
                AuthStore.setPublicKey(validateData.publicKey);

                if (validateData.token === null) navigate('/results'); // если пользователь уже голосовал, то перенаправление на /results
                else navigate('/vote'); // Перенаправление на /vote

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
