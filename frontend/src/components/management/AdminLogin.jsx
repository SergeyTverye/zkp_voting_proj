import React, { useState } from 'react';
import { Button, Container, TextField, Typography } from '@mui/material';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const AdminLogin = () => {
    const [formData, setFormData] = useState({
        username: '',
        password: ''
    });

    const navigate = useNavigate();

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prevState => ({ ...prevState, [name]: value }));
    };

    const handleSubmit = async () => {
        try {
            const response = await axios.post('http://localhost:3001/api/admin/login', formData, {
                withCredentials: true
            });
            if (response.data.status === 'success') {
                alert('Successfully logged in');
                navigate('/admin/dashboard');
            }
        } catch (error) {
            alert('Login failed');
        }
    };

    return (
        <Container component="main" maxWidth="xs">
            <Typography variant="h5">Admin Login</Typography>
            <TextField fullWidth label="Username" name="username" onChange={handleChange} />
            <TextField fullWidth label="Password" type="password" name="password" onChange={handleChange} />
            <Button variant="contained" color="primary" onClick={handleSubmit}>Login</Button>
        </Container>
    );
};

export default AdminLogin;
