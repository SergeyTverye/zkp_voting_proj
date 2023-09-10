import React, { useState } from 'react';
import { Button, Container, TextField, Typography, Select, MenuItem } from '@mui/material';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const AdminSignup = () => {
    const [formData, setFormData] = useState({
        username: '',
        password: '',
        role: 'admin',
        polling_station: 0
    });

    const navigate = useNavigate();

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prevState => ({ ...prevState, [name]: value }));
    };

    const handleSubmit = async () => {
        try {
            const response = await axios.post('http://localhost:3001/api/admin/signup', formData);
            if (response.data.status === 'success') {
                alert('Successfully registered');
                navigate('/admin');
            }
        } catch (error) {
            alert('Registration failed');
        }
    };

    return (
        <Container component="main" maxWidth="xs">
            <Typography variant="h5">Admin Signup</Typography>
            <TextField fullWidth label="Username" name="username" onChange={handleChange} />
            <TextField fullWidth label="Password" type="password" name="password" onChange={handleChange} />
            <Select fullWidth name="role" value={formData.role} onChange={handleChange}>
                <MenuItem value="admin">Admin</MenuItem>
                <MenuItem value="stakeholder">Stakeholder</MenuItem>
            </Select>
            {formData.role === 'stakeholder' && (
                <TextField fullWidth label="Polling Station" type="number" name="polling_station" onChange={handleChange} />
            )}
            <Button variant="contained" color="primary" onClick={handleSubmit}>Signup</Button>
        </Container>
    );
};

export default AdminSignup;
