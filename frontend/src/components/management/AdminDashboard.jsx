import React, { useEffect, useState } from 'react';
import { Container, Typography, Button } from '@mui/material';
import axios from 'axios';

const AdminDashboard = () => {
    const [role, setRole] = useState(null);
    const [polling_station, setPollingStation] = useState(null);
    const [theoreticalVotes, setTheoreticalVotes] = useState(0);
    const [actualVotes, setActualVotes] = useState(0);

    useEffect(() => {
        const fetchSessionData = async () => {
            try {
                const response = await axios.get('http://localhost:3001/api/admin/session', {
                    withCredentials: true
                });
                if (response.data.status === 'success') {
                    setRole(response.data.role);
                    setPollingStation(response.data.polling_station);
                    setTheoreticalVotes(response.data.theoreticalVotes);
                    setActualVotes(response.data.actualVotes);

                    if (response.data.actualVotes > response.data.theoreticalVotes) {
                        alert('Warning: The number of actual votes is greater than the expected number. The election may be compromised.');
                    }
                }
            } catch (error) {
                console.error('Failed to fetch session data:', error);
            }
        };

        fetchSessionData();
    }, []);

    const checkVotes = async () => {
        try {
            const response = await axios.get('http://localhost:3001/api/admin/check_votes', {
                withCredentials: true
            });
            if (response.data.status === 'success') {
                alert('All votes are in order.');
            }
        } catch (error) {
            alert('Warning: The election may be compromised.');
        }
    };

    const restartVoting = async () => {
        try {
            const response = await axios.post('http://localhost:3001/api/admin/restart_voting', {}, {
                withCredentials: true
            });
            if (response.data.status === 'success') {
                alert('Voting restarted successfully.');
            }
        } catch (error) {
            alert('Failed to restart voting.');
        }
    };

    return (
        <Container component="main" maxWidth="md">
            <Typography variant="h5">Admin Dashboard</Typography>
            {role === 'admin' ? (
                <>
                    <Typography variant="body1">Admin Content</Typography>
                    <Button variant="contained" color="secondary" onClick={restartVoting}>Restart Voting</Button>
                </>
            ) : (
                role && (
                    <>
                        <Typography variant="body1">Stakeholder Content</Typography>
                        <Typography variant="body1">Polling Station: {polling_station}</Typography>
                        <Typography variant="body1">Theoretical Votes: {theoreticalVotes}</Typography>
                        <Typography variant="body1">Actual Votes: {actualVotes}</Typography>
                        <Button variant="contained" color="primary" onClick={checkVotes}>Check Votes</Button>
                    </>
                )
            )}
        </Container>
    );
};

export default AdminDashboard;
