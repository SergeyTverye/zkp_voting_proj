import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Container, Typography, Alert } from '@mui/material';
import 'chart.js/auto';
import { Pie, Bar } from 'react-chartjs-2';

const Results = () => {
    const [results, setResults] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null); //состояние для ошибки

    useEffect(() => {
        axios.get('http://localhost:3001/results')
            .then(response => {
                setResults(response.data);
            })
            .catch(error => {
                console.error('Error fetching results:', error);
                setError(error.response?.data?.message || 'An error occurred'); // Установка сообщения об ошибке
            })
            .finally(() => {
                setLoading(false);
            });
    }, []);

    const totalVotes = results?.forDemocrats + results?.forRepublicans;
    const corruptedVotes = results?.corruptedVotes;

    const pieData = {
        labels: ['Democrats', 'Republicans'],
        datasets: [
            {
                data: [results?.forDemocrats, results?.forRepublicans],
                backgroundColor: ['Blue', 'Red']
            }
        ]
    };

    const barData = {
        labels: Object.keys(results?.pollingStations || {}),
        datasets: [
            {
                label: 'Democrats',
                data: Object.values(results?.pollingStations || {}).map(station => station.forDemocrats),
                backgroundColor: 'Blue'
            },
            {
                label: 'Republicans',
                data: Object.values(results?.pollingStations || {}).map(station => station.forRepublicans),
                backgroundColor: 'Red'
            }
        ]
    };

    return (
        <Container component="main" maxWidth="md">
            <Typography variant="h5" align="center">Voting Results</Typography>
            {loading ? (
                <Typography variant="body1" align="center">Loading...</Typography>
            ) : error ? ( // Проверка на наличие ошибки
                <Alert severity="error">{error}</Alert> // Отображение ошибки
            ) : (
                <>
                    <Typography variant="h6" align="center">Total Votes: {totalVotes}</Typography>
                    <Typography variant="h6" align="center">Corrupted Votes: {corruptedVotes}</Typography>
                    <Typography variant="h6" align="center">Overall Distribution</Typography>
                    <div className={'dia'} style={{ width: '600px', height: '400px' }}><Pie data={pieData}/></div>
                    <Typography variant="h6" align="center">Distribution by Polling Station</Typography>
                    <div className={'dia'} style={{ width: '600px', height: '400px' }}><Bar data={barData}/></div>
                </>
            )}
        </Container>
    );
};

export default Results;
