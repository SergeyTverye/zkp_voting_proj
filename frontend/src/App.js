import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Signup from './components/Signup';
import Login from './components/Login';
import Vote from './components/Vote';
import { Provider } from 'mobx-react';
import AuthStore from './stores/AuthStore';
import Results from "./components/Results";
import './App.css';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import AdminLogin from "./components/management/AdminLogin";
import AdminSignup from "./components/management/AdminSignup";
import AdminDashboard from "./components/management/AdminDashboard";

const theme = createTheme({
    palette: {
        mode: 'light', // или 'dark'
    },
});

function App() {
    return (
        <ThemeProvider theme={theme}>
                <Provider AuthStore={AuthStore}>
                    <Router>
                        <Routes>
                            <Route path="/" element={<Login />} />
                            <Route path="/signup" element={<Signup />} />
                            <Route path="/vote" element={<Vote />} />
                            <Route path="/results" element={<Results />} />
                            <Route path="admin/" element={<AdminLogin />} />
                            <Route path="admin/signup" element={<AdminSignup />} /> {/*для тестов*/}
                            <Route path="admin/dashboard" element={<AdminDashboard />} />
                            <Route path="*" element={<h1>404 Not Found</h1>} />
                        </Routes>
                    </Router>
                </Provider>
        </ThemeProvider>
    );
}

export default App;
