// src/App.js
import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import HomePage from './pages/HomePage';
import DashboardPage from './pages/DashboardPage';
import Register from './components/Register';
import Login from './components/Login';
import NavBar from './components/NavBar';
import { AuthProvider } from './context/AuthContext';
import CTIReportsPage from "./pages/CTIReportsPage";
import DashboardPage2 from './pages/DashboardPage2';


function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <NavBar />
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/cti-reports" element={<CTIReportsPage />} />
            <Route path="/dashboard2" element={<DashboardPage2 />} /> 
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
