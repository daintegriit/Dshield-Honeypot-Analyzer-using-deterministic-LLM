import React, { useContext } from 'react';
import { Navigate, Outlet } from 'react-router-dom'; // Use Navigate for redirection
import { AuthContext } from '../context/AuthContext';

const ProtectedRoute = () => {
  const { isAuthenticated } = useContext(AuthContext);

  // If user is not authenticated, redirect to login page
  return isAuthenticated ? <Outlet /> : <Navigate to="/login" />;
};

export default ProtectedRoute;
