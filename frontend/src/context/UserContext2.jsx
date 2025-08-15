import React, { createContext, useState, useContext, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';
import { useNavigate } from 'react-router-dom';

const UserContext = createContext();

export const UserProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Load user from localStorage on app start
  useEffect(() => {
    const storedUser = localStorage.getItem('dashboardAgent_user');
    const storedToken = localStorage.getItem('dashboardAgent_token');
    
    if (storedUser && storedToken) {
      try {
        const userData = JSON.parse(storedUser);
        
        // For JWT tokens (both Google and email/password), check expiration
        try {
          const tokenData = jwtDecode(storedToken);
          
          // Check if token is still valid
          if (tokenData.exp * 1000 > Date.now()) {
            setUser(userData);
            setIsAuthenticated(true);
          } else {
            // Token expired, clear storage
            localStorage.removeItem('dashboardAgent_user');
            localStorage.removeItem('dashboardAgent_token');
          }
        } catch (tokenError) {
          // If token can't be decoded, treat as invalid
          console.error('Invalid token format:', tokenError);
          localStorage.removeItem('dashboardAgent_user');
          localStorage.removeItem('dashboardAgent_token');
        }
      } catch (error) {
        console.error('Error loading user from storage:', error);
        localStorage.removeItem('dashboardAgent_user');
        localStorage.removeItem('dashboardAgent_token');
      }
    }
    setIsLoading(false);
  }, []);

  // Universal login function for both Google OAuth and email/password
  const login = (credentialResponse) => {
    try {
      let userData;
      
      if (credentialResponse.user_data) {
        // Email/password authentication (from backend)
        userData = credentialResponse.user_data;
        localStorage.setItem('dashboardAgent_token', credentialResponse.credential);
      } else {
        // Google OAuth authentication
        const decoded = jwtDecode(credentialResponse.credential);
        userData = {
          id: decoded.sub,
          name: decoded.name,
          firstName: decoded.given_name,
          lastName: decoded.family_name,
          email: decoded.email,
          picture: decoded.picture,
          auth_method: 'google',
          loginTime: new Date().toISOString()
        };
        localStorage.setItem('dashboardAgent_token', credentialResponse.credential);
      }

      // Store user data in localStorage for persistence
      localStorage.setItem('dashboardAgent_user', JSON.stringify(userData));
      
      setUser(userData);
      setIsAuthenticated(true);
      
      console.log('User logged in:', userData);
      return userData;
    } catch (error) {
      console.error('Error during login:', error);
      throw error;
    }
  };

  // Logout function with navigation
  const logout = (navigate) => {
    localStorage.removeItem('dashboardAgent_user');
    localStorage.removeItem('dashboardAgent_token');
    setUser(null);
    setIsAuthenticated(false);
    console.log('User logged out');
    
    // Navigate to landing page if navigate function is provided
    if (navigate) {
      navigate('/');
    } else {
      // Fallback: redirect using window.location
      window.location.href = '/';
    }
  };

  // Update user data
  const updateUser = (userData) => {
    const updatedUser = { ...user, ...userData };
    localStorage.setItem('dashboardAgent_user', JSON.stringify(updatedUser));
    setUser(updatedUser);
  };

  const value = {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
    updateUser,
    setUser
  };

  return (
    <UserContext.Provider value={value}>
      {children}
    </UserContext.Provider>
  );
};

export const useUser = () => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};

