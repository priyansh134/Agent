import React, { createContext, useState, useContext, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';

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
      } catch (error) {
        console.error('Error loading user from storage:', error);
        localStorage.removeItem('dashboardAgent_user');
        localStorage.removeItem('dashboardAgent_token');
      }
    }
    setIsLoading(false);
  }, []);

  // Login function for Google authentication
  const login = (credentialResponse) => {
    try {
      const decoded = jwtDecode(credentialResponse.credential);
      
      const userData = {
        id: decoded.sub,
        name: decoded.name,
        firstName: decoded.given_name,
        lastName: decoded.family_name,
        email: decoded.email,
        picture: decoded.picture,
        loginTime: new Date().toISOString()
      };

      // Store in localStorage for persistence
      localStorage.setItem('dashboardAgent_user', JSON.stringify(userData));
      localStorage.setItem('dashboardAgent_token', credentialResponse.credential);
      
      setUser(userData);
      setIsAuthenticated(true);
      
      console.log('User logged in:', userData);
      return userData;
    } catch (error) {
      console.error('Error decoding Google token:', error);
      throw error;
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem('dashboardAgent_user');
    localStorage.removeItem('dashboardAgent_token');
    setUser(null);
    setIsAuthenticated(false);
    console.log('User logged out');
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

