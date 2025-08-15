import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import ChatPage from './page/Chatpage';
import LandingPages from './page/LandingPage';
import RecommendationsPage from './page/Recommendation';
import { UserProvider } from './context/UserContext';

const App = () => {
  return (
    <UserProvider>
      <Router>
        <Routes>
          <Route path="/" element={<LandingPages />} />
          <Route path="/recommendations" element={<RecommendationsPage />} />
          <Route path="/chat" element={<ChatPage />} />
        </Routes>
      </Router>
    </UserProvider>
  );
};

export default App;
