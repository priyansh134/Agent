import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import ChatPage from './page/Chatpage';
import LandingPages from './page/LandingPage';
import RecommendationsPage from './page/Recommendation';

const App = () => {
  return (

    <Router>
      <Routes>
       <Route path="" element={<LandingPages />} />
        <Route path="recommendations" element={<RecommendationsPage />} />
        <Route path="chat" element={<ChatPage />} />
      </Routes>
    </Router>
  );
};

export default App;
