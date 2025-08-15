import React from 'react';
import './Header.css';  // Assuming CSS is in a separate file

const Header = () => {
  return (
    <header className="header">
      <div className="brand-box">
        <span className="brand">SuperUs</span>
      </div>

      <div className="text-box">
        <h1 className="heading-primary">
          <span className="heading-primary-main">We give Data Stories.</span>
          <span className="heading-primary-sub">We make the Data View according to your choice</span>
        </h1>
        
      </div>
    </header>
  );
};

export default Header;
