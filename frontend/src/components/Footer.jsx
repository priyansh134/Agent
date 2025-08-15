import React from 'react';
import './Footer.css';  // Assuming CSS is in a separate file

const Footer = () => {
  return (
    <footer className="footer"> {/* Changed from header to footer */}
      <div className="brand-box">
        <span className="brand">SuperUs</span> {/* Brand name remains the same */}
      </div>

      <div className="text-box">
        <h1 className="heading-primary">
          <span className="heading-primary-main">Stay Connected with Us</span> {/* Changed the main heading */}
          <span className="heading-primary-sub">Follow us for the latest updates and news.</span> {/* Changed the subheading */}
        </h1>
      </div>
    </footer>
  );
};

export default Footer;
