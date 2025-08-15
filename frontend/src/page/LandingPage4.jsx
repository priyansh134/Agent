import React, { useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { GoogleLogin } from '@react-oauth/google';
import { useNavigate } from 'react-router-dom';
import { BarChart3, TrendingUp, Database, Zap, Shield, Users, ArrowRight, CheckCircle, Star, Activity, Eye, EyeOff, Mail, Lock, User } from 'lucide-react';
import { useUser } from '../context/UserContext';
import axios from 'axios';

const textArray = [
  "Enterprise Data Intelligence", 
  "Advanced Analytics Platform", 
  "Unlock Business Insights"
];

const features = [
  {
    icon: Activity,
    title: "Real-Time Analytics",
    description: "Monitor and analyze your business data with real-time dashboards and alerts"
  },
  {
    icon: Database,
    title: "Data Integration",
    description: "Seamlessly connect multiple data sources and databases with our unified platform"
  },
  {
    icon: TrendingUp,
    title: "Predictive Insights",
    description: "Leverage machine learning algorithms to forecast trends and business outcomes"
  },
  {
    icon: Zap,
    title: "High Performance",
    description: "Process millions of data points with sub-second response times"
  },
  {
    icon: Shield,
    title: "Enterprise Security",
    description: "SOC 2 compliant with end-to-end encryption and advanced access controls"
  },
  {
    icon: Users,
    title: "Team Collaboration",
    description: "Share insights across teams with role-based permissions and governance"
  }
];

const stats = [
  { value: "50M+", label: "Records Processed Daily" },
  { value: "2,500+", label: "Enterprise Customers" },
  { value: "99.99%", label: "Platform Uptime" },
  { value: "24/7", label: "Premium Support" }
];

const LandingPages = () => {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [showGoogleLogin, setShowGoogleLogin] = useState(false);
  const [authMode, setAuthMode] = useState('login'); // 'login' or 'signup'
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  });
  const [errors, setErrors] = useState({});
  
  const navigate = useNavigate();
  const { login: userLogin, isAuthenticated } = useUser();
  const url = "http://127.0.0.1:8080";

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/chat');
    }
  }, [isAuthenticated, navigate]);

  const handleGoogleSuccess = async (credentialResponse) => {
    try {
      setIsLoading(true);
      
      // Decode the JWT token to get user data
      const decoded = JSON.parse(atob(credentialResponse.credential.split('.')[1]));
      
      const userData = {
        id: decoded.sub,
        name: decoded.name,
        given_name: decoded.given_name,
        family_name: decoded.family_name,
        email: decoded.email,
        picture: decoded.picture
      };

      // Send to backend for processing
      const response = await axios.post(`${url}/auth/google`, {
        google_token: credentialResponse.credential,
        user_data: userData
      });

      if (response.data.user && response.data.token) {
        // Use the login function from UserContext
        userLogin({
          credential: response.data.token,
          user_data: response.data.user
        });
        
        navigate('/recommendations');
      }
    } catch (error) {
      console.error('Google login error:', error);
      setErrors({ general: 'Google login failed. Please try again.' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleFailure = () => {
    console.log('Google Login Failed');
    setErrors({ general: 'Google login failed. Please try again.' });
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear specific error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (authMode === 'signup' && !formData.name.trim()) {
      newErrors.name = 'Name is required';
    }
    
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email';
    }
    
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (authMode === 'signup' && formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setIsLoading(true);
    setErrors({});
    
    try {
      const endpoint = authMode === 'signup' ? '/register' : '/login';
      const response = await axios.post(`${url}${endpoint}`, formData);
      
      if (response.data.user && response.data.token) {
        // Create credential response format similar to Google
        const credentialResponse = {
          credential: response.data.token,
          user_data: response.data.user
        };
        
        userLogin(credentialResponse);
        navigate('/recommendations');
      }
    } catch (error) {
      const errorMessage = error.response?.data?.error || 
        (authMode === 'signup' ? 'Registration failed. Please try again.' : 'Login failed. Please check your credentials.');
      setErrors({ general: errorMessage });
    } finally {
      setIsLoading(false);
    }
  };

  const switchAuthMode = () => {
    setAuthMode(authMode === 'login' ? 'signup' : 'login');
    setFormData({ name: '', email: '', password: '' });
    setErrors({});
  };

  // Smooth scroll function for navigation
  const scrollToSection = (sectionId) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ 
        behavior: 'smooth',
        block: 'start'
      });
    }
  };

  useEffect(() => {
    if (currentIndex < textArray.length - 1) {
      const timer = setTimeout(() => {
        setCurrentIndex(currentIndex + 1);
      }, 3500); // Wait for 3.5 seconds before showing the next text
      return () => clearTimeout(timer);
    } else {
      // Show the login forms after the last text is displayed
      const timer = setTimeout(() => {
        setShowGoogleLogin(true);
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [currentIndex]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-slate-900" style={{ fontFamily: '"Inter", "SF Pro Display", system-ui, -apple-system, sans-serif' }}>
      {/* Custom Professional Fonts */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
        
        .font-inter {
          font-family: 'Inter', 'SF Pro Display', system-ui, -apple-system, sans-serif;
        }
        
        .font-display {
          font-family: 'Inter', 'SF Pro Display', system-ui, -apple-system, sans-serif;
          font-weight: 700;
          letter-spacing: -0.02em;
        }
        
        .font-body {
          font-family: 'Inter', system-ui, sans-serif;
          font-weight: 400;
          line-height: 1.6;
        }

        .text-gradient-corporate {
          background: linear-gradient(135deg, #1e40af 0%, #3b82f6 25%, #06b6d4  75%, #0891b2 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .bg-corporate-gradient {
          background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 25%, #3b82f6 75%, #0891b2 100%);
        }

        .shadow-corporate {
          box-shadow: 0 25px 50px -12px rgba(30, 64, 175, 0.25);
        }
      `}</style>
      
      {/* Navigation */}
      <nav className="relative z-50 bg-white/5 backdrop-blur-xl border-b border-white/10">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="flex justify-between items-center py-5">
            <div className="flex items-center space-x-3">
              <div className="w-11 h-11 bg-corporate-gradient rounded-xl flex items-center justify-center shadow-corporate">
                <BarChart3 className="w-6 h-6 text-white" />
              </div>
              <span className="text-2xl font-display text-white tracking-tight">Dashboard Agent</span>
            </div>
            <div className="hidden md:flex items-center space-x-8">
              <button 
                onClick={() => scrollToSection('features')} 
                className="text-gray-300 hover:text-white transition-all duration-300 font-medium text-sm tracking-wide cursor-pointer"
              >
                Platform
              </button>
              <button 
                onClick={() => scrollToSection('showcase')} 
                className="text-gray-300 hover:text-white transition-all duration-300 font-medium text-sm tracking-wide cursor-pointer"
              >
                Solutions
              </button>
              <button 
                onClick={() => scrollToSection('stats')} 
                className="text-gray-300 hover:text-white transition-all duration-300 font-medium text-sm tracking-wide cursor-pointer"
              >
                Pricing
              </button>
              <button 
                onClick={() => scrollToSection('contact')} 
                className="text-gray-300 hover:text-white transition-all duration-300 font-medium text-sm tracking-wide cursor-pointer"
              >
                Contact
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        {/* Professional Background Elements */}
        <div className="absolute inset-0">
          <div className="absolute top-1/3 left-1/3 w-96 h-96 bg-blue-600/8 rounded-full blur-3xl"></div>
          <div className="absolute bottom-1/3 right-1/3 w-96 h-96 bg-cyan-500/8 rounded-full blur-3xl"></div>
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-blue-600/5 to-cyan-500/5 rounded-full blur-3xl"></div>
        </div>

        <div className="relative max-w-7xl mx-auto px-6 lg:px-8 py-24">
          <div className="text-center">
            {/* Professional Logo */}
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.8, delay: 0.2 }}
              className="flex justify-center mb-12"
            >
              <div className="relative">
                <div className="w-28 h-28 bg-corporate-gradient rounded-3xl shadow-corporate flex items-center justify-center border border-white/10">
                  <BarChart3 className="w-14 h-14 text-white" />
                </div>
                <div className="absolute -inset-2 bg-corporate-gradient rounded-3xl blur-xl opacity-20"></div>
              </div>
            </motion.div>

            {/* Professional Animated Headlines - Reduced Sizes */}
            <div className="h-32 mb-12 flex items-center justify-center">
              <AnimatePresence mode="wait">
                <motion.h1
                  key={currentIndex}
                  initial={{ y: 40, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  exit={{ y: -40, opacity: 0 }}
                  transition={{ duration: 0.8, ease: "easeOut" }}
                  className="text-4xl md:text-5xl font-display text-gradient-corporate leading-tight tracking-tight"
                >
                  {textArray[currentIndex]}
                </motion.h1>
              </AnimatePresence>
            </div>

            {/* Professional Subtitle - Reduced Size */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.8 }}
              className="max-w-4xl mx-auto mb-16"
            >
              <p className="text-lg md:text-xl text-gray-300 font-body leading-relaxed tracking-wide">
                Transform complex business data into strategic insights with our enterprise-grade analytics platform. 
                <span className="text-cyan-400 font-medium"> Powered by advanced AI and machine learning.</span>
              </p>
            </motion.div>

            {/* Authentication Section */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 1.2 }}
              className="flex flex-col items-center space-y-8"
            >
              <AnimatePresence>
                {showGoogleLogin && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.6 }}
                    className="flex flex-col items-center space-y-6"
                  >
                    <div className="bg-white/8 backdrop-blur-xl rounded-3xl p-8 border border-white/10 shadow-corporate max-w-md w-full">
                      <h3 className="text-2xl font-display text-white mb-2 tracking-tight text-center">
                        {authMode === 'signup' ? 'Create Your Account' : 'Welcome Back'}
                      </h3>
                      <p className="text-gray-300 font-body mb-6 text-center text-base">
                        {authMode === 'signup' 
                          ? 'Join thousands of professionals transforming their data'
                          : 'Sign in to continue to Dashboard Agent'
                        }
                      </p>

                      {/* Error Message */}
                      {errors.general && (
                        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                          <p className="text-red-400 text-sm">{errors.general}</p>
                        </div>
                      )}

                      {/* Traditional Login/Signup Form */}
                      <form onSubmit={handleFormSubmit} className="space-y-4 mb-6">
                        {authMode === 'signup' && (
                          <div>
                            <div className="relative">
                              <User className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                              <input
                                type="text"
                                name="name"
                                placeholder="Full Name"
                                value={formData.name}
                                onChange={handleInputChange}
                                className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                              />
                            </div>
                            {errors.name && <p className="text-red-400 text-xs mt-1">{errors.name}</p>}
                          </div>
                        )}

                        <div>
                          <div className="relative">
                            <Mail className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                            <input
                              type="email"
                              name="email"
                              placeholder="Email Address"
                              value={formData.email}
                              onChange={handleInputChange}
                              className="w-full pl-10 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                          </div>
                          {errors.email && <p className="text-red-400 text-xs mt-1">{errors.email}</p>}
                        </div>

                        <div>
                          <div className="relative">
                            <Lock className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                            <input
                              type={showPassword ? "text" : "password"}
                              name="password"
                              placeholder="Password"
                              value={formData.password}
                              onChange={handleInputChange}
                              className="w-full pl-10 pr-12 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                            <button
                              type="button"
                              onClick={() => setShowPassword(!showPassword)}
                              className="absolute right-3 top-3 text-gray-400 hover:text-white"
                            >
                              {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                            </button>
                          </div>
                          {errors.password && <p className="text-red-400 text-xs mt-1">{errors.password}</p>}
                        </div>

                        <button
                          type="submit"
                          disabled={isLoading}
                          className="w-full py-3 bg-corporate-gradient text-white rounded-lg font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isLoading ? (
                            <div className="flex items-center justify-center">
                              <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent mr-2"></div>
                              {authMode === 'signup' ? 'Creating Account...' : 'Signing In...'}
                            </div>
                          ) : (
                            authMode === 'signup' ? 'Create Account' : 'Sign In'
                          )}
                        </button>
                      </form>

                      {/* Divider */}
                      <div className="relative mb-6">
                        <div className="absolute inset-0 flex items-center">
                          <div className="w-full border-t border-white/20"></div>
                        </div>
                        <div className="relative flex justify-center text-sm">
                          <span className="px-4 bg-transparent text-gray-400">or continue with</span>
                        </div>
                      </div>

                      {/* Google Login */}
                      <div className="mb-6">
                        <GoogleLogin
                          onSuccess={handleGoogleSuccess}
                          onError={handleGoogleFailure}
                          size="large"
                          theme="filled_blue"
                          shape="rectangular"
                          width="100%"
                        />
                      </div>

                      {/* Switch Auth Mode */}
                      <div className="text-center">
                        <p className="text-gray-400 text-sm">
                          {authMode === 'signup' ? 'Already have an account?' : "Don't have an account?"}{' '}
                          <button
                            onClick={switchAuthMode}
                            className="text-cyan-400 hover:text-cyan-300 font-medium"
                          >
                            {authMode === 'signup' ? 'Sign In' : 'Sign Up'}
                          </button>
                        </p>
                      </div>

                      {/* Trust Indicators */}
                      <div className="flex items-center justify-center mt-6 text-gray-400 font-medium text-sm">
                        <CheckCircle className="w-4 h-4 mr-2 text-cyan-400" />
                        <span>14-day free trial • No commitment required</span>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {!showGoogleLogin && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-gray-400 text-lg font-body"
                >
                  Initializing enterprise platform...
                </motion.div>
              )}
            </motion.div>
          </div>
        </div>
      </section>

      {/* Professional Stats Section */}
      <section id="stats" className="relative py-20 bg-white/3 backdrop-blur-xl border-y border-white/10">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-12">
            {stats.map((stat, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, delay: 1.4 + index * 0.1 }}
                className="text-center"
              >
                <div className="text-3xl md:text-4xl font-display text-gradient-corporate mb-3 tracking-tight">
                  {stat.value}
                </div>
                <div className="text-gray-300 font-body text-base md:text-lg tracking-wide">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Professional Features Section - Reduced Heading Size */}
      <section id="features" className="py-24">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 1.6 }}
            className="text-center mb-20"
          >
            <h2 className="text-3xl md:text-4xl font-display text-white mb-8 tracking-tight">
              Enterprise-Grade Platform
            </h2>
            <p className="text-lg md:text-xl text-gray-300 max-w-4xl mx-auto font-body leading-relaxed">
              Built for scale, security, and performance that Fortune 500 companies trust
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-10">
            {features.map((feature, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 40 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, delay: 1.8 + index * 0.1 }}
                className="bg-white/5 backdrop-blur-xl rounded-2xl p-8 border border-white/10 hover:bg-white/8 transition-all duration-500 group shadow-lg hover:shadow-corporate"
              >
                <div className="w-14 h-14 bg-corporate-gradient rounded-2xl flex items-center justify-center mb-8 group-hover:scale-110 transition-transform duration-500 shadow-lg">
                  <feature.icon className="w-7 h-7 text-white" />
                </div>
                <h3 className="text-xl font-display text-white mb-5 tracking-tight">{feature.title}</h3>
                <p className="text-gray-300 font-body leading-relaxed text-base">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Product Showcase Section - Reduced Heading Size */}
      <section id="showcase" className="py-24 bg-white/3 backdrop-blur-xl border-y border-white/10">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 1.9 }}
            className="text-center mb-16"
          >
            <h2 className="text-3xl md:text-4xl font-display text-white mb-6 tracking-tight">
              See Dashboard Agent in Action
            </h2>
            <p className="text-base md:text-lg text-gray-300 max-w-3xl mx-auto font-body">
              Experience the power of natural language data querying and intelligent analytics
            </p>
          </motion.div>

          <div className="grid lg:grid-cols-2 gap-16 items-center">
            {/* Product Interface Image */}
            <motion.div
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8, delay: 2.0 }}
              className="relative"
            >
              <div className="relative bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20 shadow-corporate">
                {/* Mock Browser Header */}
                <div className="flex items-center space-x-2 mb-4 pb-3 border-b border-white/20">
                  <div className="w-3 h-3 bg-red-400 rounded-full"></div>
                  <div className="w-3 h-3 bg-yellow-400 rounded-full"></div>
                  <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                  <div className="ml-4 text-xs text-gray-400 font-body">Dashboard Agent - Enterprise Analytics</div>
                </div>
                
                {/* Dashboard Interface Mockup */}
                <div className="bg-gradient-to-br from-gray-50 to-gray-100 rounded-xl overflow-hidden shadow-xl">
                  {/* Header */}
                  <div className="bg-white border-b border-gray-200 px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-corporate-gradient rounded-lg flex items-center justify-center">
                          <BarChart3 className="w-4 h-4 text-white" />
                        </div>
                        <span className="font-display text-gray-800 text-lg tracking-tight">Dashboard Agent</span>
                        <span className="text-sm text-gray-500 font-body">Overview</span>
                      </div>
                      <div className="text-sm text-gray-600 font-body">John Doe</div>
                    </div>
                  </div>
                  
                  {/* Main Interface */}
                  <div className="flex">
                    {/* Content Area */}
                    <div className="flex-1 p-6">
                      <div className="text-center py-12">
                        <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
                          <BarChart3 className="w-8 h-8 text-white" />
                        </div>
                        <h3 className="text-xl font-bold text-gray-800 mb-2">Welcome to Data Analytics</h3>
                        <p className="text-gray-600 text-sm font-body mb-4">
                          Upload your data and start querying with natural language.<br/>
                          Your results will appear here.
                        </p>
                        <div className="bg-white/70 rounded-lg p-3 text-xs text-gray-500">
                          👈 Use the chat panel to get started
                        </div>
                      </div>
                    </div>
                    
                    {/* Chat Sidebar */}
                    <div className="w-72 bg-white border-l border-gray-200">
                      <div className="p-4 border-b border-gray-200">
                        <h4 className="font-bold text-gray-800 text-sm mb-1">Data Assistant</h4>
                        <p className="text-xs text-gray-600 font-body">Ask questions about your data in natural language</p>
                      </div>
                      
                      {/* File Upload */}
                      <div className="p-4 border-b border-gray-100">
                        <label className="block text-xs font-medium text-gray-700 mb-2">Data File</label>
                        <div className="border-2 border-dashed border-gray-300 rounded-lg p-3 text-center">
                          <div className="text-xs text-gray-600">Upload CSV/TXT file</div>
                        </div>
                      </div>
                      
                      {/* Sample Queries */}
                      <div className="p-4 border-b border-gray-100">
                        <label className="block text-xs font-medium text-gray-700 mb-2">Sample Queries</label>
                        <div className="border border-gray-300 rounded p-2 text-xs text-gray-500">
                          Choose a sample query...
                        </div>
                      </div>
                      
                      {/* Query Input */}
                      <div className="p-4">
                        <label className="block text-xs font-medium text-gray-700 mb-2">Your Query</label>
                        <div className="border border-gray-300 rounded-lg p-2 h-20 bg-gray-50">
                          <div className="text-xs text-gray-400">Ask me anything about your data...</div>
                        </div>
                        <button className="w-full mt-3 bg-corporate-gradient text-white rounded-lg py-2 text-xs font-medium">
                          Generate Query
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Floating Elements */}
              <div className="absolute -top-6 -right-6 w-24 h-24 bg-cyan-500/10 rounded-full blur-2xl"></div>
              <div className="absolute -bottom-6 -left-6 w-32 h-32 bg-blue-500/10 rounded-full blur-2xl"></div>
            </motion.div>

            {/* Product Description - Reduced Heading Sizes */}
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8, delay: 2.1 }}
              className="space-y-8"
            >
              <div>
                <h3 className="text-xl md:text-2xl font-display text-white mb-4 tracking-tight">
                  Transform Data into Insights with Natural Language
                </h3>
                <p className="text-gray-300 font-body text-base leading-relaxed mb-6">
                  Dashboard Agent revolutionizes how enterprises interact with their data. Our intelligent platform 
                  understands your questions in plain English and delivers powerful analytics instantly.
                </p>
              </div>

              <div className="space-y-6">
                <div className="flex items-start space-x-4">
                  <div className="w-8 h-8 bg-corporate-gradient rounded-lg flex items-center justify-center flex-shrink-0 mt-1">
                    <Database className="w-4 h-4 text-white" />
                  </div>
                  <div>
                    <h4 className="text-white font-display text-base mb-2">Smart Data Processing</h4>
                    <p className="text-gray-300 font-body text-sm leading-relaxed">
                      Upload CSV files and query them instantly using natural language. No SQL knowledge required.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-4">
                  <div className="w-8 h-8 bg-corporate-gradient rounded-lg flex items-center justify-center flex-shrink-0 mt-1">
                    <TrendingUp className="w-4 h-4 text-white" />
                  </div>
                  <div>
                    <h4 className="text-white font-display text-base mb-2">Interactive Visualizations</h4>
                    <p className="text-gray-300 font-body text-sm leading-relaxed">
                      Generate beautiful charts and graphs automatically. Customize X/Y axes and chart types with ease.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-4">
                  <div className="w-8 h-8 bg-corporate-gradient rounded-lg flex items-center justify-center flex-shrink-0 mt-1">
                    <BarChart3 className="w-4 h-4 text-white" />
                  </div>
                  <div>
                    <h4 className="text-white font-display text-base mb-2">Enterprise Dashboards</h4>
                    <p className="text-gray-300 font-body text-sm leading-relaxed">
                      Pin your favorite charts and generate professional PDF reports for stakeholder presentations.
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-4">
                  <div className="w-8 h-8 bg-corporate-gradient rounded-lg flex items-center justify-center flex-shrink-0 mt-1">
                    <Zap className="w-4 h-4 text-white" />
                  </div>
                  <div>
                    <h4 className="text-white font-display text-base mb-2">Voice-Enabled Queries</h4>
                    <p className="text-gray-300 font-body text-sm leading-relaxed">
                      Speak your questions naturally and get instant analytics. Perfect for hands-free data exploration.
                    </p>
                  </div>
                </div>
              </div>

              <div className="pt-4">
                <div className="bg-white/8 backdrop-blur-md rounded-xl p-6 border border-white/10">
                  <div className="flex items-center space-x-3 mb-3">
                    <CheckCircle className="w-5 h-5 text-cyan-400" />
                    <span className="text-white font-medium text-sm">Ready to transform your data workflow?</span>
                  </div>
                  <p className="text-gray-300 font-body text-sm leading-relaxed">
                    Join thousands of data professionals who have streamlined their analytics with Dashboard Agent's 
                    intelligent platform.
                  </p>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Professional Footer - Contact Section */}
      <footer id="contact" className="bg-black/30 backdrop-blur-xl border-t border-white/10 py-16">
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center space-x-3 mb-6 md:mb-0">
              <div className="w-10 h-10 bg-corporate-gradient rounded-xl flex items-center justify-center shadow-lg">
                <BarChart3 className="w-5 h-5 text-white" />
              </div>
              <div>
                <span className="text-xl font-display text-white tracking-tight">Dashboard Agent</span>
                <p className="text-gray-400 text-sm font-body">Enterprise Analytics Platform</p>
              </div>
            </div>
            <div className="text-center md:text-right">
              <p className="text-gray-400 font-body mb-2">
                Transforming enterprise data into competitive advantage
              </p>
              <p className="text-gray-500 text-sm font-body">
                © 2024 Dashboard Agent. All rights reserved. 
              </p>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPages;

