import { useState } from 'react'
import { useNavigate } from "react-router-dom"
import { LogOut, Search, BarChart3, Moon, Sun, Database, Wifi } from 'lucide-react'
import { useUser } from '../context/UserContext'

export function Navbar({ isDarkMode, onToggleDarkMode, isConnectedToDatabase }) {
  const navigate = useNavigate()
  const { user, logout, isAuthenticated } = useUser()
  const [isDropdownOpen, setIsDropdownOpen] = useState(false)
  
  const handleLogout = () => {
    logout(navigate)
    setIsDropdownOpen(false)
  }

  // Get user display name and initials
  const displayName = user?.firstName || user?.name || "User"
  const initials = user?.firstName ? user.firstName.charAt(0).toUpperCase() : (user?.name ? user.name.charAt(0).toUpperCase() : "U")
  const profilePicture = user?.picture

  return (
    <div className="border-b bg-white">
      <div className="flex h-16 items-center px-4 md:px-6">
        <div className="flex items-center space-x-6 mr-4">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
              <BarChart3 className="w-5 h-5 text-white" />
            </div>
            <div className="text-xl font-semibold">Dashboard Agent</div>
          </div>
          <nav className="hidden md:flex items-center space-x-6 text-sm font-medium">
            <button 
              onClick={() => navigate('/chat')}
              className="text-black hover:text-blue-600 transition-colors"
            >
              Analytics
            </button>
            <button 
              onClick={() => navigate('/recommendations')}
              className="text-gray-500 hover:text-black transition-colors"
            >
              Dashboard
            </button>
            <a href="#" className="text-gray-500 hover:text-black transition-colors">Reports</a>
          </nav>
        </div>
        
        <div className="ml-auto flex items-center space-x-4">
          {/* Database Connection Status */}
          <div className="flex items-center space-x-1">
            <Wifi className={`h-4 w-4 ${isConnectedToDatabase ? 'text-green-500' : 'text-gray-400'}`} />
            <Database className={`h-4 w-4 ${isConnectedToDatabase ? 'text-green-500' : 'text-gray-400'}`} />
          </div>
          
          {/* Dark Mode Toggle */}
          <button 
            onClick={onToggleDarkMode}
            className="p-2 hover:bg-gray-100 rounded-full transition-colors"
            title={isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {isDarkMode ? (
              <Sun className="h-5 w-5 text-gray-500" />
            ) : (
              <Moon className="h-5 w-5 text-gray-500" />
            )}
          </button>
          
          {/* Search Button */}
          <button className="p-2 hover:bg-gray-100 rounded-full transition-colors">
            <Search className="h-5 w-5 text-gray-500" />
          </button>
          
          {/* User Profile Dropdown */}
          {isAuthenticated && user ? (
            <div className="relative">
              <button 
                onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                className="flex items-center space-x-2 hover:bg-gray-100 rounded-full p-1 transition-colors"
              >
                <div className="h-8 w-8 rounded-full overflow-hidden bg-gray-200 flex items-center justify-center">
                  {profilePicture ? (
                    <img 
                      src={profilePicture} 
                      alt={displayName}
                      className="h-full w-full object-cover"
                    />
                  ) : (
                    <span className="text-sm font-medium text-gray-600">{initials}</span>
                  )}
                </div>
                <span className="text-sm font-medium text-gray-700">{displayName}</span>
              </button>
              
              {isDropdownOpen && (
                <div className="absolute right-0 mt-2 w-56 bg-white rounded-lg shadow-lg py-1 z-50 border">
                  {/* User Info */}
                  <div className="px-4 py-3 border-b border-gray-100">
                    <div className="flex items-center space-x-3">
                      <div className="h-10 w-10 rounded-full overflow-hidden bg-gray-200 flex items-center justify-center">
                        {profilePicture ? (
                          <img 
                            src={profilePicture} 
                            alt={displayName}
                            className="h-full w-full object-cover"
                          />
                        ) : (
                          <span className="text-sm font-medium text-gray-600">{initials}</span>
                        )}
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-900">{user.name || displayName}</div>
                        <div className="text-xs text-gray-500">{user.email}</div>
                        <div className="text-xs text-blue-500">
                          {user.auth_method === 'google' ? '🟢 Google Account' : '🔐 Email Account'}
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  {/* Menu Items */}
                  <button
                    onClick={() => {
                      navigate('/profile')
                      setIsDropdownOpen(false)
                    }}
                    className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  >
                    <div className="mr-2 h-4 w-4 rounded-full bg-blue-100 flex items-center justify-center">
                      <div className="h-2 w-2 bg-blue-500 rounded-full"></div>
                    </div>
                    <span>Profile Settings</span>
                  </button>
                  
                  <div className="border-t border-gray-100 my-1"></div>
                  
                  <button
                    onClick={handleLogout}
                    className="flex items-center w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50"
                  >
                    <LogOut className="mr-2 h-4 w-4" />
                    <span>Sign Out</span>
                  </button>
                </div>
              )}
            </div>
          ) : (
            /* Show login button if not authenticated */
            <button
              onClick={() => navigate('/')}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
            >
              Sign In
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

