import { useState } from 'react'
import { useNavigate } from "react-router-dom"
import { LogOut, Search } from 'lucide-react'

export function Navbar({ userName = "User" }) {
  const navigate = useNavigate()
  const [isDropdownOpen, setIsDropdownOpen] = useState(false)
  
  const handleLogout = () => {
    // Add logout logic here
    navigate('/')
  }

  return (
    <div className="border-b bg-white">
      <div className="flex h-16 items-center px-4 md:px-6">
        <div className="flex items-center space-x-6 mr-4">
          <div className="text-xl font-semibold">Dashboard Agent</div>
          <nav className="hidden md:flex items-center space-x-6 text-sm font-medium">
            <a href="#" className="text-black">Overview</a>
           
          
          </nav>
        </div>
        <div className="ml-auto flex items-center space-x-4">
          <button className="p-2 hover:bg-gray-100 rounded-full">
            <Search className="h-5 w-5 text-gray-500" />
          </button>
          <div className="relative">
            <button 
              onClick={() => setIsDropdownOpen(!isDropdownOpen)}
              className="flex items-center space-x-2 hover:bg-gray-100 rounded-full p-1"
            >
              <div className="h-8 w-8 rounded-full bg-gray-200 flex items-center justify-center">
                {userName.charAt(0)}
              </div>
              <span className="text-sm font-medium">{userName}</span>
            </button>
            {isDropdownOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg py-1 z-50">
                <button
                  onClick={handleLogout}
                  className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>Log out</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

