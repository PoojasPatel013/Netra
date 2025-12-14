import React from 'react';
import { Bell, User, Sun, Moon, Search } from 'lucide-react';
import { motion } from 'framer-motion';

const Header = ({ darkMode, setDarkMode }) => {
    return (
        <header className="h-16 bg-cyber-black/80 backdrop-blur-md border-b border-cyber-border fixed top-0 right-0 left-64 z-40 flex items-center justify-between px-8">
            {/* Search Bar */}
            <div className="relative w-96 group">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Search className="h-4 w-4 text-slate-500 group-focus-within:text-radium-500 transition-colors" />
                </div>
                <input
                    type="text"
                    className="block w-full pl-10 pr-3 py-2 bg-cyber-dark border border-cyber-border rounded-md leading-5 text-slate-300 placeholder-slate-500 focus:outline-none focus:bg-cyber-black focus:border-radium-500 focus:shadow-neon transition-all duration-300 sm:text-sm font-mono"
                    placeholder="Search assets, IPs, or vulnerabilities..."
                />
            </div>

            {/* Right Actions */}
            <div className="flex items-center gap-4">
                {/* Theme Toggle */}
                <button
                    onClick={() => setDarkMode(!darkMode)}
                    className={`relative w-14 h-7 rounded-full transition-colors duration-300 ${darkMode ? 'bg-radium-600/20 border border-radium-500/50' : 'bg-slate-200 border border-slate-300'}`}
                >
                    <motion.div
                        className={`absolute top-0.5 left-0.5 w-5.5 h-5.5 rounded-full shadow-md flex items-center justify-center ${darkMode ? 'bg-radium-500' : 'bg-white'}`}
                        animate={{ x: darkMode ? 28 : 0 }}
                        transition={{ type: "spring", stiffness: 500, damping: 30 }}
                    >
                        {darkMode ? <Moon className="w-3 h-3 text-black" /> : <Sun className="w-3 h-3 text-yellow-500" />}
                    </motion.div>
                </button>

                {/* Notifications */}
                <button className="relative p-2 rounded-lg text-slate-400 hover:text-radium-400 hover:bg-cyber-dark transition-colors">
                    <Bell className="w-5 h-5" />
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-radium-500 rounded-full animate-pulse"></span>
                </button>

                {/* User Profile */}
                <div className="flex items-center gap-3 pl-4 border-l border-cyber-border">
                    <div className="text-right hidden md:block">
                        <p className="text-sm font-medium text-white">Netra v2.0</p>
                        <p className="text-xs text-radium-500 font-mono">AI-ASM Platform</p>
                    </div>
                    <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-radium-500 to-blue-600 p-[1px]">
                        <div className="w-full h-full rounded-full bg-cyber-black flex items-center justify-center">
                            <User className="w-4 h-4 text-white" />
                        </div>
                    </div>
                </div>
            </div>
        </header>
    );
};

export default Header;
