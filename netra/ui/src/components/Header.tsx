import { useState } from 'react';
import React from 'react';
import { Bell, User, Sun, Moon, Search, LayoutDashboard, Share2, Activity, AlertTriangle, Database, Settings, Shield } from 'lucide-react';
import { motion } from 'framer-motion';

interface HeaderProps {
    darkMode: boolean;
    setDarkMode: (mode: boolean) => void;
    activeTab: string;
    setActiveTab: (tab: string) => void;
}

const Header = ({ darkMode, setDarkMode, activeTab, setActiveTab }: HeaderProps) => {
    const menuItems = [
        { id: 'dashboard', label: 'FRONT PAGE', icon: LayoutDashboard },
        { id: 'scans', label: 'LATEST CABLES', icon: Activity },
        { id: 'graph', label: 'INVESTIGATIONS', icon: Share2 },
        { id: 'threats', label: 'OBITUARIES (VULNS)', icon: AlertTriangle },
        { id: 'assets', label: 'CLASSIFIEDS', icon: Database },
        { id: 'settings', label: 'ARCHIVES', icon: Settings },
    ];

    return (
        <header className="flex flex-col w-full bg-slate-50 dark:bg-cyber-black transition-colors duration-300 border-b-4 border-double border-slate-900 dark:border-slate-700 relative z-40">
            {/* Top Bar: Date, Weather (Mock), Search, Theme */}
            <div className="flex items-center justify-between px-8 py-2 border-b border-slate-300 dark:border-slate-800 text-xs font-serif italic text-slate-600 dark:text-slate-400">
                <div className="flex items-center gap-4">
                    <span>{new Date().toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</span>
                    <span className="hidden md:inline">|</span>
                    <span className="hidden md:inline">Vol. 2, No. 42</span>
                    <span className="hidden md:inline">|</span>
                    <span className="hidden md:inline">New Delhi, India</span>
                </div>

                <div className="flex items-center gap-4">
                    {/* Theme Toggle */}
                    <button
                        onClick={() => setDarkMode(!darkMode)}
                        className="hover:text-radium-600 dark:hover:text-radium-400 transition-colors"
                    >
                        {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                    </button>
                    {/* User */}
                    <div className="flex items-center gap-2">
                        <User className="w-3 h-3" />
                        <span className="font-bold">ADMINISTRATOR</span>
                    </div>
                </div>
            </div>

            {/* Masthead Title */}
            <div className="py-8 text-center relative overflow-hidden group">
                <motion.div
                    initial={{ y: -20, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    transition={{ duration: 0.8, ease: "circOut" }}
                >
                    <h1 className="text-6xl md:text-8xl font-serif font-black tracking-tighter text-slate-900 dark:text-slate-100 mb-2 pointer-events-none select-none relative z-10">
                        The Netra Times
                    </h1>
                </motion.div>
                <div className="h-1 w-32 bg-slate-900 dark:bg-slate-100 mx-auto mb-1"></div>
                <div className="h-0.5 w-full max-w-2xl bg-slate-900 dark:bg-slate-100 mx-auto"></div>
                <p className="mt-2 font-display text-sm tracking-[0.3em] text-slate-500 dark:text-radium-500 uppercase">
                    Advanced Security Monitoring & Intelligence
                </p>

                {/* Background Decor */}
                <Shield className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-64 h-64 text-slate-200/50 dark:text-slate-800/50 -z-0 opacity-20 rotate-12" />
            </div>

            {/* Navigation Bar */}
            <nav className="flex justify-center border-t border-b border-slate-300 dark:border-slate-700 py-3 sticky top-0 bg-slate-50/95 dark:bg-cyber-black/95 backdrop-blur z-50">
                <ul className="flex flex-wrap justify-center gap-1 md:gap-8 px-4">
                    {menuItems.map((item) => {
                        const isActive = activeTab === item.id;
                        return (
                            <li key={item.id}>
                                <button
                                    onClick={() => setActiveTab(item.id)}
                                    className={`relative px-2 py-1 font-serif text-sm md:text-base font-bold tracking-wider transition-all duration-300 ${isActive
                                        ? 'text-radium-700 dark:text-radium-400 scale-105'
                                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                                        }`}
                                >
                                    {item.label}
                                    {isActive && (
                                        <motion.div
                                            layoutId="activeTabUnderline"
                                            className="absolute -bottom-2 left-0 right-0 h-0.5 bg-radium-600 dark:bg-radium-500"
                                        />
                                    )}
                                </button>
                            </li>
                        );
                    })}
                </ul>
            </nav>
        </header>
    );
};

export default Header;
