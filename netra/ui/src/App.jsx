import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './views/Dashboard';
import Settings from './views/Settings';

function App() {
    const [activeTab, setActiveTab] = useState('dashboard');
    const [darkMode, setDarkMode] = useState(true);

    return (
        <div className={`min-h-screen font-sans selection:bg-radium-500/30 ${darkMode ? 'dark bg-cyber-black text-white' : 'bg-slate-50 text-slate-900'}`}>
            <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
            <Header darkMode={darkMode} setDarkMode={setDarkMode} />

            <main className="ml-64 pt-20 p-8 min-h-screen transition-all duration-300">
                {activeTab === 'dashboard' && <Dashboard />}
                {activeTab === 'settings' && <Settings />}

                {/* Placeholders for other tabs */}
                {['scans', 'threats', 'assets'].includes(activeTab) && (
                    <div className="flex flex-col items-center justify-center h-[600px] border-2 border-dashed border-cyber-border rounded-xl">
                        <div className="text-radium-500 animate-pulse text-6xl font-display mb-4">COMING SOON</div>
                        <p className="text-slate-500 font-mono">Module under development by Netra Core.</p>
                    </div>
                )}
            </main>
        </div>
    );
}

export default App;
