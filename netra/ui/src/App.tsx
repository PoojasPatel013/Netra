import { useState, useEffect } from 'react';
import Assets from './views/Assets';
import GraphView from './views/GraphView';
import Settings from './views/Settings';
import { AnimatePresence, motion } from 'framer-motion';
import Dashboard from './views/Dashboard';
import Header from './components/Header';

function App() {
    // ... existing ... 
    const [activeTab, setActiveTab] = useState('dashboard');
    const [darkMode, setDarkMode] = useState(() => {
        const saved = localStorage.getItem('netra-theme');
        return saved ? JSON.parse(saved) : true;
    });

    useEffect(() => {
        localStorage.setItem('netra-theme', JSON.stringify(darkMode));
        if (darkMode) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    }, [darkMode]);

    // Page Flip Variants
    const pageVariants = {
        initial: {
            rotateY: -90,
            opacity: 0,
            transformPerspective: 1000,
            transformOrigin: "left center"
        },
        animate: {
            rotateY: 0,
            opacity: 1,
            transformPerspective: 1000,
            transformOrigin: "left center"
        },
        exit: {
            rotateY: 90,
            opacity: 0,
            transformPerspective: 1000,
            transformOrigin: "right center"
        }
    };

    return (
        <div className={`min-h-screen font-sans selection:bg-radium-500/30 overflow-x-hidden ${darkMode ? 'dark bg-cyber-black text-white' : 'bg-slate-50 text-slate-900'} transition-colors duration-500`}>
            {/* <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} /> -- REPLACED BY MASTHEAD */}
            <Header darkMode={darkMode} setDarkMode={setDarkMode} activeTab={activeTab} setActiveTab={setActiveTab} />

            <main className="max-w-7xl mx-auto p-4 md:p-8 min-h-[calc(100vh-300px)]">
                <AnimatePresence mode="wait">
                    {activeTab === 'dashboard' && (
                        <motion.div key="dashboard" variants={pageVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.6, ease: "easeInOut" }} className="origin-left">
                            <Dashboard />
                        </motion.div>
                    )}
                    {activeTab === 'assets' && (
                        <motion.div key="assets" variants={pageVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.6, ease: "easeInOut" }} className="origin-left">
                            <Assets />
                        </motion.div>
                    )}
                    {activeTab === 'graph' && (
                        <motion.div key="graph" variants={pageVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.6, ease: "easeInOut" }} className="origin-left">
                            <GraphView />
                        </motion.div>
                    )}
                    {activeTab === 'settings' && (
                        <motion.div key="settings" variants={pageVariants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.6, ease: "easeInOut" }} className="origin-left">
                            <Settings />
                        </motion.div>
                    )}

                    {/* Placeholders for other tabs */}
                    {['scans', 'threats'].includes(activeTab) && (
                        <motion.div key="placeholder" variants={pageVariants} initial="initial" animate="animate" exit="exit" className="flex flex-col items-center justify-center h-[600px] border-4 border-double border-slate-300 dark:border-slate-700 bg-white dark:bg-cyber-dark p-8 shadow-xl origin-left">
                            <div className="text-center">
                                <h2 className="text-4xl font-serif font-bold text-slate-800 dark:text-slate-100 mb-4 italic">"This Story is Developing..."</h2>
                                <div className="h-0.5 w-24 bg-radium-500 mx-auto mb-4"></div>
                                <p className="text-slate-600 dark:text-slate-400 font-mono text-lg">Our reporters are currently investigating this module. Check back in the next edition.</p>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>

            <footer className="border-t border-slate-300 dark:border-slate-800 py-8 text-center bg-slate-100 dark:bg-cyber-black mt-12">
                <p className="font-serif italic text-slate-500 dark:text-slate-500">
                    &copy; {new Date().getFullYear()} The Netra Times. All rights reserved. | Printed in Docker.
                </p>
            </footer>
        </div>
    );
}

export default App;
