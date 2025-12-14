import Assets from './views/Assets';
import GraphView from './views/GraphView';
import Settings from './views/Settings';
import { AnimatePresence, motion } from 'framer-motion';

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

    // Page Transition Variants
    const variants = {
        initial: { opacity: 0, y: 10, filter: 'blur(5px)' },
        animate: { opacity: 1, y: 0, filter: 'blur(0px)' },
        exit: { opacity: 0, y: -10, filter: 'blur(5px)' }
    };

    return (
        <div className={`min-h-screen font-sans selection:bg-radium-500/30 ${darkMode ? 'dark bg-cyber-black text-white' : 'bg-slate-50 text-slate-900'}`}>
            <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
            <Header darkMode={darkMode} setDarkMode={setDarkMode} />

            <main className="ml-64 pt-20 p-8 min-h-screen transition-all duration-300">
                <AnimatePresence mode="wait">
                    {activeTab === 'dashboard' && (
                        <motion.div key="dashboard" variants={variants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.3, ease: "easeOut" }}>
                            <Dashboard />
                        </motion.div>
                    )}
                    {activeTab === 'assets' && (
                        <motion.div key="assets" variants={variants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.3, ease: "easeOut" }}>
                            <Assets />
                        </motion.div>
                    )}
                    {activeTab === 'graph' && (
                        <motion.div key="graph" variants={variants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.3, ease: "easeOut" }}>
                            <GraphView />
                        </motion.div>
                    )}
                    {activeTab === 'settings' && (
                        <motion.div key="settings" variants={variants} initial="initial" animate="animate" exit="exit" transition={{ duration: 0.3, ease: "easeOut" }}>
                            <Settings />
                        </motion.div>
                    )}

                    {/* Placeholders for other tabs */}
                    {['scans', 'threats', 'assets'].includes(activeTab) && (
                        <motion.div key="placeholder" variants={variants} initial="initial" animate="animate" exit="exit" className="flex flex-col items-center justify-center h-[600px] border-2 border-dashed border-cyber-border rounded-xl">
                            <div className="text-radium-500 animate-pulse text-6xl font-display mb-4">COMING SOON</div>
                            <p className="text-slate-500 font-mono">Module under development by Netra Core.</p>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
        </div>
    );
}

export default App;
