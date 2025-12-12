import React from 'react';
import { LayoutDashboard, Shield, AlertTriangle, Settings, Activity, Database } from 'lucide-react';

const Sidebar = ({ activeTab, setActiveTab }) => {
    const menuItems = [
        { id: 'dashboard', icon: LayoutDashboard, label: 'Mission Control' },
        { id: 'scans', icon: Activity, label: 'Active Scans' },
        { id: 'threats', icon: AlertTriangle, label: 'Threat Intel' },
        { id: 'assets', icon: Database, label: 'Asset Inventory' },
        { id: 'settings', icon: Settings, label: 'System Config' },
    ];

    return (
        <aside className="w-64 bg-cyber-black border-r border-cyber-border h-screen fixed left-0 top-0 flex flex-col z-50">
            {/* Logo Area */}
            <div className="h-16 flex items-center px-6 border-b border-cyber-border bg-cyber-dark/50 backdrop-blur">
                <Shield className="w-8 h-8 text-radium-500 animate-pulse-slow mr-3" />
                <div>
                    <h1 className="text-2xl font-display font-bold text-white tracking-widest text-glow">
                        NETRA
                    </h1>
                    <div className="h-0.5 w-full bg-radium-500 shadow-neon mt-1"></div>
                </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 py-6 px-3 space-y-2">
                {menuItems.map((item) => {
                    const isActive = activeTab === item.id;
                    const Icon = item.icon;
                    return (
                        <button
                            key={item.id}
                            onClick={() => setActiveTab(item.id)}
                            className={`w-full flex items-center px-4 py-3 rounded-lg transition-all duration-300 group relative overflow-hidden ${isActive
                                    ? 'bg-radium-500/10 text-radium-400 border border-radium-500/50 shadow-neon'
                                    : 'text-slate-400 hover:bg-cyber-dark hover:text-white hover:border hover:border-radium-500/30'
                                }`}
                        >
                            {/* Active Indicator Line */}
                            {isActive && <div className="absolute left-0 top-0 bottom-0 w-1 bg-radium-500 shadow-neon"></div>}

                            <Icon className={`w-5 h-5 mr-3 transition-transform ${isActive ? 'scale-110' : 'group-hover:scale-110'}`} />
                            <span className="font-mono text-sm tracking-wide">{item.label}</span>
                        </button>
                    );
                })}
            </nav>

            {/* Footer */}
            <div className="p-4 border-t border-cyber-border bg-cyber-darkAPI/30">
                <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse shadow-[0_0_8px_#22c55e]"></div>
                    <span className="text-xs font-mono text-radium-200">System Online</span>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
