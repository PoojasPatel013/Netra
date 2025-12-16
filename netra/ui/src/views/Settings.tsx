import React from 'react';
import { Save, Lock, Bell, Cloud, Database } from 'lucide-react';

interface ToggleProps {
    label: string;
    enabled: boolean;
}

const Toggle = ({ label, enabled }: ToggleProps) => (
    <div className="flex items-center justify-between py-4 border-b border-cyber-border last:border-0">
        <span className="text-slate-300 font-medium">{label}</span>
        <button className={`w-12 h-6 rounded-full p-1 transition-colors duration-300 ${enabled ? 'bg-radium-600' : 'bg-slate-700'}`}>
            <div className={`w-4 h-4 bg-white rounded-full shadow-md transform transition-transform duration-300 ${enabled ? 'translate-x-6' : 'translate-x-0'}`}></div>
        </button>
    </div>
);

const Settings = () => {
    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-fade-in">
            <h2 className="text-2xl font-display font-bold text-white mb-6 border-l-4 border-radium-500 pl-4">System Configuration</h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* General Settings */}
                <div className="bg-cyber-dark border border-cyber-border rounded-xl p-6 shadow-lg">
                    <div className="flex items-center gap-3 mb-6">
                        <Cloud className="w-5 h-5 text-radium-500" />
                        <h3 className="text-lg font-bold text-white">Scanning Modules</h3>
                    </div>
                    <div className="space-y-1">
                        <Toggle label="Passive Reconnaissance (OSINT)" enabled={true} />
                        <Toggle label="Active Port Scanning" enabled={true} />
                        <Toggle label="Threat Intelligence Feed" enabled={true} />
                        <Toggle label="Compliance Mapping (PCI/GDPR)" enabled={false} />
                    </div>
                </div>

                {/* API Keys */}
                <div className="bg-cyber-dark border border-cyber-border rounded-xl p-6 shadow-lg">
                    <div className="flex items-center gap-3 mb-6">
                        <Lock className="w-5 h-5 text-radium-500" />
                        <h3 className="text-lg font-bold text-white">API Integration</h3>
                    </div>
                    <div className="space-y-4">
                        <div>
                            <label className="block text-xs font-mono text-slate-500 mb-1">DEFECTDOJO API KEY</label>
                            <input type="password" value="************************" className="w-full bg-cyber-black border border-cyber-border rounded px-3 py-2 text-slate-300 font-mono text-sm focus:border-radium-500 outline-none" disabled />
                        </div>
                        <div>
                            <label className="block text-xs font-mono text-slate-500 mb-1">AWS ACCESS KEY</label>
                            <input type="password" value="************************" className="w-full bg-cyber-black border border-cyber-border rounded px-3 py-2 text-slate-300 font-mono text-sm focus:border-radium-500 outline-none" disabled />
                        </div>
                        <button className="w-full py-2 bg-cyber-black border border-radium-500/30 text-radium-400 text-sm font-mono hover:bg-radium-500/10 transition-colors rounded">
                            UPDATE CREDENTIALS
                        </button>
                    </div>
                </div>
            </div>

            {/* Notification Area */}
            <div className="bg-cyber-dark border border-cyber-border rounded-xl p-6 shadow-lg">
                <div className="flex items-center gap-3 mb-6">
                    <Bell className="w-5 h-5 text-radium-500" />
                    <h3 className="text-lg font-bold text-white">Alert Preferences</h3>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="p-4 bg-cyber-black rounded border border-cyber-border flex flex-col items-center text-center hover:border-radium-500/50 transition-colors">
                        <span className="text-slate-300 font-bold mb-2">Email Alerts</span>
                        <span className="text-xs text-slate-500">Critical findings per scan</span>
                        <div className="mt-3 w-3 h-3 rounded-full bg-green-500 shadow-neon"></div>
                    </div>
                    <div className="p-4 bg-cyber-black rounded border border-cyber-border flex flex-col items-center text-center opacity-50">
                        <span className="text-slate-300 font-bold mb-2">Slack Webhook</span>
                        <span className="text-xs text-slate-500">Real-time channel push</span>
                        <div className="mt-3 w-3 h-3 rounded-full bg-slate-700"></div>
                    </div>
                    <div className="p-4 bg-cyber-black rounded border border-cyber-border flex flex-col items-center text-center opacity-50">
                        <span className="text-slate-300 font-bold mb-2">Jira Sync</span>
                        <span className="text-xs text-slate-500">Auto-ticket creation</span>
                        <div className="mt-3 w-3 h-3 rounded-full bg-slate-700"></div>
                    </div>
                </div>
            </div>

            <div className="flex justify-end pt-4">
                <button className="flex items-center gap-2 bg-radium-600 hover:bg-radium-500 text-white px-6 py-3 rounded-lg shadow-neon transition-all font-bold tracking-wide">
                    <Save className="w-4 h-4" />
                    SAVE CONFIGURATION
                </button>
            </div>
        </div>
    );
};

export default Settings;
