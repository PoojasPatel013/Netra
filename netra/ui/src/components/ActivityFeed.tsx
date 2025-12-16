import React from 'react';
import { motion } from 'framer-motion';
import { Activity, ShieldCheck, AlertTriangle, User, Database } from 'lucide-react';

const activities = [
    { id: 1, type: 'scan', msg: 'Port Scan completed on 192.168.1.105', time: '2 mins ago', icon: Activity, color: 'text-blue-400' },
    { id: 2, type: 'vuln', msg: 'High severity CVE-2024-3094 detected', time: '15 mins ago', icon: AlertTriangle, color: 'text-red-500' },
    { id: 3, type: 'auth', msg: 'Admin login from new IP (10.0.0.5)', time: '1 hour ago', icon: User, color: 'text-yellow-400' },
    { id: 4, type: 'system', msg: 'Database backup successful', time: '3 hours ago', icon: Database, color: 'text-green-400' },
    { id: 5, type: 'scan', msg: 'Passive Recon started on target: example.com', time: '5 hours ago', icon: ShieldCheck, color: 'text-radium-400' },
];

const ActivityFeed = () => {
    return (
        <div className="bg-cyber-dark/50 border border-cyber-border rounded-xl p-6 relative backdrop-blur overflow-hidden flex flex-col h-full">
            <h3 className="text-lg font-display font-bold text-white mb-4 border-b border-cyber-border pb-2">Recent Activity</h3>

            <ul className="space-y-4 overflow-y-auto pr-2 scrollbar-thin">
                {activities.map((item, index) => (
                    <motion.li
                        key={item.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                        className="flex gap-4 items-start group"
                    >
                        <div className={`mt-1 bg-cyber-black p-2 rounded-lg border border-cyber-border group-hover:border-radium-500/30 transition-colors ${item.color}`}>
                            <item.icon className="w-4 h-4" />
                        </div>
                        <div className="flex-1">
                            <p className="text-sm text-slate-300 group-hover:text-white transition-colors">{item.msg}</p>
                            <span className="text-xs text-slate-600 font-mono">{item.time}</span>
                        </div>
                    </motion.li>
                ))}
            </ul>
        </div>
    );
};

export default ActivityFeed;
