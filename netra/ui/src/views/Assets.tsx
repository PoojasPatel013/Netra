import React from 'react';
import { motion } from 'framer-motion';
import { Server, Globe, Box, MoreVertical, Wifi, Shield } from 'lucide-react';

const assets = [
    { id: 1, name: 'primary-db-01', ip: '10.0.0.15', type: 'Database', os: 'Ubuntu 22.04', status: 'active', vulns: 2 },
    { id: 2, name: 'web-frontend-prod', ip: '192.168.1.10', type: 'Server', os: 'CentOS 8', status: 'active', vulns: 0 },
    { id: 3, name: 'gateway-router', ip: '192.168.1.1', type: 'Network', os: 'Cisco IOS', status: 'warning', vulns: 5 },
    { id: 4, name: 'dev-environment', ip: '10.0.0.88', type: 'Container', os: 'Alpine Linux', status: 'inactive', vulns: 0 },
    { id: 5, name: 'legacy-app-server', ip: '192.168.1.200', type: 'Server', os: 'Windows Server 2019', status: 'critical', vulns: 12 },
];

interface StatusBadgeProps {
    status: string;
}

const StatusBadge = ({ status }: StatusBadgeProps) => {
    const styles = {
        active: 'bg-green-500/10 text-green-400 border-green-500/20',
        inactive: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
        warning: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
        critical: 'bg-red-500/10 text-red-400 border-red-500/20'
    };
    return (
        <span className={`px-2 py-1 rounded text-xs font-mono border ${styles[status as keyof typeof styles] || styles.inactive}`}>
            {status.toUpperCase()}
        </span>
    );
};

const Assets = () => {
    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-display font-bold text-white mb-2">Asset Inventory</h2>
                    <p className="text-slate-400 text-sm">Manage and monitor discovered network entities.</p>
                </div>
                <button className="bg-radium-600 hover:bg-radium-500 text-white px-4 py-2 rounded-lg text-sm font-bold shadow-neon transition-all">
                    + ADD ASSET
                </button>
            </div>

            <div className="bg-cyber-dark border border-cyber-border rounded-xl overflow-hidden shadow-lg">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-cyber-black border-b border-cyber-border text-slate-400 text-xs font-mono uppercase tracking-wider">
                            <th className="p-4">Asset Name</th>
                            <th className="p-4">IP Address</th>
                            <th className="p-4">Type</th>
                            <th className="p-4">OS / Firmware</th>
                            <th className="p-4">Status</th>
                            <th className="p-4 text-center">Vulns</th>
                            <th className="p-4"></th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border">
                        {assets.map((asset, index) => (
                            <motion.tr
                                key={asset.id}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: index * 0.05 }}
                                className="group hover:bg-cyber-light/5 transition-colors"
                            >
                                <td className="p-4">
                                    <div className="flex items-center gap-3">
                                        <div className="p-2 rounded bg-cyber-black text-radium-500 group-hover:text-radium-400 transition-colors">
                                            {asset.type === 'Database' ? <Box size={16} /> :
                                                asset.type === 'Network' ? <Wifi size={16} /> :
                                                    <Server size={16} />}
                                        </div>
                                        <span className="font-bold text-slate-200 group-hover:text-white transition-colors">{asset.name}</span>
                                    </div>
                                </td>
                                <td className="p-4 font-mono text-sm text-slate-400">{asset.ip}</td>
                                <td className="p-4 text-sm text-slate-300">{asset.type}</td>
                                <td className="p-4 text-sm text-slate-400">{asset.os}</td>
                                <td className="p-4"><StatusBadge status={asset.status} /></td>
                                <td className="p-4 text-center">
                                    {asset.vulns > 0 ? (
                                        <span className="text-red-400 font-bold bg-red-500/10 px-2 py-1 rounded text-xs">{asset.vulns}</span>
                                    ) : (
                                        <span className="text-green-500/50 text-xs">-</span>
                                    )}
                                </td>
                                <td className="p-4 text-right">
                                    <button className="text-slate-500 hover:text-white transition-colors">
                                        <MoreVertical size={16} />
                                    </button>
                                </td>
                            </motion.tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default Assets;
