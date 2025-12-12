import React, { useState, useEffect } from 'react';
import { Terminal, Play, Activity, AlertOctagon, CheckCircle, Server, Globe, Cpu } from 'lucide-react';

const StatCard = ({ title, value, icon: Icon, color, trend }) => (
    <div className="bg-cyber-dark border border-cyber-border p-5 rounded-xl relative overflow-hidden group hover:border-radium-500/50 transition-all duration-300">
        <div className={`absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity ${color}`}>
            <Icon className="w-16 h-16" />
        </div>
        <div className="flex items-center justify-between mb-4">
            <h3 className="text-slate-400 text-sm font-mono tracking-wider">{title}</h3>
            <Icon className={`w-5 h-5 ${color.replace('bg-', 'text-')}`} />
        </div>
        <div className="flex items-end gap-2">
            <span className="text-3xl font-bold text-white font-display text-glow">{value}</span>
            <span className="text-xs text-radium-400 mb-1 font-mono">{trend}</span>
        </div>
    </div>
);

const Dashboard = () => {
    const [target, setTarget] = useState('');
    const [scanning, setScanning] = useState(false);
    const [logs, setLogs] = useState([]);
    const [results, setResults] = useState(null);

    const addLog = (msg) => setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);

    const startScan = async () => {
        if (!target) return;
        setScanning(true);
        setResults(null);
        setLogs([]);
        addLog(`INITIALIZING SCAN SEQUENCE FOR: ${target}`);

        // Simulate logs for demo feel immediately
        setTimeout(() => addLog("Resolving DNS targeting vectors..."), 500);
        setTimeout(() => addLog("Engaging active reconnaissance modules..."), 1200);

        try {
            // Real API Call
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target }),
            });

            if (!response.ok) throw new Error('API Handshake Failed');

            addLog('Payload delivered. Job queued.');

            const pollInterval = setInterval(async () => {
                try {
                    const res = await fetch(`/api/scan/results/${encodeURIComponent(target)}`);
                    const resData = await res.json();
                    if (resData.status !== 'pending or not found') {
                        clearInterval(pollInterval);
                        setResults(resData);
                        setScanning(false);
                        addLog('MISSION COMPLETE. Data acquired.');
                    }
                } catch (e) { console.error(e); }
            }, 2000);

            // Timeout
            setTimeout(() => {
                clearInterval(pollInterval);
                if (scanning) {
                    setScanning(false);
                    addLog("TIMEOUT: Target unresponsive.");
                }
            }, 60000);

        } catch (e) {
            addLog(`CRITICAL FAILURE: ${e.message}`);
            setScanning(false);
        }
    };

    return (
        <div className="space-y-6">
            {/* KPI Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard title="TOTAL SCANS" value="1,284" icon={Activity} color="text-blue-500" trend="+12% this week" />
                <StatCard title="CRITICAL VULNS" value="42" icon={AlertOctagon} color="text-red-500" trend="-5% resolved" />
                <StatCard title="ACTIVE ASSETS" value="856" icon={Server} color="text-green-500" trend="+3 new" />
                <StatCard title="THREAT LEVEL" value="MODERATE" icon={Globe} color="text-yellow-500" trend="Defcon 3" />
            </div>

            {/* Main Interface */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">

                {/* Left Column: Input & Logs */}
                <div className="lg:col-span-1 flex flex-col gap-6">
                    {/* Input Card */}
                    <div className="bg-cyber-dark border border-cyber-border p-6 rounded-xl shadow-lg relative overflow-hidden">
                        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-radium-500 to-transparent opacity-50"></div>
                        <h2 className="text-xl font-display font-bold text-white mb-4 flex items-center gap-2">
                            <Terminal className="w-5 h-5 text-radium-500" />
                            Target Acquisition
                        </h2>

                        <div className="relative mb-4">
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Enter Domain / IP..."
                                className="w-full bg-cyber-black border border-cyber-border rounded-lg py-3 px-4 text-white font-mono focus:outline-none focus:border-radium-500 focus:shadow-neon transition-all placeholder-slate-600"
                            />
                            <div className="absolute right-3 top-3.5">
                                <span className="flex h-2 w-2 relative">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-radium-400 opacity-75"></span>
                                    <span className="relative inline-flex rounded-full h-2 w-2 bg-radium-500"></span>
                                </span>
                            </div>
                        </div>

                        <button
                            onClick={startScan}
                            disabled={scanning}
                            className={`w-full py-3 rounded-lg font-bold font-mono tracking-widest transition-all duration-300 flex items-center justify-center gap-2 ${scanning
                                    ? 'bg-radium-900/50 text-radium-500 cursor-not-allowed border border-radium-500/20'
                                    : 'bg-radium-600 hover:bg-radium-500 text-white shadow-neon hover:scale-[1.02]'
                                }`}
                        >
                            {scanning ? <Activity className="w-5 h-5 animate-spin" /> : <Play className="w-5 h-5" />}
                            {scanning ? 'SCANNING...' : 'INITIATE SCAN'}
                        </button>
                    </div>

                    {/* Console Logs */}
                    <div className="flex-1 bg-cyber-black border border-cyber-border rounded-xl p-4 font-mono text-xs overflow-hidden flex flex-col shadow-inner">
                        <div className="flex items-center justify-between mb-2 pb-2 border-b border-cyber-border">
                            <span className="text-slate-400">System Logs</span>
                            <div className="flex gap-1.5">
                                <div className="w-2.5 h-2.5 rounded-full bg-red-500/20 border border-red-500/50"></div>
                                <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/20 border border-yellow-500/50"></div>
                                <div className="w-2.5 h-2.5 rounded-full bg-green-500/20 border border-green-500/50"></div>
                            </div>
                        </div>
                        <div className="flex-1 overflow-y-auto space-y-1 text-radium-200 scrollbar-thin">
                            {logs.length === 0 && <span className="text-slate-700 typing-cursor">Awaiting commands...</span>}
                            {logs.map((log, i) => (
                                <div key={i} className="break-all opacity-80 hover:opacity-100 transition-opacity">
                                    <span className="text-slate-500 mr-2">{'>'}</span>
                                    {log}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Right Column: Visualization / Results */}
                <div className="lg:col-span-2 bg-cyber-dark/50 border border-cyber-border rounded-xl p-6 relative backdrop-blur overflow-hidden flex flex-col">
                    {/* Scan Results Visualization */}
                    {!results ? (
                        <div className="flex-1 flex flex-col items-center justify-center relative">
                            {/* Scan Animation Placeholder */}
                            <div className="relative w-64 h-64">
                                <div className={`absolute inset-0 border-4 border-radium-500/20 rounded-full ${scanning ? 'animate-ping' : ''}`}></div>
                                <div className={`absolute inset-4 border-4 border-t-radium-500 border-r-transparent border-b-radium-500 border-l-transparent rounded-full ${scanning ? 'animate-spin-slow' : ''}`}></div>
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <div className="text-center">
                                        <Shield className={`w-12 h-12 mx-auto mb-2 text-radium-500 ${scanning ? 'animate-pulse' : 'opacity-50'}`} />
                                        <p className="text-radium-500 font-mono text-sm tracking-widest">{scanning ? 'ANALYZING' : 'READY'}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="h-full overflow-y-auto pr-2 space-y-4">
                            <div className="flex items-center justify-between mb-4">
                                <h2 className="text-xl font-display text-white">Analysis Report</h2>
                                <span className="px-3 py-1 bg-green-900/30 text-green-400 border border-green-500/30 rounded text-xs font-mono">COMPLETED</span>
                            </div>

                            {/* Dynamic Cards based on Results */}

                            {/* Port Scanner */}
                            {results.PortScanner && (
                                <div className="bg-cyber-black p-4 rounded-lg border border-cyber-border hover:border-radium-500/30 transition-colors">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Server className="w-4 h-4 text-blue-400" />
                                        <h4 className="text-sm font-bold text-slate-300">OPEN PORTS</h4>
                                    </div>
                                    <div className="flex flex-wrap gap-2">
                                        {results.PortScanner.open_ports?.map(p => (
                                            <span key={p} className="px-3 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded text-xs font-mono font-bold tracking-wider">
                                                PORT {p}
                                            </span>
                                        )) || <span className="text-slate-500 text-xs italic">No open ports detected.</span>}
                                    </div>
                                </div>
                            )}

                            {/* Threats */}
                            {results.ThreatScanner && (
                                <div className="bg-cyber-black p-4 rounded-lg border border-cyber-border hover:border-red-500/30 transition-colors">
                                    <div className="flex items-center gap-2 mb-3">
                                        <AlertOctagon className="w-4 h-4 text-red-500" />
                                        <h4 className="text-sm font-bold text-slate-300">THREAT INTEL</h4>
                                    </div>
                                    <div className="space-y-2">
                                        {results.ThreatScanner.vulnerabilities?.map((vuln, i) => (
                                            <div key={i} className="flex items-start gap-3 p-3 bg-red-950/10 border-l-2 border-red-500 rounded">
                                                <div className="flex-1">
                                                    <p className="text-red-400 text-sm font-bold">{vuln.type}</p>
                                                    <p className="text-slate-400 text-xs">{vuln.details}</p>
                                                </div>
                                                <span className="text-xs font-mono text-red-500 border border-red-500/20 px-2 py-0.5 rounded">{vuln.severity}</span>
                                            </div>
                                        )) || <span className="text-green-500 text-xs">No threats detected.</span>}
                                    </div>
                                </div>
                            )}

                            {/* JSON Dump for unmatched */}
                            <div className="mt-4">
                                <details>
                                    <summary className="text-xs text-slate-500 cursor-pointer hover:text-white">View Raw Data</summary>
                                    <pre className="mt-2 text-[10px] text-slate-400 bg-black p-4 rounded font-mono overflow-x-auto">
                                        {JSON.stringify(results, null, 2)}
                                    </pre>
                                </details>
                            </div>

                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
