import React, { useRef, useEffect } from 'react';
import { motion } from 'framer-motion';

interface Particle {
    x: number;
    y: number;
    vx: number;
    vy: number;
}

const GraphView = () => {
    const canvasRef = useRef<HTMLCanvasElement>(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Simple particle simulation to look like a "Graph"
        let particles: Particle[] = [];
        for (let i = 0; i < 50; i++) {
            particles.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                vx: (Math.random() - 0.5) * 0.5,
                vy: (Math.random() - 0.5) * 0.5
            });
        }

        const animate = () => {
            if (!canvas) return;
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#00f3ff';
            ctx.strokeStyle = 'rgba(0, 243, 255, 0.2)';

            particles.forEach(p => {
                p.x += p.vx;
                p.y += p.vy;
                if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
                if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

                ctx.beginPath();
                ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
                ctx.fill();

                particles.forEach(p2 => {
                    const dx = p.x - p2.x;
                    const dy = p.y - p2.y;
                    if (Math.sqrt(dx * dx + dy * dy) < 100) {
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.stroke();
                    }
                });
            });
            requestAnimationFrame(animate);
        };
        animate();
    }, []);

    return (
        <div className="relative h-full w-full bg-cyber-black overflow-hidden rounded-xl border border-cyber-border">
            <div className="absolute top-4 left-4 z-10">
                <h2 className="text-2xl font-display font-bold text-white">Asset Graph <span className="text-radium-500 text-sm">v2.0 Beta</span></h2>
                <p className="text-slate-400 text-sm">Visualizing relationships between domains, IPs, and cloud resources.</p>
            </div>
            <canvas ref={canvasRef} width={800} height={600} className="w-full h-full opacity-60" />
        </div>
    );
};

export default GraphView;
