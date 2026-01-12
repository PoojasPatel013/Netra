import logging
import networkx as nx
import numpy as np
from sklearn.cluster import KMeans
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class NetraBrain:
    def __init__(self):
        self.kmeans_model = None
        self.last_training_size = 0

    def cluster_risks(self, scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Unsupervised Learning: Group scans into risk profiles (Safe, Suspicious, Critical).
        """
        if not scans or len(scans) < 3:
            return {"error": "Not enough data points for clustering (need 3+)"}

        try:
            # 1. Feature Extraction
            # Features: [RiskScore, NumVulns, NumPorts]
            features = []
            scan_ids = []
            
            for s in scans:
                # Handle SQLModel object vs Dict
                score = getattr(s, "risk_score", 0)
                sid = getattr(s, "id", "unknown")
                
                # Extract deeper metrics if available (simulated for safely handling dict/obj)
                res = getattr(s, "results", {})
                vulns = 0
                ports = 0
                
                if isinstance(res, dict):
                     vulns = len(res.get("ThreatScanner", {}).get("vulnerabilities", []))
                     ports = len(res.get("PortScanner", {}).get("open_ports", []))

                features.append([score, vulns, ports])
                scan_ids.append(sid)

            X = np.array(features)

            # 2. K-Means
            kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
            labels = kmeans.fit_predict(X)
            
            # 3. Interpret Clusters
            # We need to map 0,1,2 to "High", "Med", "Low" based on the centroids
            # Calculate mean Risk Score for each cluster
            centers = kmeans.cluster_centers_
            cluster_risk_avg = [rec[0] for rec in centers]
            
            # Sort indices by risk (Ascending)
            # e.g. [10, 80, 40] -> sorted indices: [0, 2, 1] -> Low, Med, High
            sorted_indices = np.argsort(cluster_risk_avg)
            
            risk_map = {
                sorted_indices[0]: "Low Risk (Safe)",
                sorted_indices[1]: "Medium Risk (Suspicious)",
                sorted_indices[2]: "High Risk (Critical)"
            }

            clusters = {}
            for idx, label in enumerate(labels):
                group_name = risk_map[label]
                if group_name not in clusters:
                    clusters[group_name] = []
                clusters[group_name].append(scan_ids[idx])

            return {
                "clusters": clusters,
                "centroids": centers.tolist(),
                "status": "success"
            }

        except Exception as e:
            logger.error(f"Clustering Failed: {e}")
            return {"error": str(e)}

    def analyze_topology(self, nodes: List[Dict], links: List[Dict]) -> Dict[str, Any]:
        """
        Graph Theory: Calculate Betweenness Centrality to find critical bridges.
        """
        try:
            G = nx.Graph()
            
            # Build Graph
            for n in nodes:
                G.add_node(n["id"], label=n.get("label", "Unknown"))
                
            for l in links:
                G.add_edge(l["source"], l["target"])
                
            if G.number_of_nodes() == 0:
                return {"critical_nodes": []}

            # Analysis
            centrality = nx.betweenness_centrality(G)
            
            # Get Top 3 Critical Nodes
            # Sort by score desc
            sorted_nodes = sorted(centrality.items(), key=lambda item: item[1], reverse=True)[:3]
            
            critical_infrastructure = []
            for node_id, score in sorted_nodes:
                if score > 0:
                    # Find original node label
                    detail = next((n for n in nodes if n["id"] == node_id), None)
                    label = detail["label"] if detail else node_id
                    critical_infrastructure.append({
                        "node": label,
                        "centrality_score": round(score, 4),
                        "insight": "High traffic bridge - Critical point of failure"
                    })

            return {"critical_nodes": critical_infrastructure}

        except Exception as e:
            logger.error(f"Topology Analysis Failed: {e}")
            return {"error": str(e)}
