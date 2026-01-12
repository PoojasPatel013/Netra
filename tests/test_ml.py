import unittest
import numpy as np
from netra.ml.brain import NetraBrain

class MockScan:
    def __init__(self, id, score, vulns, ports):
        self.id = id
        self.risk_score = score
        self.results = {
            "ThreatScanner": {"vulnerabilities": ["v"] * vulns},
            "PortScanner": {"open_ports": ["p"] * ports}
        }

class TestNetraBrain(unittest.TestCase):
    
    def setUp(self):
        self.brain = NetraBrain()

    def test_clustering(self):
        # Create 3 distinct groups of scans
        # Group A: Low Risk (0 score)
        # Group B: Med Risk (50 score)
        # Group C: High Risk (100 score)
        scans = []
        for i in range(5): scans.append(MockScan(f"L{i}", 0, 0, 1))
        for i in range(5): scans.append(MockScan(f"M{i}", 50, 5, 5))
        for i in range(5): scans.append(MockScan(f"H{i}", 100, 20, 10))
        
        result = self.brain.cluster_risks(scans)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("centroids", result)
        self.assertIn("High Risk (Critical)", result["clusters"])
        # Verify at least some ended up in High Risk
        self.assertTrue(len(result["clusters"]["High Risk (Critical)"]) > 0)

    def test_topology_centrality(self):
        # Create a "Star" topology where Node A is the center
        # B-A-C
        #   |
        #   D
        nodes = [
            {"id": "A", "label": "Center"},
            {"id": "B", "label": "Leaf1"},
            {"id": "C", "label": "Leaf2"},
            {"id": "D", "label": "Leaf3"}
        ]
        links = [
            {"source": "B", "target": "A"},
            {"source": "C", "target": "A"},
            {"source": "D", "target": "A"}
        ]
        
        result = self.brain.analyze_topology(nodes, links)
        
        critical = result["critical_nodes"]
        self.assertTrue(len(critical) > 0)
        # A should be the most critical
        self.assertEqual(critical[0]["node"], "Center")

if __name__ == '__main__':
    unittest.main()
