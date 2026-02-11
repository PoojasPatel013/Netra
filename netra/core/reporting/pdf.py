from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch, mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO
from datetime import datetime

class PDFReportGenerator:
    def __init__(self, buffer):
        self.buffer = buffer
        self.doc = SimpleDocTemplate(
            self.buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        self.styles = getSampleStyleSheet()
        self.elements = []

    def generate(self, scan_data: dict, user_name: str = "Netra User"):
        """
        Main orchestration method to build the PDF.
        """
        self._add_header_logo()
        self._add_title(scan_data)
        self._add_executive_summary(scan_data)
        self._add_findings_table(scan_data)
        self._add_footer_disclaimer()

        self.doc.build(self.elements)

    def _add_header_logo(self):
        # Header
        title_style = ParagraphStyle(
            'NetraHeader',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor("#2563EB"), # Blue-600
            alignment=1 # Center
        )
        self.elements.append(Paragraph("NETRA VORTEX", title_style))
        self.elements.append(Paragraph("Autonomous Security Grid", self.styles['Normal']))
        self.elements.append(Spacer(1, 20))

    def _add_title(self, scan_data):
        target = scan_data.get("target", "Unknown Target")
        date_str = scan_data.get("created_at", datetime.now().isoformat()).split("T")[0]
        
        self.elements.append(Paragraph(f"Security Audit Report: {target}", self.styles['Heading2']))
        self.elements.append(Paragraph(f"Date: {date_str}", self.styles['Normal']))
        self.elements.append(Spacer(1, 10))

    def _add_executive_summary(self, scan_data):
        score = scan_data.get("risk_score", 0)
        source = scan_data.get("risk_source", "Heuristic")
        
        # Color coding for Risk
        risk_color = "#10B981" # Green
        risk_label = "LOW RISK"
        if score > 50:
            risk_color = "#F59E0B" # Orange
            risk_label = "MEDIUM RISK"
        if score > 80:
            risk_color = "#EF4444" # Red
            risk_label = "CRITICAL RISK"
            
        summary_text = f"""
        <b>Executive Summary</b><br/>
        Netra Vortex has performed an automated security assessment of the target infrastructure.
        The overall risk score is calculated based on exposed ports, vulnerability density, and graph centrality.<br/><br/>
        <b>Risk Score: {score}/100</b> ({risk_label})<br/>
        <i>Source: {source} Engine</i>
        """
        
        self.elements.append(Paragraph(summary_text, self.styles['BodyText']))
        self.elements.append(Spacer(1, 20))

    def _add_findings_table(self, scan_data):
        self.elements.append(Paragraph("Detailed Findings", self.styles['Heading3']))
        
        # Extract findings from results blob
        results = scan_data.get("results", {})
        data = [["Scanner", "Severity", "Finding", "Details"]]
        
        # Flatten findings logic
        # 1. ThreatScanner (Vulnerabilities)
        threats = results.get("ThreatScanner", {}).get("vulnerabilities", [])
        for t in threats:
            rows = [
                "Vulnerability",
                t.get("severity", "Medium"),
                t.get("type", "Unknown Issue")[:30], # Truncate for table
                t.get("description", "")[:50] + "..."
            ]
            data.append(rows)
            
        # 2. PortScanner (Open Ports)
        ports = results.get("PortScanner", {}).get("open_ports", [])
        for p in ports:
            rows = [
                "Port Scan",
                "Info",
                f"Port {p}",
                "Open Service Detected"
            ]
            data.append(rows)

        # 3. CloudScanner (Buckets)
        buckets = results.get("CloudScanner", {}).get("buckets", [])
        for b in buckets:
            status = b.get("status", "Unknown")
            severity = "High" if status == "public" else "Info"
            rows = [
                "Cloud Hunter",
                severity,
                f"Bucket: {b.get('name')}",
                f"Status: {status}"
            ]
            data.append(rows)

        if len(data) == 1:
            data.append(["-", "-", "No findings detected", "-"])

        # Table Styling
        table = Table(data, colWidths=[1.2*inch, 0.8*inch, 2.5*inch, 2.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")), # Dark Header
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        self.elements.append(table)
        self.elements.append(Spacer(1, 20))

    def _add_footer_disclaimer(self):
        text = """
        <b>Disclaimer:</b> This report is generated automatically by Netra Vortex. 
        False positives are possible. Verify all findings manually before taking action.
        """
        style = ParagraphStyle('Disclaimer', parent=self.styles['Normal'], fontSize=8, textColor=colors.gray)
        self.elements.append(Paragraph(text, style))

def create_scan_pdf(scan_data: dict) -> bytes:
    buffer = BytesIO()
    generator = PDFReportGenerator(buffer)
    generator.generate(scan_data)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
