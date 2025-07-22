package reporting

import (
	"fmt"
	"html/template"
	"strings"
)

func (rg *ReportGenerator) initializeTemplate() error {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberRaven Security Assessment Report</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --critical-color: #8e44ad;
            --light-bg: #f8f9fa;
            --border-color: #dee2e6;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --shadow: 0 4px 12px rgba(0,0,0,0.1);
            --border-radius: 8px;
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.15);
            overflow: hidden;
            animation: fadeIn 0.6s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, #34495e 100%);
            color: white;
            padding: 60px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 20"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/></pattern></defs><rect width="100" height="20" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }
        
        .header-content {
            position: relative;
            z-index: 1;
        }

        .header h1 {
            font-size: 3.5em;
            font-weight: 700;
            margin-bottom: 15px;
            text-shadow: 2px 2px 8px rgba(0,0,0,0.3);
            letter-spacing: -0.02em;
        }

        .header .subtitle {
            font-size: 1.4em;
            opacity: 0.9;
            margin-bottom: 25px;
            font-weight: 300;
        }
        
        .header .meta {
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
            font-size: 1em;
            opacity: 0.8;
        }

        .meta-item {
            background: rgba(255,255,255,0.1);
            padding: 8px 16px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }
        
        .content {
            padding: 50px;
        }

        .section {
            margin-bottom: 50px;
            animation: slideIn 0.6s ease-out;
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .section-header {
            display: flex;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--border-color);
        }

        .section-icon {
            width: 40px;
            height: 40px;
            margin-right: 15px;
            background: var(--secondary-color);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.2em;
        }

        .section h2 {
            color: var(--primary-color);
            font-size: 2em;
            font-weight: 600;
            margin: 0;
        }
        
        .executive-summary {
            background: linear-gradient(135deg, var(--light-bg) 0%, #e9ecef 100%);
            padding: 40px;
            border-radius: var(--border-radius);
            margin-bottom: 40px;
            border-left: 6px solid var(--secondary-color);
            box-shadow: var(--shadow);
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }
        
        .metric-card {
            background: white;
            padding: 30px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            text-align: center;
            border-top: 4px solid var(--secondary-color);
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            transition: left 0.5s;
        }

        .metric-card:hover::before {
            left: 100%;
        }

        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }
        
        .metric-value {
            font-size: 3em;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 10px;
            position: relative;
        }
        
        .metric-label {
            font-size: 0.9em;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 500;
        }

        .risk-level {
            display: inline-flex;
            align-items: center;
            padding: 12px 24px;
            border-radius: 25px;
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
            box-shadow: var(--shadow);
        }

        .risk-level::before {
            content: '●';
            margin-right: 8px;
            font-size: 1.2em;
        }
        
        .risk-critical { 
            background: linear-gradient(135deg, var(--critical-color), #c0392b);
        }
        .risk-high { 
            background: linear-gradient(135deg, var(--danger-color), #c0392b);
        }
        .risk-medium { 
            background: linear-gradient(135deg, var(--warning-color), #e67e22);
        }
        .risk-low { 
            background: linear-gradient(135deg, var(--warning-color), #f1c40f);
            color: var(--text-primary);
        }
        .risk-minimal { 
            background: linear-gradient(135deg, var(--success-color), #229954);
        }
        
        .vulnerability-grid {
            display: grid;
            gap: 20px;
            margin: 30px 0;
        }
        
        .vulnerability-item {
            background: white;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: 25px;
            border-left: 5px solid var(--danger-color);
            box-shadow: var(--shadow);
            transition: var(--transition);
        }

        .vulnerability-item:hover {
            transform: translateX(5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .vulnerability-item.critical { border-left-color: var(--critical-color); }
        .vulnerability-item.high { border-left-color: var(--danger-color); }
        .vulnerability-item.medium { border-left-color: var(--warning-color); }
        .vulnerability-item.low { border-left-color: #f1c40f; }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .vulnerability-title {
            font-weight: 600;
            color: var(--primary-color);
            font-size: 1.1em;
            flex: 1;
            margin-right: 20px;
        }

        .severity-badge {
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-critical { background: #f8d7da; color: #721c24; }
        .severity-high { background: #f8d7da; color: #721c24; }
        .severity-medium { background: #fff3cd; color: #856404; }
        .severity-low { background: #d4edda; color: #155724; }
        
        .vulnerability-details {
            color: var(--text-secondary);
            line-height: 1.7;
        }

        .detail-row {
            display: grid;
            grid-template-columns: 120px 1fr;
            margin: 8px 0;
            align-items: start;
        }

        .detail-label {
            font-weight: 600;
            color: var(--primary-color);
        }

        .detail-value {
            word-break: break-word;
        }

        .risk-score {
            display: inline-flex;
            align-items: center;
            background: var(--light-bg);
            padding: 4px 12px;
            border-radius: 15px;
            font-weight: 600;
            font-size: 0.9em;
        }

        .risk-score::before {
            content: '⚡';
            margin-right: 5px;
        }
        
        .recommendations-grid {
            display: grid;
            gap: 25px;
            margin: 30px 0;
        }
        
        .recommendation-item {
            background: white;
            border-radius: var(--border-radius);
            padding: 30px;
            border-left: 6px solid var(--secondary-color);
            box-shadow: var(--shadow);
            transition: var(--transition);
        }

        .recommendation-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }

        .recommendation-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .recommendation-title {
            font-weight: 600;
            color: var(--primary-color);
            font-size: 1.2em;
        }

        .priority-badge {
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }

        .priority-critical { background: #f8d7da; color: #721c24; }
        .priority-high { background: #f8d7da; color: #721c24; }
        .priority-medium { background: #fff3cd; color: #856404; }
        .priority-low { background: #d4edda; color: #155724; }
        
        .actions-list {
            margin: 20px 0;
            padding-left: 0;
            list-style: none;
        }

        .actions-list li {
            position: relative;
            padding: 8px 0 8px 25px;
            border-bottom: 1px solid var(--border-color);
        }

        .actions-list li:last-child {
            border-bottom: none;
        }

        .actions-list li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: var(--success-color);
            font-weight: bold;
        }

        .performance-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }

        .performance-card {
            text-align: center;
            padding: 25px;
            background: white;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            border-top: 4px solid var(--secondary-color);
        }

        .performance-value {
            font-size: 2.2em;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 8px;
        }

        .performance-label {
            color: var(--text-secondary);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 500;
        }

        /* Module Analysis Styles */
        .modules-overview {
            margin: 20px 0;
        }

        .modules-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .module-card {
            background: white;
            border-radius: var(--border-radius);
            padding: 18px;
            box-shadow: var(--shadow);
            border-left: 4px solid var(--secondary-color);
            transition: var(--transition);
        }

        .module-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
        }

        .module-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }

        .module-header h3 {
            color: var(--primary-color);
            font-size: 1.1em;
            font-weight: 600;
            margin: 0;
        }

        .module-stats {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .stat-item {
            font-size: 0.8em;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .module-metrics {
            margin-bottom: 15px;
        }

        .metric-row {
            display: flex;
            justify-content: space-between;
            margin: 4px 0;
            padding: 3px 0;
            border-bottom: 1px solid #f5f5f5;
            font-size: 0.9em;
        }

        .metric-row:last-child {
            border-bottom: none;
        }

        .metric-label {
            font-weight: 500;
            color: var(--text-secondary);
        }

        .metric-value {
            font-weight: 600;
            color: var(--primary-color);
        }

        .module-toggle {
            width: 100%;
            padding: 8px 12px;
            background: var(--secondary-color);
            color: white;
            border: none;
            border-radius: var(--border-radius);
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9em;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: var(--transition);
        }

        .module-toggle:hover {
            background: #2980b9;
        }

        .toggle-icon {
            transition: transform 0.3s ease;
            font-size: 0.8em;
        }

        .toggle-icon.rotated {
            transform: rotate(180deg);
        }

        .module-details {
            background: var(--light-bg);
            border-radius: var(--border-radius);
            padding: 20px;
            margin: 15px 0;
            border: 1px solid var(--border-color);
            animation: slideDown 0.3s ease-out;
        }

        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .module-details-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }

        .module-details-header h3 {
            color: var(--primary-color);
            font-size: 1.2em;
            margin: 0;
        }

        .close-module {
            background: var(--danger-color);
            color: white;
            border: none;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            cursor: pointer;
            font-size: 1em;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: var(--transition);
        }

        .close-module:hover {
            background: #c0392b;
            transform: scale(1.1);
        }

        /* Vulnerability items dans les modules - plus compacts */
        .module-details .vulnerability-item {
            padding: 15px;
            margin-bottom: 10px;
        }

        .module-details .vulnerability-header {
            margin-bottom: 10px;
        }

        .module-details .vulnerability-title {
            font-size: 1em;
        }

        .module-details .detail-row {
            margin: 5px 0;
            font-size: 0.9em;
        }

        .no-vulnerabilities {
            text-align: center;
            padding: 25px;
        }

        .success-message {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(39, 174, 96, 0.1);
            padding: 12px 20px;
            border-radius: 20px;
            color: var(--success-color);
            font-weight: 600;
            font-size: 0.9em;
        }

        .success-icon {
            font-size: 1.1em;
        }

        .top-issues-note {
            background: rgba(52, 152, 219, 0.1);
            padding: 15px;
            border-radius: var(--border-radius);
            margin-bottom: 20px;
            border-left: 4px solid var(--secondary-color);
        }

        .top-issues-note p {
            margin: 0;
            color: var(--text-secondary);
            font-style: italic;
            font-size: 0.9em;
        }

        .reference-link {
            color: var(--secondary-color);
            text-decoration: none;
            margin-right: 10px;
            font-size: 1.1em;
            transition: var(--transition);
        }

        .reference-link:hover {
            color: var(--primary-color);
            transform: scale(1.2);
        }
        
        .footer {
            background: var(--primary-color);
            color: white;
            text-align: center;
            padding: 30px;
            font-size: 0.9em;
        }

        .footer-content {
            max-width: 600px;
            margin: 0 auto;
        }

        .powered-by {
            opacity: 0.8;
            margin-top: 10px;
        }

        .module-details .vulnerability-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 20px 0;
        }

        /* Vulnerability items dans les modules - plus compacts pour 2 colonnes */
        .module-details .vulnerability-item {
            padding: 12px;
            margin-bottom: 0;
            font-size: 0.9em;
        }

        .module-details .vulnerability-header {
            margin-bottom: 8px;
        }

        .module-details .vulnerability-title {
            font-size: 0.95em;
            line-height: 1.3;
        }

        .module-details .severity-badge {
            padding: 4px 8px;
            font-size: 0.7em;
        }

        .module-details .detail-row {
            margin: 4px 0;
            font-size: 0.85em;
            grid-template-columns: 80px 1fr;
        }

        .module-details .detail-label {
            font-size: 0.8em;
        }

        .module-details .risk-score {
            padding: 2px 8px;
            font-size: 0.8em;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .content {
                padding: 30px 20px;
            }

            .header {
                padding: 40px 20px;
            }

            .header h1 {
                font-size: 2.5em;
            }

            .header .meta {
                flex-direction: column;
                gap: 15px;
            }

            .metrics-grid {
                grid-template-columns: 1fr;
            }

            .detail-row {
                grid-template-columns: 1fr;
                gap: 5px;
            }

            .vulnerability-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .recommendation-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .module-details .vulnerability-grid {
                grid-template-columns: 1fr;
            }
            
            .module-details .detail-row {
                grid-template-columns: 1fr;
                gap: 2px;
            }
        }

        @media (min-width: 1600px) {
            .module-details .vulnerability-grid {
                grid-template-columns: 1fr 1fr 1fr;
            }
        }

        /* Print Styles */
        @media print {
            body {
                background: white;
                padding: 0;
            }

            .container {
                box-shadow: none;
                border-radius: 0;
            }

            .header {
                background: var(--primary-color) !important;
                print-color-adjust: exact;
            }

            .metric-card, .vulnerability-item, .recommendation-item {
                break-inside: avoid;
                box-shadow: none;
                border: 1px solid var(--border-color);
            }
        }
    </style>
    <script>
        // Module toggle functionality
        function toggleModule(moduleKey) {
            const moduleDetails = document.getElementById('module-' + moduleKey);
            const toggleButton = document.querySelector('[onclick="toggleModule(\'' + moduleKey + '\')"]');
            const toggleIcon = toggleButton.querySelector('.toggle-icon');
            const toggleText = toggleButton.querySelector('.toggle-text');
            
            if (moduleDetails.style.display === 'none' || moduleDetails.style.display === '') {
                moduleDetails.style.display = 'block';
                toggleIcon.classList.add('rotated');
                toggleText.textContent = 'Hide Details';
                toggleButton.style.background = '#e67e22';
                
                // Smooth scroll to module details
                setTimeout(() => {
                    moduleDetails.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            } else {
                moduleDetails.style.display = 'none';
                toggleIcon.classList.remove('rotated');
                toggleText.textContent = 'View Details';
                toggleButton.style.background = '#3498db';
            }
        }

        // Add smooth scrolling for all internal links
        document.addEventListener('DOMContentLoaded', function() {
            // Add fade-in animation for cards on scroll
            const observerOptions = {
                threshold: 0.1,
                rootMargin: '0px 0px -50px 0px'
            };

            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.style.opacity = '1';
                        entry.target.style.transform = 'translateY(0)';
                    }
                });
            }, observerOptions);

            // Observe all cards
            const cards = document.querySelectorAll('.metric-card, .vulnerability-item, .recommendation-item, .module-card');
            cards.forEach(card => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
                observer.observe(card);
            });

            // Add hover effect for severity badges
            const severityBadges = document.querySelectorAll('.severity-badge');
            severityBadges.forEach(badge => {
                badge.addEventListener('mouseenter', function() {
                    this.style.transform = 'scale(1.1)';
                });
                badge.addEventListener('mouseleave', function() {
                    this.style.transform = 'scale(1)';
                });
            });

            // Add click effect for buttons
            const buttons = document.querySelectorAll('.module-toggle, .close-module');
            buttons.forEach(button => {
                button.addEventListener('click', function(e) {
                    const ripple = document.createElement('span');
                    ripple.style.position = 'absolute';
                    ripple.style.borderRadius = '50%';
                    ripple.style.transform = 'scale(0)';
                    ripple.style.animation = 'ripple 0.6s linear';
                    ripple.style.background = 'rgba(255,255,255,0.7)';
                    
                    const rect = this.getBoundingClientRect();
                    const size = Math.max(rect.width, rect.height);
                    ripple.style.width = ripple.style.height = size + 'px';
                    ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
                    ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';
                    
                    this.style.position = 'relative';
                    this.style.overflow = 'hidden';
                    this.appendChild(ripple);
                    
                    setTimeout(() => {
                        ripple.remove();
                    }, 600);
                });
            });
        });

        // Add ripple animation
        const style = document.createElement('style');
style.textContent = '@keyframes ripple { to { transform: scale(4); opacity: 0; } }';
document.head.appendChild(style);
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>🐦‍⚡ CYBERRAVEN</h1>
                <div class="subtitle">Professional Security Assessment Report</div>
                <div class="meta">
                    <div class="meta-item">📅 {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</div>
                    <div class="meta-item">🆔 {{.SessionData.SessionID}}</div>
                    <div class="meta-item">🎯 {{.SessionData.Target.BaseURL}}</div>
                    <div class="meta-item">⏱️ {{.SessionData.Duration.Round 1000000}}</div>
                </div>
            </div>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <div class="section-header">
                    <div class="section-icon">📊</div>
                    <h2>Executive Summary</h2>
                </div>
                <div class="executive-summary">
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value">{{.ExecutiveSummary.SecurityScore}}/100</div>
                            <div class="metric-label">Security Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{{.ExecutiveSummary.TotalIssuesFound}}</div>
                            <div class="metric-label">Issues Found</div>
                        </div>
                        <!-- <div class="metric-card">
                            <div class="metric-value">{{printf "%.1f" .ExecutiveSummary.TestCoverage}}%</div>
                            <div class="metric-label">Test Coverage</div>
                        </div> -->
                        <div class="metric-card">
                            <div class="metric-value">{{.ExecutiveSummary.ComplianceScore}}/100</div>
                            <div class="metric-label">Compliance Score</div>
                        </div>
                    </div>
                    
                    <div style="margin: 30px 0;">
                        <strong>Overall Risk Level:</strong> 
                        <span class="risk-level risk-{{.ExecutiveSummary.OverallRiskLevel | lower}}">
                            {{.ExecutiveSummary.OverallRiskLevel}}
                        </span>
                    </div>
                    
                    {{if gt .ExecutiveSummary.TotalIssuesFound 0}}
                    <div style="margin-top: 25px;">
                        <strong>Issue Breakdown:</strong>
                        <div class="metrics-grid" style="margin-top: 15px;">
                            {{if gt .ExecutiveSummary.CriticalIssues 0}}
                            <div class="metric-card" style="border-top-color: var(--critical-color);">
                                <div class="metric-value" style="color: var(--critical-color);">{{.ExecutiveSummary.CriticalIssues}}</div>
                                <div class="metric-label">Critical</div>
                            </div>
                            {{end}}
                            {{if gt .SessionData.HighCount 0}}
                            <div class="metric-card" style="border-top-color: var(--danger-color);">
                                <div class="metric-value" style="color: var(--danger-color);">{{.SessionData.HighCount}}</div>
                                <div class="metric-label">High</div>
                            </div>
                            {{end}}
                            {{if gt .SessionData.MediumCount 0}}
                            <div class="metric-card" style="border-top-color: var(--warning-color);">
                                <div class="metric-value" style="color: var(--warning-color);">{{.SessionData.MediumCount}}</div>
                                <div class="metric-label">Medium</div>
                            </div>
                            {{end}}
                            {{if gt .SessionData.LowCount 0}}
                            <div class="metric-card" style="border-top-color: #f1c40f;">
                                <div class="metric-value" style="color: #f1c40f;">{{.SessionData.LowCount}}</div>
                                <div class="metric-label">Low</div>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            
            <!-- Module-Based Vulnerability Analysis -->
            {{if .VulnerabilityAnalysis.ModuleAnalysis}}
            <div class="section">
                <div class="section-header">
                    <div class="section-icon">🔍</div>
                    <h2>Security Analysis by Module</h2>
                </div>
                
                <div class="modules-overview">
                    <div class="modules-grid">
                        {{range $moduleKey, $module := .VulnerabilityAnalysis.ModuleAnalysis}}
                        <div class="module-card">
                            <div class="module-header">
                                <h3>{{$module.ModuleName}}</h3>
                                <div class="module-stats">
                                    <span class="stat-item">{{$module.VulnCount}} issues</span>
                                    {{if ne $module.HighestSeverity "none"}}
                                    <span class="severity-badge severity-{{$module.HighestSeverity}}">{{$module.HighestSeverity}}</span>
                                    {{end}}
                                </div>
                            </div>
                            <div class="module-metrics">
                                <div class="metric-row">
                                    <span class="metric-label">Tests:</span>
                                    <span class="metric-value">{{$module.TestsExecuted}}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Duration:</span>
                                    <span class="metric-value">{{$module.TestDuration.Round 1000000}}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">RPS:</span>
                                    <span class="metric-value">{{printf "%.1f" $module.RequestsPerSecond}}</span>
                                </div>
                            </div>
                            <button class="module-toggle" onclick="toggleModule('{{$moduleKey}}')">
                                <span class="toggle-text">View Details</span>
                                <span class="toggle-icon">▼</span>
                            </button>
                        </div>
                        {{end}}
                    </div>
                </div>

                <!-- Module Details (Collapsible) -->
                {{range $moduleKey, $module := .VulnerabilityAnalysis.ModuleAnalysis}}
                <div class="module-details" id="module-{{$moduleKey}}" style="display: none;">
                    <div class="module-details-header">
                        <h3>{{$module.ModuleName}} - Detailed Analysis</h3>
                        <button class="close-module" onclick="toggleModule('{{$moduleKey}}')">✕</button>
                    </div>
                    
                    {{if $module.Vulnerabilities}}
                    <div class="vulnerability-grid">
                        {{range $module.Vulnerabilities}}
                        <div class="vulnerability-item {{.Severity}}">
                            <div class="vulnerability-header">
                                <div class="vulnerability-title">{{.Description}}</div>
                                <div class="severity-badge severity-{{.Severity}}">{{.Severity}}</div>
                            </div>
                            <div class="vulnerability-details">
                                <div class="detail-row">
                                    <div class="detail-label">Endpoint:</div>
                                    <div class="detail-value"><code>{{.Method}} {{.Endpoint}}</code></div>
                                </div>
                                <div class="detail-row">
                                    <div class="detail-label">Risk Score:</div>
                                    <div class="detail-value"><span class="risk-score">{{.RiskScore}}/100</span></div>
                                </div>
                                <div class="detail-row">
                                    <div class="detail-label">Evidence:</div>
                                    <div class="detail-value">{{.Evidence}}</div>
                                </div>
                                <div class="detail-row">
                                    <div class="detail-label">Remediation:</div>
                                    <div class="detail-value">{{.Remediation}}</div>
                                </div>
                                {{if .References}}
                                <div class="detail-row">
                                    <div class="detail-label">References:</div>
                                    <div class="detail-value">
                                        {{range .References}}<a href="{{.}}" target="_blank" class="reference-link">📖</a> {{end}}
                                    </div>
                                </div>
                                {{end}}
                            </div>
                        </div>
                        {{end}}
                    </div>
                    {{else}}
                    <div class="no-vulnerabilities">
                        <div class="success-message">
                            <span class="success-icon">✅</span>
                            <span>No vulnerabilities found in this module</span>
                        </div>
                    </div>
                    {{end}}
                </div>
                {{end}}
            </div>
            {{end}}
            
            <!-- Top Issues Summary -->
            {{if .VulnerabilityAnalysis.TopIssues}}
            <div class="section">
                <div class="section-header">
                    <div class="section-icon">🎯</div>
                    <h2>Top Priority Issues</h2>
                </div>
                <div class="top-issues-note">
                    <p>The following are the highest-priority issues identified across all modules, sorted by risk score:</p>
                </div>
                <div class="vulnerability-grid">
                    {{range .VulnerabilityAnalysis.TopIssues}}
                    {{if ge .RiskScore 70}}
                    <div class="vulnerability-item {{.Severity}}">
                        <div class="vulnerability-header">
                            <div class="vulnerability-title">{{.Description}}</div>
                            <div class="severity-badge severity-{{.Severity}}">{{.Severity}}</div>
                        </div>
                        <div class="vulnerability-details">
                            <div class="detail-row">
                                <div class="detail-label">Endpoint:</div>
                                <div class="detail-value"><code>{{.Method}} {{.Endpoint}}</code></div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Risk Score:</div>
                                <div class="detail-value"><span class="risk-score">{{.RiskScore}}/100</span></div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Evidence:</div>
                                <div class="detail-value">{{.Evidence}}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Remediation:</div>
                                <div class="detail-value">{{.Remediation}}</div>
                            </div>
                        </div>
                    </div>
                    {{end}}
                    {{end}}
                </div>
            </div>
            {{end}}
            
            <!-- Security Recommendations -->
            {{if .Recommendations}}
            <div class="section">
                <div class="section-header">
                    <div class="section-icon">💡</div>
                    <h2>Security Recommendations</h2>
                </div>
                <div class="recommendations-grid">
                    {{range .Recommendations}}
                    <div class="recommendation-item">
                        <div class="recommendation-header">
                            <div class="recommendation-title">{{.Title}}</div>
                            <div class="priority-badge priority-{{.Priority}}">{{.Priority}} Priority</div>
                        </div>
                        <p style="margin: 15px 0; color: var(--text-secondary);">{{.Description}}</p>
                        <div class="detail-row">
                            <div class="detail-label">Category:</div>
                            <div class="detail-value">{{.Category | title}}</div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Effort:</div>
                            <div class="detail-value">{{.EstimatedEffort}}</div>
                        </div>
                        {{if .Actions}}
                        <div style="margin-top: 20px;">
                            <div class="detail-label">Action Items:</div>
                            <ul class="actions-list">
                                {{range .Actions}}<li>{{.}}</li>{{end}}
                            </ul>
                        </div>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
            
            <!-- Performance Metrics -->
            <div class="section">
                <div class="section-header">
                    <div class="section-icon">⚡</div>
                    <h2>Performance Metrics</h2>
                </div>
                <div class="performance-grid">
                    <div class="performance-card">
                        <div class="performance-value">{{.PerformanceMetrics.TotalRequestsSent}}</div>
                        <div class="performance-label">Total Requests</div>
                    </div>
                    <div class="performance-card">
                        <div class="performance-value">{{printf "%.1f" .PerformanceMetrics.RequestsPerSecond}}</div>
                        <div class="performance-label">Requests/Second</div>
                    </div>
                    <div class="performance-card">
                        <div class="performance-value">{{.PerformanceMetrics.AverageResponseTime.Round 1000000}}</div>
                        <div class="performance-label">Avg Response Time</div>
                    </div>
                    <div class="performance-card">
                        <div class="performance-value">{{printf "%.1f" .PerformanceMetrics.ErrorRate}}%</div>
                        <div class="performance-label">Error Rate</div>
                    </div>
                    <div class="performance-card">
                        <div class="performance-value">{{.PerformanceMetrics.ConcurrentConnections}}</div>
                        <div class="performance-label">Concurrent Connections</div>
                    </div>
                    <div class="performance-card">
                        <div class="performance-value">{{printf "%.1f" .PerformanceMetrics.TimeoutRate}}%</div>
                        <div class="performance-label">Timeout Rate</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <div class="footer-content">
                <div><strong>Report generated by CyberRaven v{{.CyberRavenVersion}}</strong></div>
                <div class="powered-by">Professional Security Assessment Tool | {{.GeneratedAt.Format "January 2, 2006"}}</div>
            </div>
        </div>
    </div>
</body>
</html>`

	// Parse template with custom functions
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"title": strings.Title,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	rg.template = tmpl
	return nil
}
