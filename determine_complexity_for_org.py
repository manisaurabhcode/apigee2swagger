"""
Integration Example: Adding Complexity Analysis to Your Existing Proxy Analysis Script
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List
from complexity_analyzer_v1 import ComplexityAnalyzer, ProxyComplexityReport


# ==================== INTEGRATION WITH YOUR EXISTING CODE ====================

def analyze_all_proxies_with_complexity(base_dir: str, output_dir: str):
    """
    Integrate complexity analysis into your existing proxy analysis workflow
    
    Args:
        base_dir: Base directory containing exported proxies
        output_dir: Directory to save complexity reports
    """
    
    logging.info("Starting proxy complexity analysis for all proxies")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize complexity analyzer
    analyzer = ComplexityAnalyzer()
    
    # Store all reports
    all_reports = []
    summary_stats = {
        "total_proxies": 0,
        "simple_proxies": 0,
        "medium_proxies": 0,
        "complex_proxies": 0,
        "total_red_flags": 0
    }
    
    # Iterate through organizations
    print(base_dir)
    for org in os.listdir(base_dir):
        org_dir = os.path.join(base_dir, org)
        
        if not os.path.isdir(org_dir):
            continue
        
        logging.info(f"Processing organization: {org}")
        
        # Loop through each environment
        for env in os.listdir(org_dir):
            env_path = os.path.join(org_dir, env)
            proxy_path = os.path.join(env_path, 'proxies')
            print(proxy_path)
            
            if not os.path.exists(proxy_path):
                continue
            
            logging.info(f"  Processing environment: {env}")
            
            # Analyze each proxy
            for proxy_folder in os.listdir(proxy_path):
                proxy_full_path = os.path.join(proxy_path, proxy_folder)
                
                if not os.path.isdir(proxy_full_path):
                    continue
                
                apiproxy_path = os.path.join(proxy_full_path, 'apiproxy')
                
                if not os.path.exists(apiproxy_path):
                    logging.warning(f"    Skipping {proxy_folder} - no apiproxy folder")
                    continue
                
                try:
                    # Run complexity analysis
                    logging.info(f"    Analyzing: {proxy_folder}")
                    report = analyzer.analyze_proxy_complexity(
                        proxy_full_path, 
                        proxy_folder
                    )
                    #input()
                    
                    # Update statistics
                    summary_stats["total_proxies"] += 1
                    print("summartstat:",summary_stats)
                    if report.complexity_level == "Simple":
                        summary_stats["simple_proxies"] += 1
                    elif report.complexity_level == "Medium":
                        summary_stats["medium_proxies"] += 1
                    else:
                        summary_stats["complex_proxies"] += 1
                    
                    summary_stats["total_red_flags"] += len(report.red_flags)
                    
                    # Add context
                    report_dict = {
                        "organization": org,
                        "environment": env,
                        "proxy_name": proxy_folder,
                        "total_score": report.total_score,
                        "complexity_level": report.complexity_level,
                        "migration_strategy": report.migration_strategy,
                        "red_flags": report.red_flags,
                        "summary": report.summary,
                        "top_concerns": report.detailed_analysis.get('top_concerns', []),
                        "quick_wins": report.detailed_analysis.get('quick_wins', [])
                    }
                    
                    all_reports.append(report_dict)
                    
                    # Export individual reports
                    json_output = os.path.join(
                        output_dir, 
                        f"{proxy_folder}_complexity.json"
                    )
                    analyzer.export_report_json(report, json_output)
                    
                    html_output = os.path.join(
                        output_dir, 
                        f"{proxy_folder}_complexity.html"
                    )
                    analyzer.export_report_html(report, html_output)
                    
                except Exception as e:
                    logging.error(f"    Error analyzing {proxy_folder}: {e}")
                    continue
    
    # Generate master summary report
    master_report = {
        "summary_statistics": summary_stats,
        "proxy_reports": all_reports,
        "migration_recommendations": generate_migration_recommendations(all_reports)
    }
    
    # Save master report
    master_json = os.path.join(output_dir, "complexity_master_report.json")
    with open(master_json, 'w') as f:
        json.dump(master_report, f, indent=4)
    
    # Generate master HTML report
    generate_master_html_report(master_report, output_dir)
    
    # Print summary to console
    print_summary(summary_stats, all_reports)
    
    logging.info(f"Complexity analysis complete. Analyzed {summary_stats['total_proxies']} proxies")
    
    return master_report


def generate_migration_recommendations(reports: List[Dict]) -> Dict:
    """Generate migration recommendations based on all proxy analyses"""
    
    simple_proxies = [r for r in reports if r['complexity_level'] == 'Simple']
    medium_proxies = [r for r in reports if r['complexity_level'] == 'Medium']
    complex_proxies = [r for r in reports if r['complexity_level'] == 'Complex']
    
    # Sort by score within each category
    simple_proxies.sort(key=lambda x: x['total_score'])
    medium_proxies.sort(key=lambda x: x['total_score'])
    complex_proxies.sort(key=lambda x: x['total_score'], reverse=True)
    
    recommendations = {
        "phase_1_automated": {
            "description": "Simple proxies suitable for automated migration",
            "proxy_count": len(simple_proxies),
            "proxies": [
                {
                    "name": p['proxy_name'],
                    "score": p['total_score'],
                    "org": p['organization'],
                    "env": p['environment']
                } for p in simple_proxies
            ],
            "estimated_effort": "Low - Use automated migration tools",
            "priority": "High - Quick wins",
            "timeline": f"{len(simple_proxies) * 0.5} days (0.5 day per proxy)"
        },
        "phase_2_semi_automated": {
            "description": "Medium complexity proxies requiring manual review",
            "proxy_count": len(medium_proxies),
            "proxies": [
                {
                    "name": p['proxy_name'],
                    "score": p['total_score'],
                    "org": p['organization'],
                    "env": p['environment'],
                    "concerns": p.get('top_concerns', [])[:3]
                } for p in medium_proxies
            ],
            "estimated_effort": "Medium - Automated with manual review",
            "priority": "Medium - Iterative approach",
            "timeline": f"{len(medium_proxies) * 2} days (2 days per proxy)"
        },
        "phase_3_manual": {
            "description": "Complex proxies requiring manual migration",
            "proxy_count": len(complex_proxies),
            "proxies": [
                {
                    "name": p['proxy_name'],
                    "score": p['total_score'],
                    "org": p['organization'],
                    "env": p['environment'],
                    "red_flags": p.get('red_flags', [])[:5]
                } for p in complex_proxies
            ],
            "estimated_effort": "High - Manual analysis and implementation",
            "priority": "Plan carefully - May require redesign",
            "timeline": f"{len(complex_proxies) * 5} days (5 days per proxy)"
        }
    }
    
    # Identify proxies with specific red flags
    java_callout_proxies = [
        {"name": r['proxy_name'], "org": r['organization'], "score": r['total_score']}
        for r in reports 
        if any('Java callout' in flag for flag in r.get('red_flags', []))
    ]
    
    python_proxies = [
        {"name": r['proxy_name'], "org": r['organization'], "score": r['total_score']}
        for r in reports 
        if any('Python' in flag for flag in r.get('red_flags', []))
    ]
    
    xslt_proxies = [
        {"name": r['proxy_name'], "org": r['organization'], "score": r['total_score']}
        for r in reports 
        if any('XSLT' in flag for flag in r.get('red_flags', []))
    ]
    
    large_js_proxies = [
        {"name": r['proxy_name'], "org": r['organization'], "score": r['total_score']}
        for r in reports 
        if any('JavaScript' in flag and 'lines' in flag for flag in r.get('red_flags', []))
    ]
    
    recommendations["special_attention"] = {
        "java_callouts": {
            "count": len(java_callout_proxies),
            "proxies": java_callout_proxies,
            "action": "Requires Java logic reimplementation",
            "effort": "High - 3-5 days per proxy"
        },
        "python_scripts": {
            "count": len(python_proxies),
            "proxies": python_proxies,
            "action": "Convert to native policies or serverless functions",
            "effort": "High - 2-4 days per proxy"
        },
        "xslt_transforms": {
            "count": len(xslt_proxies),
            "proxies": xslt_proxies,
            "action": "XSLT requires specialized transformation logic",
            "effort": "High - 3-5 days per proxy"
        },
        "large_javascript": {
            "count": len(large_js_proxies),
            "proxies": large_js_proxies,
            "action": "Large JavaScript codebase needs careful migration",
            "effort": "Medium - 2-3 days per proxy"
        }
    }
    
    # Calculate total effort
    total_days = (
        len(simple_proxies) * 0.5 +
        len(medium_proxies) * 2 +
        len(complex_proxies) * 5
    )
    
    recommendations["overall_estimate"] = {
        "total_proxies": len(reports),
        "estimated_days": round(total_days, 1),
        "estimated_weeks": round(total_days / 5, 1),
        "recommended_team_size": max(2, round(total_days / 60)),  # Assume 3 months project
        "critical_dependencies": len(java_callout_proxies) + len(python_proxies) + len(xslt_proxies)
    }
    
    return recommendations


def generate_master_html_report(master_report: Dict, output_dir: str):
    """Generate a master HTML report with all proxies"""
    
    stats = master_report['summary_statistics']
    recommendations = master_report['migration_recommendations']
    reports = master_report['proxy_reports']
    
    # Calculate percentages
    total = stats['total_proxies']
    simple_pct = (stats['simple_proxies'] / total * 100) if total > 0 else 0
    medium_pct = (stats['medium_proxies'] / total * 100) if total > 0 else 0
    complex_pct = (stats['complex_proxies'] / total * 100) if total > 0 else 0
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Master Complexity Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #1976D2; border-bottom: 3px solid #1976D2; padding-bottom: 10px; margin-top: 0; }}
        h2 {{ color: #424242; margin-top: 40px; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; }}
        .dashboard {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }}
        .card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 8px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .card.simple {{ background: linear-gradient(135deg, #4CAF50 0%, #66BB6A 100%); }}
        .card.medium {{ background: linear-gradient(135deg, #FF9800 0%, #FFA726 100%); }}
        .card.complex {{ background: linear-gradient(135deg, #F44336 0%, #EF5350 100%); }}
        .card h2 {{ margin: 0; font-size: 48px; font-weight: bold; }}
        .card p {{ margin: 10px 0 0 0; font-size: 14px; opacity: 0.9; }}
        .card .percentage {{ font-size: 18px; margin-top: 5px; font-weight: bold; }}
        .phase {{ background: #f9f9f9; padding: 20px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #2196F3; }}
        .phase h3 {{ margin-top: 0; color: #1976D2; }}
        .proxy-list {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 15px; }}
        .proxy-item {{ background: white; padding: 12px; border-radius: 4px; border: 1px solid #e0e0e0; font-size: 14px; }}
        .proxy-item .name {{ font-weight: bold; color: #1976D2; }}
        .proxy-item .score {{ color: #757575; font-size: 12px; }}
        .alert {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }}
        .alert.danger {{ background: #ffebee; border-left-color: #f44336; }}
        .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; }}
        .metric .value {{ font-size: 32px; font-weight: bold; color: #1976D2; }}
        .metric .label {{ color: #757575; font-size: 14px; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
        th {{ background: #f5f5f5; font-weight: bold; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .badge-simple {{ background: #4CAF50; color: white; }}
        .badge-medium {{ background: #FF9800; color: white; }}
        .badge-complex {{ background: #F44336; color: white; }}
        .timeline {{ margin: 20px 0; }}
        .timeline-item {{ display: flex; gap: 20px; margin: 15px 0; padding: 15px; background: #f9f9f9; border-radius: 5px; }}
        .timeline-item .phase-number {{ background: #1976D2; color: white; width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0; }}
        .timeline-item .content {{ flex: 1; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Master Complexity Analysis Report</h1>
        <p style="color: #757575; font-size: 16px;">Comprehensive analysis of all API proxies for migration planning</p>
        
        <div class="dashboard">
            <div class="card">
                <h2>{stats['total_proxies']}</h2>
                <p>Total Proxies Analyzed</p>
            </div>
            <div class="card simple">
                <h2>{stats['simple_proxies']}</h2>
                <p>Simple Proxies</p>
                <div class="percentage">{simple_pct:.1f}%</div>
            </div>
            <div class="card medium">
                <h2>{stats['medium_proxies']}</h2>
                <p>Medium Proxies</p>
                <div class="percentage">{medium_pct:.1f}%</div>
            </div>
            <div class="card complex">
                <h2>{stats['complex_proxies']}</h2>
                <p>Complex Proxies</p>
                <div class="percentage">{complex_pct:.1f}%</div>
            </div>
        </div>
        
        <h2>📊 Overall Migration Estimate</h2>
        <div class="metrics">
            <div class="metric">
                <div class="value">{recommendations['overall_estimate']['estimated_days']}</div>
                <div class="label">Estimated Days</div>
            </div>
            <div class="metric">
                <div class="value">{recommendations['overall_estimate']['estimated_weeks']}</div>
                <div class="label">Estimated Weeks</div>
            </div>
            <div class="metric">
                <div class="value">{recommendations['overall_estimate']['recommended_team_size']}</div>
                <div class="label">Recommended Team Size</div>
            </div>
        </div>
        
        <h2>🚀 Migration Timeline</h2>
        <div class="timeline">
            <div class="timeline-item">
                <div class="phase-number">1</div>
                <div class="content">
                    <h3>Phase 1: Automated Migration</h3>
                    <p><strong>{recommendations['phase_1_automated']['proxy_count']} proxies</strong> - {recommendations['phase_1_automated']['description']}</p>
                    <p><strong>Timeline:</strong> {recommendations['phase_1_automated']['timeline']}</p>
                    <p><strong>Effort:</strong> {recommendations['phase_1_automated']['estimated_effort']}</p>
                </div>
            </div>
            <div class="timeline-item">
                <div class="phase-number">2</div>
                <div class="content">
                    <h3>Phase 2: Semi-Automated Migration</h3>
                    <p><strong>{recommendations['phase_2_semi_automated']['proxy_count']} proxies</strong> - {recommendations['phase_2_semi_automated']['description']}</p>
                    <p><strong>Timeline:</strong> {recommendations['phase_2_semi_automated']['timeline']}</p>
                    <p><strong>Effort:</strong> {recommendations['phase_2_semi_automated']['estimated_effort']}</p>
                </div>
            </div>
            <div class="timeline-item">
                <div class="phase-number">3</div>
                <div class="content">
                    <h3>Phase 3: Manual Migration</h3>
                    <p><strong>{recommendations['phase_3_manual']['proxy_count']} proxies</strong> - {recommendations['phase_3_manual']['description']}</p>
                    <p><strong>Timeline:</strong> {recommendations['phase_3_manual']['timeline']}</p>
                    <p><strong>Effort:</strong> {recommendations['phase_3_manual']['estimated_effort']}</p>
                </div>
            </div>
        </div>
        
        <h2>⚠️ Special Attention Required</h2>
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px;">
    """
    
    # Add special attention items
    for key, data in recommendations['special_attention'].items():
        if data['count'] > 0:
            html += f"""
            <div class="alert danger">
                <h4 style="margin-top: 0;">{key.replace('_', ' ').title()} ({data['count']} proxies)</h4>
                <p><strong>Action:</strong> {data['action']}</p>
                <p><strong>Effort:</strong> {data['effort']}</p>
                <ul style="margin: 10px 0;">
            """
            for proxy in data['proxies'][:5]:
                html += f"<li>{proxy['name']} (Score: {proxy['score']})</li>"
            if len(data['proxies']) > 5:
                html += f"<li>...and {len(data['proxies']) - 5} more</li>"
            html += "</ul></div>"
    
    html += """
        </div>
        
        <h2>📋 Complete Proxy Inventory</h2>
        <table>
            <thead>
                <tr>
                    <th>Proxy Name</th>
                    <th>Organization</th>
                    <th>Environment</th>
                    <th>Score</th>
                    <th>Complexity</th>
                    <th>Red Flags</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Sort reports by score (descending)
    sorted_reports = sorted(reports, key=lambda x: x['total_score'], reverse=True)
    
    for report in sorted_reports:
        badge_class = f"badge-{report['complexity_level'].lower()}"
        html += f"""
            <tr>
                <td><strong>{report['proxy_name']}</strong></td>
                <td>{report['organization']}</td>
                <td>{report['environment']}</td>
                <td>{report['total_score']}</td>
                <td><span class="badge {badge_class}">{report['complexity_level']}</span></td>
                <td>{len(report['red_flags'])}</td>
            </tr>
        """
    
    html += """
            </tbody>
        </table>
        
        <div style="margin-top: 40px; padding: 20px; background: #e3f2fd; border-radius: 5px;">
            <h3 style="margin-top: 0;">📌 Next Steps</h3>
            <ol>
                <li>Review individual proxy complexity reports (HTML files)</li>
                <li>Prioritize Phase 1 proxies for quick wins</li>
                <li>Plan resources for Phase 2 and Phase 3 migrations</li>
                <li>Address special attention items (Java callouts, Python, XSLT)</li>
                <li>Set up migration tooling and testing environments</li>
            </ol>
        </div>
    </div>
</body>
</html>
    """
    
    output_path = os.path.join(output_dir, "master_complexity_report.html")
    with open(output_path, 'w') as f:
        f.write(html)
    
    logging.info(f"Master HTML report generated: {output_path}")


def print_summary(stats: Dict, reports: List[Dict]):
    """Print summary to console"""
    
    print("\n" + "="*80)
    print("COMPLEXITY ANALYSIS SUMMARY".center(80))
    print("="*80)
    print(f"\nTotal Proxies Analyzed: {stats['total_proxies']}")
    print(f"  ✅ Simple (Automated):  {stats['simple_proxies']:3d} ({stats['simple_proxies']/stats['total_proxies']*100:5.1f}%)")
    print(f"  ⚠️  Medium (Semi-Auto):  {stats['medium_proxies']:3d} ({stats['medium_proxies']/stats['total_proxies']*100:5.1f}%)")
    print(f"  🔴 Complex (Manual):    {stats['complex_proxies']:3d} ({stats['complex_proxies']/stats['total_proxies']*100:5.1f}%)")
    print(f"\nTotal Red Flags: {stats['total_red_flags']}")
    
    # Show top 5 most complex
    sorted_reports = sorted(reports, key=lambda x: x['total_score'], reverse=True)
    print("\nTop 5 Most Complex Proxies:")
    for i, report in enumerate(sorted_reports[:5], 1):
        print(f"  {i}. {report['proxy_name']:30s} - Score: {report['total_score']:3d} ({report['complexity_level']})")
    
    # Show red flag summary
    all_red_flags = {}
    for report in reports:
        for flag in report.get('red_flags', []):
            flag_type = flag.split(':')[0]
            all_red_flags[flag_type] = all_red_flags.get(flag_type, 0) + 1
    
    if all_red_flags:
        print("\nRed Flag Summary:")
        for flag_type, count in sorted(all_red_flags.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {flag_type}: {count}")
    
    print("\n" + "="*80 + "\n")


# ==================== STANDALONE USAGE ====================

if __name__ == "__main__":
    """
    Example standalone usage
    """
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('complexity_analysis.log'),
            logging.StreamHandler()
        ]
    )
    
    # Configuration
    BASE_EXPORT_DIR = "/workspaces/codespaces-blank/apigee2openapi/apigee-proxy"
    OUTPUT_DIR = "/workspaces/codespaces-blank/apigee2openapi/tmp"
    
    # Run analysis
    print("Starting complexity analysis...")
    master_report = analyze_all_proxies_with_complexity(BASE_EXPORT_DIR, OUTPUT_DIR)
    
    print(f"\n✅ Analysis complete!")
    print(f"📁 Reports saved to: {OUTPUT_DIR}")
    print(f"📊 Master report: {os.path.join(OUTPUT_DIR, 'master_complexity_report.html')}")
    print(f"📋 JSON summary: {os.path.join(OUTPUT_DIR, 'complexity_master_report.json')}")