"""
Apigee Proxy Complexity Analyzer
Analyzes proxies based on 20 criteria and generates complexity scores
"""

import os
import re
import json
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum


class ComplexityLevel(Enum):
    """Complexity classification levels"""
    SIMPLE = "Simple"
    MEDIUM = "Medium"
    COMPLEX = "Complex"


@dataclass
class ComplexityScore:
    """Holds complexity scoring for a single criterion"""
    criterion_name: str
    raw_score: int  # 0-10
    weight: int  # 1, 2, or 3
    weighted_score: int
    level: str  # Simple, Medium, Complex
    details: Dict
    recommendations: List[str]


@dataclass
class ProxyComplexityReport:
    """Complete complexity analysis report for a proxy"""
    proxy_name: str
    total_score: int
    complexity_level: str
    migration_strategy: str
    criteria_scores: List[ComplexityScore]
    red_flags: List[str]
    summary: Dict
    detailed_analysis: Dict


class ComplexityAnalyzer:
    """Analyzes Apigee proxy complexity based on 20 criteria"""
    
    # Scoring thresholds
    SIMPLE_THRESHOLD = 100
    MEDIUM_THRESHOLD = 250
    
    # Weight multipliers
    HIGH_IMPACT = 3
    MEDIUM_IMPACT = 2
    LOW_IMPACT = 1
    
    def __init__(self, config_manager=None):
        self.config_manager = config_manager
        self.red_flags = []
    
    def analyze_proxy_complexity(self, proxy_path: str, proxy_name: str) -> ProxyComplexityReport:
        """
        Main function to analyze proxy complexity
        
        Args:
            proxy_path: Path to proxy directory (e.g., /path/to/proxy/apiproxy)
            proxy_name: Name of the API proxy
            
        Returns:
            ProxyComplexityReport with complete analysis
        """
        logging.info(f"Starting complexity analysis for: {proxy_name}")
        
        self.red_flags = []
        criteria_scores = []
        
        # HIGH IMPACT Criteria (Weight: 3x)
        criteria_scores.append(self._analyze_policy_count(proxy_path))
        criteria_scores.append(self._analyze_javascript_complexity(proxy_path))
        criteria_scores.append(self._analyze_java_callouts(proxy_path))
        criteria_scores.append(self._analyze_service_callouts(proxy_path))
        criteria_scores.append(self._analyze_conditional_flows(proxy_path))
        criteria_scores.append(self._analyze_message_transformation(proxy_path))
        criteria_scores.append(self._analyze_shared_flows(proxy_path))
        criteria_scores.append(self._analyze_custom_extensions(proxy_path))
        criteria_scores.append(self._analyze_soap_xml_complexity(proxy_path))
        criteria_scores.append(self._analyze_external_dependencies(proxy_path))
        
        # MEDIUM IMPACT Criteria (Weight: 2x)
        criteria_scores.append(self._analyze_target_endpoints(proxy_path))
        criteria_scores.append(self._analyze_authentication(proxy_path))
        criteria_scores.append(self._analyze_traffic_management(proxy_path))
        criteria_scores.append(self._analyze_fault_handling(proxy_path))
        criteria_scores.append(self._analyze_variable_extraction(proxy_path))
        criteria_scores.append(self._analyze_kvm_usage(proxy_path))
        criteria_scores.append(self._analyze_response_customization(proxy_path))
        criteria_scores.append(self._analyze_deployment_config(proxy_path))
        
        # LOW IMPACT Criteria (Weight: 1x)
        criteria_scores.append(self._analyze_caching(proxy_path))
        criteria_scores.append(self._analyze_logging_analytics(proxy_path))
        
        print(criteria_scores)
        criteria_scores = [score for score in criteria_scores if score is not None]

        # Calculate total score
        #total_score = sum(score.weighted_score for score in criteria_scores)
        total_score = sum(score.weighted_score for score in criteria_scores if score is not None)

        # Determine complexity level
        if total_score <= self.SIMPLE_THRESHOLD:
            complexity_level = ComplexityLevel.SIMPLE.value
            migration_strategy = "✅ Automated Migration - Use automated tools with minimal manual review"
        elif total_score <= self.MEDIUM_THRESHOLD:
            complexity_level = ComplexityLevel.MEDIUM.value
            migration_strategy = "⚠️ Semi-Automated Migration - Automated migration with focused manual review and testing"
        else:
            complexity_level = ComplexityLevel.COMPLEX.value
            migration_strategy = "🔴 Manual Migration - Requires detailed analysis, manual implementation, and comprehensive testing"
        
        # Generate summary
        summary = self._generate_summary(criteria_scores, total_score)
        
        # Generate detailed analysis
        detailed_analysis = self._generate_detailed_analysis(criteria_scores)
        
        report = ProxyComplexityReport(
            proxy_name=proxy_name,
            total_score=total_score,
            complexity_level=complexity_level,
            migration_strategy=migration_strategy,
            criteria_scores=criteria_scores,
            red_flags=self.red_flags,
            summary=summary,
            detailed_analysis=detailed_analysis
        )
        
        logging.info(f"Complexity analysis completed for {proxy_name}: {complexity_level} ({total_score} points)")
        
        return report
    
    # ==================== HIGH IMPACT CRITERIA ====================
    
    def _analyze_policy_count(self, proxy_path: str) -> ComplexityScore:
        """Criterion 1: Total number of policies"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        if not os.path.exists(policy_folder):
            return self._create_score("Policy Count", 0, self.HIGH_IMPACT, 
                                     {"count": 0}, ["No policies found"])
        
        policy_files = [f for f in os.listdir(policy_folder) if f.endswith('.xml')]
        count = len(policy_files)
        
        # Scoring logic
        if count <= 5:
            raw_score, level = 2, "Simple"
        elif count <= 15:
            raw_score, level = 5, "Medium"
        else:
            raw_score, level = 9, "Complex"
        
        recommendations = []
        if count > 20:
            recommendations.append("Consider breaking down into multiple proxies or shared flows")
            self.red_flags.append(f"High policy count: {count} policies")
        
        return self._create_score(
            "Policy Count",
            raw_score,
            self.HIGH_IMPACT,
            {"total_policies": count, "policy_files": policy_files[:10]},
            recommendations
        )
    
    def _analyze_javascript_complexity(self, proxy_path: str) -> ComplexityScore:
        """Criterion 2: JavaScript policy complexity"""

        import os
        import logging
        import xml.etree.ElementTree as ET

        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        resources_folder = os.path.join(proxy_path, 'apiproxy', 'resources', 'jsc')

        js_policies = []
        js_files = []
        total_lines = 0
        total_size_kb = 0
        has_dependencies = False
        recommendations = []

        # Find JavaScript policies and referenced JS files
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    if root.tag == "Javascript":
                        js_policies.append(policy_file)
                        resource_file = root.find('.//ResourceURL')
                        if resource_file is not None and resource_file.text:
                            js_files.append(resource_file.text)
                except ET.ParseError:
                    pass

        # Analyze all JS files in resources/jsc
        if os.path.exists(resources_folder):
            for js_file in os.listdir(resources_folder):
                if not js_file.endswith('.js'):
                    continue
                file_path = os.path.join(resources_folder, js_file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = len(content.splitlines())
                        total_lines += lines
                        total_size_kb += os.path.getsize(file_path) / 1024
                        if ('require(' in content or 'import ' in content) and not has_dependencies:
                            has_dependencies = True
                            self.red_flags.append(f"JavaScript with external dependencies found: {js_file}")
                except Exception as e:
                    logging.error(f"Error reading JS file {js_file}: {e}")

        js_count = len(js_policies)
        # Scoring logic
        if js_count == 0:
            raw_score, level = 0, "Simple"
        elif js_count <= 1 and total_lines < 50:
            raw_score, level = 3, "Simple"
        elif js_count <= 3 and total_lines < 200:
            raw_score, level = 6, "Medium"
        else:
            raw_score, level = 10, "Complex"

        if total_lines > 500:
            recommendations.append("JavaScript exceeds 500 lines - requires careful migration")
            self.red_flags.append(f"Large JavaScript codebase: {total_lines} lines")
        if js_count > 3:
            recommendations.append("Multiple JavaScript policies - consider consolidation")
        if has_dependencies:
            recommendations.append("External dependencies detected - may require bundling or rewriting")

        return self._create_score(
            "JavaScript Complexity",
            raw_score,
            self.HIGH_IMPACT,
            {
                "js_policy_count": js_count,
                "total_lines": total_lines,
                "total_size_kb": round(total_size_kb, 2),
                "js_files": js_files,
                "has_dependencies": has_dependencies
            },
            recommendations
        )

    
    def _analyze_fault_handling(self, proxy_path: str) -> ComplexityScore:
        """Criterion 11: Fault handling & error logic"""
        proxies_folder = os.path.join(proxy_path, 'apiproxy', 'proxies')
        targets_folder = os.path.join(proxy_path, 'apiproxy', 'targets')
        
        fault_rules = []
        
        # Check proxy endpoints
        if os.path.exists(proxies_folder):
            for endpoint_file in os.listdir(proxies_folder):
                if not endpoint_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(proxies_folder, endpoint_file))
                    root = tree.getroot()
                    
                    fault_rule_elements = root.findall('.//FaultRule')
                    fault_rules.extend([fr.attrib.get('name', 'unnamed') for fr in fault_rule_elements])
                except ET.ParseError:
                    pass
        
        # Check target endpoints
        if os.path.exists(targets_folder):
            for target_file in os.listdir(targets_folder):
                if not target_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(targets_folder, target_file))
                    root = tree.getroot()
                    
                    fault_rule_elements = root.findall('.//FaultRule')
                    fault_rules.extend([fr.attrib.get('name', 'unnamed') for fr in fault_rule_elements])
                except ET.ParseError:
                    pass
        
        fault_count = len(fault_rules)
        
        # Scoring logic
        if fault_count == 0:
            raw_score, level = 1, "Simple"
        elif fault_count <= 3:
            raw_score, level = 4, "Medium"
        else:
            raw_score, level = 7, "Complex"
        
        recommendations = []
        if fault_count > 5:
            recommendations.append("Complex error handling - map all fault scenarios to target platform")
        elif fault_count > 0:
            recommendations.append("Custom fault rules - ensure error responses match in target")
        
        return self._create_score(
            "Fault Handling",
            raw_score,
            self.MEDIUM_IMPACT,
            {"fault_rule_count": fault_count, "fault_rules": fault_rules},
            recommendations
        )
    
    def _analyze_variable_extraction(self, proxy_path: str) -> ComplexityScore:
        """Criterion 12: Variable extraction & manipulation"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        extract_policies = []
        complex_patterns = []
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "ExtractVariables":
                        extract_policies.append(policy_file)
                        
                        # Check for complex patterns
                        patterns = root.findall('.//{*}Pattern')
                        for pattern in patterns:
                            if pattern.text and len(pattern.text) > 20:
                                complex_patterns.append(pattern.text[:50])
                except ET.ParseError:
                    pass
        
        extract_count = len(extract_policies)
        
        # Scoring logic
        if extract_count == 0:
            raw_score, level = 0, "Simple"
        elif extract_count <= 2:
            raw_score, level = 3, "Simple"
        elif extract_count <= 5:
            raw_score, level = 5, "Medium"
        else:
            raw_score, level = 8, "Complex"
        
        recommendations = []
        if len(complex_patterns) > 3:
            recommendations.append("Complex extraction patterns - test thoroughly in target platform")
        
        return self._create_score(
            "Variable Extraction",
            raw_score,
            self.MEDIUM_IMPACT,
            {
                "extract_policy_count": extract_count,
                "complex_pattern_count": len(complex_patterns),
                "sample_patterns": complex_patterns[:2]
            },
            recommendations
        )
    
    def _analyze_kvm_usage(self, proxy_path: str) -> ComplexityScore:
        """Criterion 14: Key-Value Map usage"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        kvm_policies = []
        encrypted_kvms = []
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "KeyValueMapOperations":
                        kvm_policies.append(policy_file)
                        
                        # Check if encrypted
                        encrypted = root.find('.//{*}Encrypted')
                        if encrypted is not None and encrypted.text == 'true':
                            encrypted_kvms.append(policy_file)
                except ET.ParseError:
                    pass
        
        kvm_count = len(kvm_policies)
        
        # Scoring logic
        if kvm_count == 0:
            raw_score, level = 0, "Simple"
        elif kvm_count <= 2:
            raw_score, level = 4, "Medium"
        else:
            raw_score, level = 7, "Complex"
        
        recommendations = []
        if kvm_count > 0:
            recommendations.append("KVM data needs migration to equivalent storage in target platform")
        if len(encrypted_kvms) > 0:
            recommendations.append("Encrypted KVMs require secure storage solution in target")
        
        return self._create_score(
            "KVM Usage",
            raw_score,
            self.MEDIUM_IMPACT,
            {
                "kvm_policy_count": kvm_count,
                "encrypted_kvm_count": len(encrypted_kvms)
            },
            recommendations
        )
    
    def _analyze_response_customization(self, proxy_path: str) -> ComplexityScore:
        """Criterion 18: Response customization"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        response_policies = []
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "AssignMessage":
                        # Check if it modifies response
                        assign_to = root.find('.//{*}AssignTo')
                        if assign_to is not None and assign_to.text is not None and 'response' in assign_to.text.lower():
                            response_policies.append(policy_file)
                except ET.ParseError:
                    pass
        
        response_count = len(response_policies)
        
        # Scoring logic
        if response_count == 0:
            raw_score, level = 0, "Simple"
        elif response_count <= 3:
            raw_score, level = 4, "Medium"
        else:
            raw_score, level = 7, "Complex"
        
        recommendations = []
        if response_count > 3:
            recommendations.append("Multiple response customizations - verify all scenarios")
        
        return self._create_score(
            "Response Customization",
            raw_score,
            self.MEDIUM_IMPACT,
            {"response_policy_count": response_count},
            recommendations
        )
    
    def _analyze_deployment_config(self, proxy_path: str) -> ComplexityScore:
        """Criterion 19: Deployment configuration complexity"""
        # This would require additional metadata about deployments
        # For now, provide a placeholder implementation
        
        # Check for environment-specific files
        config_files = []
        apiproxy_path = os.path.join(proxy_path, 'apiproxy')
        
        if os.path.exists(apiproxy_path):
            for item in os.listdir(apiproxy_path):
                if 'env' in item.lower() or 'config' in item.lower():
                    config_files.append(item)
        
        # Scoring logic (basic)
        if len(config_files) == 0:
            raw_score, level = 2, "Simple"
        elif len(config_files) <= 2:
            raw_score, level = 5, "Medium"
        else:
            raw_score, level = 7, "Complex"
        
        recommendations = []
        if len(config_files) > 2:
            recommendations.append("Multiple environment configurations - plan migration per environment")
        
        return self._create_score(
            "Deployment Configuration",
            raw_score,
            self.MEDIUM_IMPACT,
            {"config_file_count": len(config_files), "config_files": config_files},
            recommendations
        )
    
    # ==================== LOW IMPACT CRITERIA ====================
    
    def _analyze_caching(self, proxy_path: str) -> ComplexityScore:
        """Criterion 9: Caching strategy complexity"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        cache_policies = {
            'ResponseCache': [],
            'PopulateCache': [],
            'LookupCache': [],
            'InvalidateCache': []
        }
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag in cache_policies:
                        cache_policies[root.tag].append(policy_file)
                except ET.ParseError:
                    pass
        
        total_cache = sum(len(v) for v in cache_policies.values())
        
        # Scoring logic
        if total_cache == 0:
            raw_score, level = 0, "Simple"
        elif total_cache <= 1:
            raw_score, level = 3, "Simple"
        else:
            raw_score, level = 6, "Medium"
        
        recommendations = []
        if total_cache > 2:
            recommendations.append("Complex caching - verify cache behavior in target platform")
        
        return self._create_score(
            "Caching Strategy",
            raw_score,
            self.LOW_IMPACT,
            {
                "total_cache_policies": total_cache,
                "by_type": {k: len(v) for k, v in cache_policies.items()}
            },
            recommendations
        )
    
    def _analyze_logging_analytics(self, proxy_path: str) -> ComplexityScore:
        """Criterion 16: Message logging & analytics"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        logging_policies = {
            'MessageLogging': [],
            'StatisticsCollector': []
        }
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag in logging_policies:
                        logging_policies[root.tag].append(policy_file)
                except ET.ParseError:
                    pass
        
        total_logging = sum(len(v) for v in logging_policies.values())
        
        # Scoring logic
        if total_logging == 0:
            raw_score, level = 0, "Simple"
        elif total_logging <= 2:
            raw_score, level = 2, "Simple"
        else:
            raw_score, level = 5, "Medium"
        
        recommendations = []
        if total_logging > 2:
            recommendations.append("Custom logging - configure equivalent in target platform")
        
        return self._create_score(
            "Logging & Analytics",
            raw_score,
            self.LOW_IMPACT,
            {
                "total_logging_policies": total_logging,
                "by_type": {k: len(v) for k, v in logging_policies.items()}
            },
            recommendations
        )
    
    # ==================== HELPER METHODS ====================
    
    def _create_score(
        self,
        criterion_name: str,
        raw_score: int,
        weight: int,
        details: Dict,
        recommendations: List[str]
    ) -> ComplexityScore:
        """Create a ComplexityScore object"""
        weighted_score = raw_score * weight
        
        # Determine level based on raw score
        if raw_score <= 3:
            level = "Simple"
        elif raw_score <= 7:
            level = "Medium"
        else:
            level = "Complex"
        
        return ComplexityScore(
            criterion_name=criterion_name,
            raw_score=raw_score,
            weight=weight,
            weighted_score=weighted_score,
            level=level,
            details=details,
            recommendations=recommendations
        )
    
    def _generate_summary(self, criteria_scores: List[ComplexityScore], total_score: int) -> Dict:
        """Generate summary statistics"""
        #high_impact = [s for s in criteria_scores if s.weight == self.HIGH_IMPACT]
        high_impact = [s for s in criteria_scores if s is not None and s.weight == self.HIGH_IMPACT]

        #medium_impact = [s for s in criteria_scores if s.weight == self.MEDIUM_IMPACT]
        medium_impact = [s for s in criteria_scores if s is not None and s.weight == self.MEDIUM_IMPACT]
        
        #low_impact = [s for s in criteria_scores if s.weight == self.LOW_IMPACT]
        low_impact = [s for s in criteria_scores if s is not None and s.weight == self.LOW_IMPACT]
        
        return {
            "total_score": total_score,
            "total_criteria": len(criteria_scores),
            "high_impact_score": sum(s.weighted_score for s in high_impact),
            "medium_impact_score": sum(s.weighted_score for s in medium_impact),
            "low_impact_score": sum(s.weighted_score for s in low_impact),
            "simple_criteria" : len([s for s in criteria_scores if s is not None and s.level == "Simple"]),
            "medium_criteria": len([s for s in criteria_scores if s is not None and s.level == "Medium"]),
            "complex_criteria": len([s for s in criteria_scores if s is not None and s.level == "Complex"]),
            "red_flag_count": len(self.red_flags)
        }
    
    def _generate_detailed_analysis(self, criteria_scores: List[ComplexityScore]) -> Dict:
        """Generate detailed analysis by category"""
        analysis = {
            "high_impact_criteria": [],
            "medium_impact_criteria": [],
            "low_impact_criteria": [],
            "top_concerns": [],
            "quick_wins": []
        }
        
        for score in criteria_scores:
            category_key = f"{['low', 'medium', 'high'][score.weight - 1]}_impact_criteria"
            analysis[category_key].append({
                "name": score.criterion_name,
                "score": score.weighted_score,
                "level": score.level,
                "details": score.details
            })
            
            # Identify top concerns (high weight + high score)
            if score.weight >= 2 and score.raw_score >= 7:
                analysis["top_concerns"].append(score.criterion_name)
            
            # Identify quick wins (low score items)
            if score.raw_score <= 2:
                analysis["quick_wins"].append(score.criterion_name)
        
        return analysis
    
    def export_report_json(self, report: ProxyComplexityReport, output_path: str):
        """Export report as JSON"""
        report_dict = {
            "proxy_name": report.proxy_name,
            "total_score": report.total_score,
            "complexity_level": report.complexity_level,
            "migration_strategy": report.migration_strategy,
            "red_flags": report.red_flags,
            "summary": report.summary,
            "criteria_scores": [
                {
                    "criterion": score.criterion_name,
                    "raw_score": score.raw_score,
                    "weight": score.weight,
                    "weighted_score": score.weighted_score,
                    "level": score.level,
                    "details": score.details,
                    "recommendations": score.recommendations
                }
                for score in report.criteria_scores
            ],
            "detailed_analysis": report.detailed_analysis
        }
        
        with open(output_path, 'w') as f:
            json.dump(report_dict, f, indent=4)
        
        logging.info(f"Report exported to: {output_path}")
    
    def export_report_html(self, report: ProxyComplexityReport, output_path: str):
        """Export report as HTML"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Complexity Analysis - {report.proxy_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e8f5e9; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .score {{ font-size: 48px; font-weight: bold; color: #2196F3; }}
        .level-simple {{ color: #4CAF50; }}
        .level-medium {{ color: #FF9800; }}
        .level-complex {{ color: #F44336; }}
        .criteria-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .criteria-table th, .criteria-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .criteria-table th {{ background: #2196F3; color: white; }}
        .red-flag {{ background: #ffebee; padding: 10px; margin: 10px 0; border-left: 4px solid #f44336; }}
        .recommendation {{ background: #fff3e0; padding: 10px; margin: 5px 0; border-left: 4px solid #ff9800; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge-high {{ background: #f44336; color: white; }}
        .badge-medium {{ background: #ff9800; color: white; }}
        .badge-low {{ background: #4caf50; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Complexity Analysis Report</h1>
        <h2>{report.proxy_name}</h2>
        
        <div class="summary">
            <h3>Overall Assessment</h3>
            <div class="score level-{report.complexity_level.lower()}">{report.total_score} points</div>
            <p><strong>Complexity Level:</strong> <span class="level-{report.complexity_level.lower()}">{report.complexity_level}</span></p>
            <p><strong>Migration Strategy:</strong> {report.migration_strategy}</p>
        </div>
        
        <h2>📊 Summary Statistics</h2>
        <ul>
            <li>Total Criteria Analyzed: {report.summary['total_criteria']}</li>
            <li>Simple Criteria: {report.summary['simple_criteria']}</li>
            <li>Medium Criteria: {report.summary['medium_criteria']}</li>
            <li>Complex Criteria: {report.summary['complex_criteria']}</li>
            <li>Red Flags: {report.summary['red_flag_count']}</li>
        </ul>
        
        {"<h2>🚩 Red Flags</h2>" + "".join([f'<div class="red-flag">{flag}</div>' for flag in report.red_flags]) if report.red_flags else ""}
        
        <h2>📋 Detailed Criteria Analysis</h2>
        <table class="criteria-table">
            <thead>
                <tr>
                    <th>Criterion</th>
                    <th>Raw Score</th>
                    <th>Weight</th>
                    <th>Weighted Score</th>
                    <th>Level</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for score in report.criteria_scores:
            badge_class = f"badge-{['low', 'medium', 'high'][score.weight - 1]}"
            html_content += f"""
                <tr>
                    <td><strong>{score.criterion_name}</strong></td>
                    <td>{score.raw_score}/10</td>
                    <td><span class="badge {badge_class}">{score.weight}x</span></td>
                    <td>{score.weighted_score}</td>
                    <td class="level-{score.level.lower()}">{score.level}</td>
                </tr>
            """
            
            if score.recommendations:
                html_content += f"""
                <tr>
                    <td colspan="5">
                        <div style="padding-left: 20px;">
                            {"".join([f'<div class="recommendation">💡 {rec}</div>' for rec in score.recommendations])}
                        </div>
                    </td>
                </tr>
                """
        
        html_content += """
            </tbody>
        </table>
        
        <h2>🎯 Top Concerns</h2>
        <ul>
        """
        
        for concern in report.detailed_analysis['top_concerns']:
            html_content += f"<li>{concern}</li>"
        
        html_content += """
        </ul>
        
        <h2>✅ Quick Wins</h2>
        <ul>
        """
        
        for win in report.detailed_analysis['quick_wins']:
            html_content += f"<li>{win}</li>"
        
        html_content += """
        </ul>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        logging.info(f"HTML report exported to: {output_path}")



    
    def _analyze_java_callouts(self, proxy_path: str) -> ComplexityScore:
        """Criterion 3: Java callout usage"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        resources_folder = os.path.join(proxy_path, 'apiproxy', 'resources', 'java')
        
        java_policies = []
        jar_files = []
        
        # Check for Java callout policies
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "JavaCallout":
                        java_policies.append(policy_file)
                        # Get class name
                        class_name = root.find('.//ClassName')
                        if class_name is not None:
                            logging.info(f"Java callout class: {class_name.text}")
                except ET.ParseError:
                    pass
        
        # Check for JAR files
        if os.path.exists(resources_folder):
            jar_files = [f for f in os.listdir(resources_folder) if f.endswith('.jar')]
        
        # Scoring logic
        java_count = len(java_policies)
        if java_count == 0:
            raw_score, level = 0, "Simple"
        elif java_count == 1 and len(jar_files) == 0:
            raw_score, level = 7, "Medium"
        else:
            raw_score, level = 10, "Complex"
            self.red_flags.append(f"Java callouts detected: {java_count} policies, {len(jar_files)} JARs")
        
        recommendations = []
        if java_count > 0:
            recommendations.append("Java callouts require complete reimplementation in target platform")
            recommendations.append("Review Java logic and identify equivalent native policies or functions")
        
        return self._create_score(
            "Java Callout Usage",
            raw_score,
            self.HIGH_IMPACT,
            {
                "java_policy_count": java_count,
                "jar_count": len(jar_files),
                "jar_files": jar_files
            },
            recommendations
        )
    
    def _analyze_service_callouts(self, proxy_path: str) -> ComplexityScore:
        """Criterion 4: Service callout orchestration"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        service_callouts = []
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "ServiceCallout":
                        service_callouts.append(policy_file)
                except ET.ParseError:
                    pass
        
        # Scoring logic
        sc_count = len(service_callouts)
        if sc_count == 0:
            raw_score, level = 0, "Simple"
        elif sc_count <= 1:
            raw_score, level = 3, "Simple"
        elif sc_count <= 3:
            raw_score, level = 6, "Medium"
        else:
            raw_score, level = 9, "Complex"
        
        recommendations = []
        if sc_count >= 5:
            recommendations.append("Complex orchestration pattern - requires careful sequencing in migration")
            self.red_flags.append(f"High service callout count: {sc_count} callouts")
        elif sc_count > 0:
            recommendations.append("Review service callout dependencies and error handling")
        
        return self._create_score(
            "Service Callout Orchestration",
            raw_score,
            self.HIGH_IMPACT,
            {"service_callout_count": sc_count, "callouts": service_callouts},
            recommendations
        )
    
    def _analyze_conditional_flows(self, proxy_path: str) -> ComplexityScore:
        """Criterion 5: Conditional flow complexity"""
        proxies_folder = os.path.join(proxy_path, 'apiproxy', 'proxies')
        targets_folder = os.path.join(proxy_path, 'apiproxy', 'targets')
        
        total_flows = 0
        max_nesting = 0
        complex_conditions = []
        
        # Analyze proxy endpoints
        if os.path.exists(proxies_folder):
            for endpoint_file in os.listdir(proxies_folder):
                if not endpoint_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(proxies_folder, endpoint_file))
                    root = tree.getroot()
                    
                    flows = root.findall('.//Flow')
                    total_flows += len(flows)
                    
                    # Check for condition complexity
                    for flow in flows:
                        condition = flow.find('Condition')
                        if condition is not None and condition.text:
                            cond_text = condition.text.strip()
                            # Check for complex conditions (and, or, nested)
                            if ' and ' in cond_text.lower() or ' or ' in cond_text.lower():
                                complex_conditions.append(cond_text[:100])
                except ET.ParseError:
                    pass
        
        # Analyze target endpoints
        if os.path.exists(targets_folder):
            for target_file in os.listdir(targets_folder):
                if not target_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(targets_folder, target_file))
                    root = tree.getroot()
                    
                    flows = root.findall('.//Flow')
                    total_flows += len(flows)
                except ET.ParseError:
                    pass
        
        # Scoring logic
        if total_flows <= 3:
            raw_score, level = 2, "Simple"
        elif total_flows <= 8:
            raw_score, level = 5, "Medium"
        else:
            raw_score, level = 9, "Complex"
        
        recommendations = []
        if total_flows > 10:
            recommendations.append("High number of conditional flows - review flow logic carefully")
        if len(complex_conditions) > 5:
            recommendations.append("Complex conditional expressions detected - may need simplification")
        
        return self._create_score(
            "Conditional Flow Complexity",
            raw_score,
            self.HIGH_IMPACT,
            {
                "total_flows": total_flows,
                "complex_condition_count": len(complex_conditions),
                "sample_conditions": complex_conditions[:3]
            },
            recommendations
        )
    
    def _analyze_message_transformation(self, proxy_path: str) -> ComplexityScore:
        """Criterion 7: Message transformation complexity"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        transformation_policies = {
            'JSONToXML': [],
            'XMLToJSON': [],
            'XSLTransform': [],
            'AssignMessage': [],
            'ExtractVariables': []
        }
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag in transformation_policies:
                        transformation_policies[root.tag].append(policy_file)
                except ET.ParseError:
                    pass
        
        total_transformations = sum(len(v) for v in transformation_policies.values())
        has_xslt = len(transformation_policies['XSLTransform']) > 0
        
        # Scoring logic
        if total_transformations <= 2:
            raw_score, level = 2, "Simple"
        elif total_transformations <= 5:
            raw_score, level = 5, "Medium"
        else:
            raw_score, level = 8, "Complex"
        
        if has_xslt:
            raw_score = 10
            level = "Complex"
            self.red_flags.append("XSLT transformations detected - requires manual migration")
        
        recommendations = []
        if has_xslt:
            recommendations.append("XSLT transformations need complete reimplementation")
        if total_transformations > 5:
            recommendations.append("Multiple transformations - consider consolidation")
        
        return self._create_score(
            "Message Transformation",
            raw_score,
            self.HIGH_IMPACT,
            {
                "total_transformations": total_transformations,
                "by_type": {k: len(v) for k, v in transformation_policies.items()},
                "has_xslt": has_xslt
            },
            recommendations
        )
    
    def _analyze_shared_flows(self, proxy_path: str) -> ComplexityScore:
        """Criterion 13: Shared flow dependencies"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        shared_flow_callouts = []
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "FlowCallout":
                        shared_flow_callouts.append(policy_file)
                except ET.ParseError:
                    pass
        
        sf_count = len(shared_flow_callouts)
        
        # Scoring logic
        if sf_count == 0:
            raw_score, level = 0, "Simple"
        elif sf_count <= 2:
            raw_score, level = 5, "Medium"
        else:
            raw_score, level = 9, "Complex"
        
        recommendations = []
        if sf_count > 0:
            recommendations.append("Shared flows must be migrated before this proxy")
            recommendations.append("Analyze shared flow complexity separately")
        
        return self._create_score(
            "Shared Flow Dependencies",
            raw_score,
            self.HIGH_IMPACT,
            {"shared_flow_count": sf_count, "flow_callouts": shared_flow_callouts},
            recommendations
        )
    
    def _analyze_custom_extensions(self, proxy_path: str) -> ComplexityScore:
        """Criterion 15: Custom extensions and plugins"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        resources_py = os.path.join(proxy_path, 'apiproxy', 'resources', 'py')
        
        python_policies = []
        python_files = []
        
        # Check for Python script policies
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "PythonScript":
                        python_policies.append(policy_file)
                        self.red_flags.append(f"Python script detected: {policy_file}")
                except ET.ParseError:
                    pass
        
        # Check for Python files
        if os.path.exists(resources_py):
            python_files = [f for f in os.listdir(resources_py) if f.endswith('.py')]
        
        py_count = len(python_policies)
        
        # Scoring logic
        if py_count == 0:
            raw_score, level = 0, "Simple"
        else:
            raw_score, level = 10, "Complex"
        
        recommendations = []
        if py_count > 0:
            recommendations.append("Python scripts require complete reimplementation")
            recommendations.append("Review Python logic and convert to native policies or serverless functions")
        
        return self._create_score(
            "Custom Extensions",
            raw_score,
            self.HIGH_IMPACT,
            {
                "python_policy_count": py_count,
                "python_file_count": len(python_files)
            },
            recommendations
        )
    
    def _analyze_soap_xml_complexity(self, proxy_path: str) -> ComplexityScore:
        """Criterion 17: SOAP/XML complexity"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        soap_policies = {
            'XSLTransform': [],
            'SOAPMessageValidation': [],
            'XMLThreatProtection': [],
            'XMLToJSON': [],
            'JSONToXML': []
        }
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag in soap_policies:
                        soap_policies[root.tag].append(policy_file)
                except ET.ParseError:
                    pass
        
        total_soap = sum(len(v) for v in soap_policies.values())
        has_xslt = len(soap_policies['XSLTransform']) > 0
        
        # Scoring logic
        if total_soap == 0:
            raw_score, level = 0, "Simple"
        elif total_soap <= 2 and not has_xslt:
            raw_score, level = 4, "Medium"
        else:
            raw_score, level = 9, "Complex"
        
        recommendations = []
        if has_xslt:
            recommendations.append("XSLT requires specialized migration")
        if total_soap > 3:
            recommendations.append("Complex SOAP/XML handling - thorough testing required")
        
        return self._create_score(
            "SOAP/XML Complexity",
            raw_score,
            self.HIGH_IMPACT,
            {
                "total_soap_policies": total_soap,
                "by_type": {k: len(v) for k, v in soap_policies.items()},
                "has_xslt": has_xslt
            },
            recommendations
        )
    
    def _analyze_external_dependencies(self, proxy_path: str) -> ComplexityScore:
        """Criterion 20: External dependencies"""
        targets_folder = os.path.join(proxy_path, 'apiproxy', 'targets')
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        target_endpoints = []
        service_callouts = 0
        
        # Count target endpoints
        if os.path.exists(targets_folder):
            target_endpoints = [f for f in os.listdir(targets_folder) if f.endswith('.xml')]
        
        # Count service callouts (external calls)
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag == "ServiceCallout":
                        service_callouts += 1
                except ET.ParseError:
                    pass
        
        total_deps = len(target_endpoints) + service_callouts
        
        # Scoring logic
        if total_deps <= 1:
            raw_score, level = 1, "Simple"
        elif total_deps <= 2:
            raw_score, level = 4, "Medium"
        else:
            raw_score, level = 8, "Complex"
        
        recommendations = []
        if total_deps > 3:
            recommendations.append("Multiple external dependencies - coordinate infrastructure setup")
        
        return self._create_score(
            "External Dependencies",
            raw_score,
            self.HIGH_IMPACT,
            {
                "target_endpoint_count": len(target_endpoints),
                "service_callout_count": service_callouts,
                "total_dependencies": total_deps
            },
            recommendations
        )
    
    # ==================== MEDIUM IMPACT CRITERIA ====================
    
    def _analyze_target_endpoints(self, proxy_path: str) -> ComplexityScore:
        """Criterion 6: Target endpoint count"""
        targets_folder = os.path.join(proxy_path, 'apiproxy', 'targets')
        
        target_files = []
        if os.path.exists(targets_folder):
            target_files = [f for f in os.listdir(targets_folder) if f.endswith('.xml')]
        
        target_count = len(target_files)
        
        # Scoring logic
        if target_count <= 1:
            raw_score, level = 1, "Simple"
        elif target_count <= 3:
            raw_score, level = 5, "Medium"
        else:
            raw_score, level = 8, "Complex"
        
        recommendations = []
        if target_count > 3:
            recommendations.append("Multiple targets - review routing logic carefully")
        
        return self._create_score(
            "Target Endpoint Count",
            raw_score,
            self.MEDIUM_IMPACT,
            {"target_count": target_count, "targets": target_files},
            recommendations
        )
    
    def _analyze_authentication(self, proxy_path: str) -> ComplexityScore:
        """Criterion 8: Authentication & security mechanisms"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        auth_policies = {
            'OAuth': [],
            'VerifyAPIKey': [],
            'SAMLAssertion': [],
            'BasicAuthentication': [],
            'VerifyJWT': [],
            'GenerateJWT': [],
            'DecodeJWT': []
        }
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue
                
                try:
                    tree = ET.parse(os.path.join(policy_folder, policy_file))
                    root = tree.getroot()
                    
                    if root.tag in auth_policies:
                        auth_policies[root.tag].append(policy_file)
                except ET.ParseError:
                    pass
        
        auth_types = [k for k, v in auth_policies.items() if len(v) > 0]
        has_saml = len(auth_policies['SAMLAssertion']) > 0
        
        # Scoring logic
        if len(auth_types) == 0:
            raw_score, level = 0, "Simple"
        elif len(auth_types) == 1:
            raw_score, level = 3, "Simple"
        elif len(auth_types) == 2:
            raw_score, level = 6, "Medium"
        else:
            raw_score, level = 9, "Complex"
        
        if has_saml:
            raw_score = 10
            self.red_flags.append("SAML authentication detected - requires specialized migration")
        
        recommendations = []
        if has_saml:
            recommendations.append("SAML requires identity provider configuration in target platform")
        if len(auth_types) > 2:
            recommendations.append("Multiple auth types - ensure all are supported in target platform")
        
        return self._create_score(
            "Authentication & Security",
            raw_score,
            self.MEDIUM_IMPACT,
            {
                "auth_type_count": len(auth_types),
                "auth_types": auth_types,
                "has_saml": has_saml
            },
            recommendations
        )
    
    def _analyze_traffic_management(self, proxy_path: str) -> ComplexityScore:
        """Criterion 10: Traffic management policies"""
        policy_folder = os.path.join(proxy_path, 'apiproxy', 'policies')
        
        traffic_policies = {
            'Quota': [],
            'SpikeArrest': [],
            'ConcurrentRateLimit': [],
            'ResetQuota': []
        }
        
        if os.path.exists(policy_folder):
            for policy_file in os.listdir(policy_folder):
                if not policy_file.endswith('.xml'):
                    continue

# ==================== USAGE EXAMPLE ====================

def main():
    """Example usage of the ComplexityAnalyzer"""
    import sys
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Initialize analyzer
    analyzer = ComplexityAnalyzer()
    
    # Check if proxy path provided as command line argument
    if len(sys.argv) > 1:
        proxy_path = sys.argv[1]
        proxy_name = os.path.basename(proxy_path)
    else:
        # Default example path
        print("Usage: python complexity_analyzer.py <proxy_path>")
        print("\nExample:")
        print("  python complexity_analyzer.py /home/vsts/work/1/tmp/export/mns-prod/prod/proxies/my-api")
        print("\nUsing default example for demonstration...")
        
        proxy_path = "/workspaces/codespaces-blank/apigee2openapi/apigee-proxy/emea-partner02/dev/proxies/graphql-sample/graphql-proxy"
        proxy_name = "graphql-proxy"
    
    # Check if path exists
    if not os.path.exists(proxy_path):
        print(f"\n❌ Error: Proxy path does not exist: {proxy_path}")
        print("\nPlease provide a valid proxy path.")
        sys.exit(1)
    
    print(f"\n{'='*70}")
    print(f"Analyzing Proxy: {proxy_name}")
    print(f"Path: {proxy_path}")
    print(f"{'='*70}\n")
    
    try:
        # Run analysis
        report = analyzer.analyze_proxy_complexity(proxy_path, proxy_name)
        
        # Export reports
        json_file = f"{proxy_name}_complexity_report.json"
        html_file = f"{proxy_name}_complexity_report.html"
        
        analyzer.export_report_json(report, json_file)
        analyzer.export_report_html(report, html_file)
        
        # Print summary
        print(f"\n{'='*70}")
        print("COMPLEXITY ANALYSIS RESULTS".center(70))
        print(f"{'='*70}")
        print(f"\n  Proxy Name:        {report.proxy_name}")
        print(f"  Total Score:       {report.total_score} points")
        print(f"  Complexity Level:  {report.complexity_level}")
        print(f"  Red Flags:         {len(report.red_flags)}")
        print(f"\n  Migration Strategy:")
        print(f"  {report.migration_strategy}")
        print(f"\n{'='*70}")
        
        # Print red flags if any
        if report.red_flags:
            print("\n🚩 RED FLAGS:")
            for i, flag in enumerate(report.red_flags, 1):
                print(f"  {i}. {flag}")
        
        # Print top concerns
        if report.detailed_analysis['top_concerns']:
            print("\n⚠️  TOP CONCERNS:")
            for concern in report.detailed_analysis['top_concerns']:
                print(f"  • {concern}")
        
        # Print quick wins
        if report.detailed_analysis['quick_wins']:
            print("\n✅ QUICK WINS (Low Complexity Areas):")
            for win in report.detailed_analysis['quick_wins']:
                print(f"  • {win}")
        
        # Print summary statistics
        summary = report.summary
        print(f"\n📊 SCORING BREAKDOWN:")
        print(f"  High Impact Score:   {summary['high_impact_score']}")
        print(f"  Medium Impact Score: {summary['medium_impact_score']}")
        print(f"  Low Impact Score:    {summary['low_impact_score']}")
        
        # Print file locations
        print(f"\n📁 REPORTS GENERATED:")
        print(f"  JSON Report: {os.path.abspath(json_file)}")
        print(f"  HTML Report: {os.path.abspath(html_file)}")
        
        print(f"\n{'='*70}\n")
        print("✅ Analysis completed successfully!")
        print(f"📖 Open the HTML report for detailed visual analysis:")
        print(f"   {os.path.abspath(html_file)}\n")
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        logging.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)
                
if __name__ == "__main__":
    main()
    