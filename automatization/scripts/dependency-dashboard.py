#!/usr/bin/env python3
"""
Dependency Dashboard for OpenDocSeal
Generates a comprehensive report of project dependencies and their security status.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import pkg_resources
import requests


class DependencyDashboard:
    """Generate dependency dashboard with security analysis."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().isoformat()
        
    def get_installed_packages(self) -> List[Dict]:
        """Get list of installed Python packages."""
        packages = []
        for dist in pkg_resources.working_set:
            packages.append({
                "name": dist.project_name,
                "version": dist.version,
                "location": dist.location
            })
        return sorted(packages, key=lambda x: x["name"].lower())
    
    def check_package_vulnerabilities(self) -> Dict:
        """Check for known vulnerabilities using Safety."""
        try:
            result = subprocess.run(
                ["safety", "check", "--json"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                return {"vulnerabilities": [], "status": "clean"}
            else:
                try:
                    vulnerabilities = json.loads(result.stdout)
                    return {
                        "vulnerabilities": vulnerabilities,
                        "status": "vulnerabilities_found"
                    }
                except json.JSONDecodeError:
                    return {
                        "vulnerabilities": [],
                        "status": "error",
                        "error": result.stderr
                    }
        except FileNotFoundError:
            return {
                "vulnerabilities": [],
                "status": "safety_not_installed"
            }
    
    def get_outdated_packages(self) -> List[Dict]:
        """Get list of outdated packages."""
        try:
            result = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []
    
    def check_license_compliance(self, packages: List[Dict]) -> Dict:
        """Check license compliance for packages."""
        license_info = {}
        problematic_licenses = [
            "GPL-3.0", "AGPL-3.0", "LGPL-3.0", 
            "CPAL-1.0", "EPL-1.0", "EUPL-1.1"
        ]
        
        for package in packages:
            try:
                # Try to get license info from package metadata
                dist = pkg_resources.get_distribution(package["name"])
                license_text = dist.get_metadata("METADATA")
                
                # Extract license from metadata (simplified)
                license_name = "Unknown"
                for line in license_text.split("\n"):
                    if line.startswith("License:"):
                        license_name = line.split(":", 1)[1].strip()
                        break
                
                is_problematic = any(
                    lic in license_name for lic in problematic_licenses
                )
                
                license_info[package["name"]] = {
                    "license": license_name,
                    "is_problematic": is_problematic
                }
            except Exception:
                license_info[package["name"]] = {
                    "license": "Unknown",
                    "is_problematic": False
                }
        
        return license_info
    
    def analyze_dependencies(self) -> Dict:
        """Perform comprehensive dependency analysis."""
        print("🔍 Analyzing dependencies...")
        
        # Get installed packages
        packages = self.get_installed_packages()
        print(f"   Found {len(packages)} installed packages")
        
        # Check for vulnerabilities
        print("   Checking for vulnerabilities...")
        vulnerabilities = self.check_package_vulnerabilities()
        
        # Get outdated packages
        print("   Checking for outdated packages...")
        outdated = self.get_outdated_packages()
        
        # Check license compliance
        print("   Checking license compliance...")
        licenses = self.check_license_compliance(packages)
        
        analysis = {
            "timestamp": self.timestamp,
            "total_packages": len(packages),
            "packages": packages,
            "vulnerabilities": vulnerabilities,
            "outdated_packages": outdated,
            "license_info": licenses,
            "summary": {
                "total_packages": len(packages),
                "vulnerable_packages": len(vulnerabilities.get("vulnerabilities", [])),
                "outdated_packages": len(outdated),
                "problematic_licenses": sum(
                    1 for info in licenses.values() 
                    if info["is_problematic"]
                )
            }
        }
        
        return analysis
    
    def generate_html_report(self, analysis: Dict) -> str:
        """Generate HTML dashboard report."""
        html_template = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenDocSeal - Dependency Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .metric {{ font-size: 2em; font-weight: bold; margin-bottom: 5px; }}
        .metric.good {{ color: #28a745; }}
        .metric.warning {{ color: #ffc107; }}
        .metric.danger {{ color: #dc3545; }}
        .section {{ margin-bottom: 30px; }}
        .table {{ width: 100%; border-collapse: collapse; }}
        .table th, .table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .table th {{ background: #f8f9fa; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .badge.success {{ background: #d4edda; color: #155724; }}
        .badge.warning {{ background: #fff3cd; color: #856404; }}
        .badge.danger {{ background: #f8d7da; color: #721c24; }}
        .timestamp {{ color: #6c757d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 OpenDocSeal - Dependency Dashboard</h1>
            <p class="timestamp">Generated on {timestamp}</p>
        </div>
        
        <div class="summary">
            <div class="card">
                <div class="metric {total_class}">{total_packages}</div>
                <div>Total Packages</div>
            </div>
            <div class="card">
                <div class="metric {vuln_class}">{vulnerable_packages}</div>
                <div>Vulnerable Packages</div>
            </div>
            <div class="card">
                <div class="metric {outdated_class}">{outdated_packages}</div>
                <div>Outdated Packages</div>
            </div>
            <div class="card">
                <div class="metric {license_class}">{problematic_licenses}</div>
                <div>License Issues</div>
            </div>
        </div>
        
        {sections}
    </div>
</body>
</html>
        """
        
        # Determine CSS classes for metrics
        summary = analysis["summary"]
        vuln_class = "danger" if summary["vulnerable_packages"] > 0 else "good"
        outdated_class = "warning" if summary["outdated_packages"] > 5 else "good"
        license_class = "warning" if summary["problematic_licenses"] > 0 else "good"
        
        # Generate sections
        sections = []
        
        # Vulnerabilities section
        if analysis["vulnerabilities"]["vulnerabilities"]:
            sections.append(self._generate_vulnerabilities_section(analysis["vulnerabilities"]))
        
        # Outdated packages section
        if analysis["outdated_packages"]:
            sections.append(self._generate_outdated_section(analysis["outdated_packages"]))
        
        # All packages section
        sections.append(self._generate_packages_section(analysis["packages"], analysis["license_info"]))
        
        return html_template.format(
            timestamp=analysis["timestamp"],
            total_packages=summary["total_packages"],
            vulnerable_packages=summary["vulnerable_packages"],
            outdated_packages=summary["outdated_packages"],
            problematic_licenses=summary["problematic_licenses"],
            total_class="good",
            vuln_class=vuln_class,
            outdated_class=outdated_class,
            license_class=license_class,
            sections="".join(sections)
        )
    
    def _generate_vulnerabilities_section(self, vulnerabilities: Dict) -> str:
        """Generate vulnerabilities section HTML."""
        if not vulnerabilities["vulnerabilities"]:
            return ""
        
        rows = []
        for vuln in vulnerabilities["vulnerabilities"]:
            rows.append(f"""
                <tr>
                    <td>{vuln.get('package', 'Unknown')}</td>
                    <td>{vuln.get('installed_version', 'Unknown')}</td>
                    <td><span class="badge danger">{vuln.get('vulnerability_id', 'Unknown')}</span></td>
                    <td>{vuln.get('advisory', 'No description available')}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="card">
                <h2>🚨 Security Vulnerabilities</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Package</th>
                            <th>Version</th>
                            <th>Vulnerability ID</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def _generate_outdated_section(self, outdated: List[Dict]) -> str:
        """Generate outdated packages section HTML."""
        if not outdated:
            return ""
        
        rows = []
        for pkg in outdated:
            rows.append(f"""
                <tr>
                    <td>{pkg['name']}</td>
                    <td>{pkg['version']}</td>
                    <td>{pkg['latest_version']}</td>
                    <td>{pkg.get('latest_filetype', 'wheel')}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="card">
                <h2>📦 Outdated Packages</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Package</th>
                            <th>Current Version</th>
                            <th>Latest Version</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def _generate_packages_section(self, packages: List[Dict], licenses: Dict) -> str:
        """Generate all packages section HTML."""
        rows = []
        for pkg in packages:
            license_info = licenses.get(pkg["name"], {"license": "Unknown", "is_problematic": False})
            license_badge = "warning" if license_info["is_problematic"] else "success"
            
            rows.append(f"""
                <tr>
                    <td>{pkg['name']}</td>
                    <td>{pkg['version']}</td>
                    <td><span class="badge {license_badge}">{license_info['license']}</span></td>
                    <td style="font-size: 0.8em;">{pkg['location']}</td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <div class="card">
                <h2>📋 All Packages</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Package</th>
                            <th>Version</th>
                            <th>License</th>
                            <th>Location</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    def generate_dashboard(self) -> None:
        """Generate complete dependency dashboard."""
        print("🔧 Generating OpenDocSeal Dependency Dashboard...")
        
        # Perform analysis
        analysis = self.analyze_dependencies()
        
        # Save JSON report
        json_file = self.output_dir / "dependency-analysis.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        
        # Generate HTML report
        html_content = self.generate_html_report(analysis)
        html_file = self.output_dir / "dependency-dashboard.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        # Print summary
        summary = analysis["summary"]
        print(f"\n📊 Summary:")
        print(f"   Total packages: {summary['total_packages']}")
        print(f"   Vulnerable packages: {summary['vulnerable_packages']}")
        print(f"   Outdated packages: {summary['outdated_packages']}")
        print(f"   License issues: {summary['problematic_licenses']}")
        
        print(f"\n📄 Reports generated:")
        print(f"   JSON: {json_file}")
        print(f"   HTML: {html_file}")
        
        # Return exit code based on findings
        if summary['vulnerable_packages'] > 0:
            print("\n⚠️  Vulnerabilities found! Please review and update packages.")
            return 1
        elif summary['outdated_packages'] > 10:
            print("\n💡 Many outdated packages found. Consider updating.")
            return 1
        else:
            print("\n✅ No critical issues found.")
            return 0


def main():
    """Main entry point."""
    dashboard = DependencyDashboard()
    exit_code = dashboard.generate_dashboard()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()