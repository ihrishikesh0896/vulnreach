#!/usr/bin/env python3
"""
Test script for Java Reachability Analyzer
"""

import json
import tempfile
import os
from pathlib import Path
from utils.java_reachability_analyzer import JavaReachabilityAnalyzer

def create_test_java_project():
    """Create a temporary Java project for testing."""
    temp_dir = tempfile.mkdtemp()
    
    # Create sample Java files
    java_files = {
        "src/main/java/com/example/App.java": """
package com.example;

import org.apache.commons.lang3.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    private static final Logger logger = LoggerFactory.getLogger(App.class);
    private ObjectMapper mapper = new ObjectMapper();
    
    public void processData(String input) {
        if (StringUtils.isNotEmpty(input)) {
            logger.info("Processing: " + input);
            // Use Jackson for JSON processing
            mapper.writeValueAsString(input);
        }
    }
}
""",
        "src/main/java/com/example/Utils.java": """
package com.example;

import org.apache.commons.lang3.StringUtils;
import java.util.List;

public class Utils {
    public static boolean isValid(String str) {
        return StringUtils.isNotBlank(str);
    }
}
""",
        "src/test/java/com/example/AppTest.java": """
package com.example;

import org.junit.Test;
import static org.junit.Assert.*;

public class AppTest {
    @Test
    public void testApp() {
        App app = new App();
        assertNotNull(app);
    }
}
"""
    }
    
    # Create files
    for file_path, content in java_files.items():
        full_path = Path(temp_dir) / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(content)
    
    return temp_dir

def create_test_vulnerability_data():
    """Create sample vulnerability data."""
    return [
        {
            "package_name": "commons-lang3",
            "installed_version": "3.8.1",
            "recommended_fixed_version": "3.12.0",
            "upgrade_needed": True
        },
        {
            "package_name": "jackson-databind",
            "installed_version": "2.9.8",
            "recommended_fixed_version": "2.13.0",
            "upgrade_needed": True
        },
        {
            "package_name": "slf4j-api",
            "installed_version": "1.7.25",
            "recommended_fixed_version": "1.7.36",
            "upgrade_needed": True
        },
        {
            "package_name": "unused-library",
            "installed_version": "1.0.0",
            "recommended_fixed_version": "2.0.0",
            "upgrade_needed": True
        }
    ]

def main():
    print("🧪 Testing Java Reachability Analyzer...")
    
    # Create test project
    test_project = create_test_java_project()
    print(f"📁 Created test project at: {test_project}")
    
    # Create analyzer
    analyzer = JavaReachabilityAnalyzer(test_project)
    
    # Test file scanning
    java_files = analyzer.scan_java_files()
    print(f"📄 Found {len(java_files)} Java files")
    
    # Test usage extraction
    for java_file in java_files:
        print(f"\n🔍 Analyzing: {java_file}")
        usage = analyzer.extract_imports_and_usage(java_file)
        for package, contexts in usage.items():
            print(f"  📦 {package}: {len(contexts)} usages")
            for ctx in contexts[:2]:  # Show first 2
                print(f"    - Line {ctx.line_number}: {ctx.context_line[:50]}...")
    
    # Test vulnerability analysis
    vuln_data = create_test_vulnerability_data()
    analyses = analyzer.analyze_vulnerability_reachability(vuln_data)
    
    print(f"\n📊 Vulnerability Analysis Results:")
    for analysis in analyses:
        print(f"  🔍 {analysis.package_name}: {analysis.criticality.value}")
        print(f"    Used: {analysis.is_used}, Files: {len(set(ctx.file_path for ctx in analysis.usage_contexts))}")
        print(f"    Reason: {analysis.risk_reason}")
    
    # Generate report
    report = analyzer.generate_report(analyses)
    
    # Save report
    report_path = Path(test_project) / "java_reachability_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n💾 Report saved to: {report_path}")
    print(f"📈 Summary: {report['summary']}")
    
    # Cleanup
    import shutil
    shutil.rmtree(test_project)
    print("🧹 Cleaned up test project")

if __name__ == "__main__":
    main()