"""
Test Tainter Agent Integration
"""

import pytest
from pathlib import Path
from vulnreach.agents.tainter_agent import TainterAgent
from vulnreach.agents.coordinator import AgentCoordinator


# Test paths
VULN_DEMO_PATH = Path(__file__).parent.parent / "labs" / "vuln_demo"


class TestTainterAgent:
    """Test TainterAgent functionality"""

    def test_tainter_agent_initialization(self):
        """Test that TainterAgent initializes correctly"""
        agent = TainterAgent(str(VULN_DEMO_PATH))
        assert agent.root_path == VULN_DEMO_PATH

    def test_tainter_scan_project(self):
        """Test full project scan"""
        agent = TainterAgent(str(VULN_DEMO_PATH))

        result = agent.analyze({
            'type': 'scan_project',
            'params': {
                'include_tests': False
            }
        })

        assert result['success'] is True
        assert result['agent'] == 'TainterAgent'
        assert 'flows' in result
        assert 'summary' in result
        assert result['total_flows'] >= 0

        print(f"\n✅ Detected {result['total_flows']} taint flows")
        print(f"📁 Files analyzed: {result['files_analyzed']}")

    def test_tainter_scan_vuln_class_sqli(self):
        """Test scanning for specific vulnerability class (SQLI)"""
        agent = TainterAgent(str(VULN_DEMO_PATH))

        result = agent.analyze({
            'type': 'scan_vuln_class',
            'params': {
                'vuln_class': 'SQLI'
            }
        })

        assert result['success'] is True
        assert 'flows' in result

        # Check if any SQLI flows detected
        sqli_flows = [f for f in result['flows'] if f.get('vulnerability_class') == 'SQLI']
        print(f"\n🔍 Found {len(sqli_flows)} SQL Injection flows")

        if sqli_flows:
            flow = sqli_flows[0]
            print(f"   Source: {flow['source']['location']['file']}:{flow['source']['location']['line']}")
            print(f"   Sink: {flow['sink']['definition']['function']}")

    def test_tainter_scan_vuln_class_xss(self):
        """Test scanning for XSS vulnerabilities"""
        agent = TainterAgent(str(VULN_DEMO_PATH))

        result = agent.analyze({
            'type': 'scan_vuln_class',
            'params': {
                'vuln_class': 'XSS'
            }
        })

        assert result['success'] is True
        xss_flows = [f for f in result['flows'] if f.get('vulnerability_class') == 'XSS']
        print(f"\n🔍 Found {len(xss_flows)} XSS flows")

    def test_tainter_check_cve_reachability(self):
        """Test CVE reachability check"""
        agent = TainterAgent(str(VULN_DEMO_PATH))

        # Simulate a deserialization CVE
        cve_details = {
            'cve_id': 'CVE-2023-XXXXX',
            'cwe_id': 'CWE-502',  # Deserialization
            'severity': 'HIGH'
        }

        result = agent.analyze({
            'type': 'check_cve_reachability',
            'params': {
                'cve_details': cve_details,
                'package_name': 'pyyaml',
                'vulnerable_functions': ['yaml.unsafe_load', 'yaml.load']
            }
        })

        assert result['success'] is True
        assert 'reachable' in result
        assert 'confidence' in result

        print(f"\n🎯 CVE Reachability: {result['reachable']}")
        print(f"   Confidence: {result['confidence']}")
        print(f"   Relevant flows: {len(result.get('relevant_flows', []))}")

    def test_tainter_list_sources(self):
        """Test listing taint sources"""
        agent = TainterAgent(str(VULN_DEMO_PATH))

        result = agent.analyze({
            'type': 'list_sources',
            'params': {}
        })

        assert result['success'] is True
        assert 'sources' in result
        assert len(result['sources']) > 0

        # Check for Flask sources
        assert 'flask.request' in result['sources']

    def test_tainter_list_sinks(self):
        """Test listing taint sinks"""
        agent = TainterAgent(str(VULN_DEMO_PATH))

        result = agent.analyze({
            'type': 'list_sinks',
            'params': {}
        })

        assert result['success'] is True
        assert 'sinks' in result
        assert len(result['sinks']) > 0


class TestCoordinatorTainterIntegration:
    """Test Tainter integration via AgentCoordinator"""

    def test_coordinator_has_tainter_agent(self):
        """Test that coordinator includes tainter agent"""
        coordinator = AgentCoordinator(str(VULN_DEMO_PATH))

        assert 'tainter' in coordinator.agents
        assert isinstance(coordinator.agents['tainter'], TainterAgent)

    def test_coordinator_run_taint_analysis(self):
        """Test running taint analysis via coordinator"""
        coordinator = AgentCoordinator(str(VULN_DEMO_PATH))

        result = coordinator.run_taint_analysis(
            vuln_classes=['SQLI', 'XSS'],
            include_tests=False
        )

        assert result['success'] is True
        assert 'flows' in result

        print(f"\n📊 Coordinator Taint Analysis:")
        print(f"   Total flows: {result['total_flows']}")
        print(f"   Files analyzed: {result['files_analyzed']}")

    def test_coordinator_check_cve_taint_reachability(self):
        """Test CVE reachability check via coordinator"""
        coordinator = AgentCoordinator(str(VULN_DEMO_PATH))

        cve_details = {
            'cve_id': 'CVE-2023-TEST',
            'cwe_id': 'CWE-89',  # SQL Injection
            'severity': 'CRITICAL'
        }

        result = coordinator.check_cve_taint_reachability(
            cve_details=cve_details,
            package_name='sqlite3',
            vulnerable_functions=['execute', 'executemany']
        )

        assert result['success'] is True
        assert result['cve_id'] == 'CVE-2023-TEST'

        print(f"\n🔬 CVE Taint Reachability via Coordinator:")
        print(f"   CVE: {result['cve_id']}")
        print(f"   Reachable: {result['reachable']}")
        print(f"   Confidence: {result['confidence']}")

    def test_coordinator_list_taint_sources(self):
        """Test listing taint sources via coordinator"""
        coordinator = AgentCoordinator(str(VULN_DEMO_PATH))

        result = coordinator.list_taint_sources()

        assert result['success'] is True
        assert 'flask' in result['sources'].lower()

    def test_coordinator_list_taint_sinks(self):
        """Test listing taint sinks via coordinator"""
        coordinator = AgentCoordinator(str(VULN_DEMO_PATH))

        result = coordinator.list_taint_sinks()

        assert result['success'] is True
        assert 'execute' in result['sinks'].lower() or 'pickle' in result['sinks'].lower()

    def test_agent_capabilities(self):
        """Test that tainter agent reports correct capabilities"""
        coordinator = AgentCoordinator(str(VULN_DEMO_PATH))

        capabilities = coordinator.agents['tainter'].get_capabilities()

        assert 'scan_project' in capabilities
        assert 'scan_vuln_class' in capabilities
        assert 'check_cve_reachability' in capabilities
        assert 'list_sources' in capabilities
        assert 'list_sinks' in capabilities


if __name__ == '__main__':
    # Run with: python -m pytest tests/test_tainter_integration.py -v -s
    pytest.main([__file__, '-v', '-s'])
