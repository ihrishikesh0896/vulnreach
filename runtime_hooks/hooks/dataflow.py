"""Dataflow graph builder for taint analysis.

Builds source-to-sink dataflow graphs from taint events, enabling:
- Visualization of taint paths
- Multi-path analysis
- Vulnerability reporting
- Graph export (JSON, Mermaid)
"""
from __future__ import annotations

from typing import Dict, List, Set, Any, Optional
from collections import defaultdict
import json


class DataflowNode:
    """Represents a node in the dataflow graph."""
    
    def __init__(self, node_id: str, node_type: str, label: str, metadata: Optional[Dict] = None):
        self.id = node_id
        self.type = node_type  # 'source', 'propagation', 'sink'
        self.label = label
        self.metadata = metadata or {}
        self.children: Set[str] = set()  # Outgoing edges
        self.parents: Set[str] = set()   # Incoming edges
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary representation."""
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "metadata": self.metadata,
            "children": list(self.children),
            "parents": list(self.parents),
        }


class DataflowGraph:
    """Builds and manages dataflow graphs from taint events."""
    
    def __init__(self):
        self.nodes: Dict[str, DataflowNode] = {}
        self.edges: List[tuple[str, str]] = []
        self.taint_flows: Dict[str, List[str]] = defaultdict(list)  # taint_id -> [node_ids]
        self.vulnerabilities: List[Dict[str, Any]] = []
    
    def add_node(self, node_id: str, node_type: str, label: str, metadata: Optional[Dict] = None) -> DataflowNode:
        """Add a node to the graph."""
        if node_id not in self.nodes:
            self.nodes[node_id] = DataflowNode(node_id, node_type, label, metadata)
        return self.nodes[node_id]
    
    def add_edge(self, from_id: str, to_id: str):
        """Add a directed edge between two nodes."""
        if from_id in self.nodes and to_id in self.nodes:
            self.nodes[from_id].children.add(to_id)
            self.nodes[to_id].parents.add(from_id)
            self.edges.append((from_id, to_id))
    
    def build_from_events(self, events: List[Dict[str, Any]]):
        """Build dataflow graph from a list of taint events.
        
        Args:
            events: List of event dictionaries with 'event_type' and 'data'
        """
        # Track taint IDs to node IDs mapping
        taint_to_nodes: Dict[str, List[str]] = defaultdict(list)
        source_nodes: Dict[str, str] = {}  # taint_source -> node_id
        
        # First pass: Create nodes for sources and sinks
        for event in events:
            event_type = event.get('event_type')
            data = event.get('data', {})
            
            if event_type == 'taint_source':
                # Create source node
                source = data.get('source', 'unknown')
                source_type = data.get('source_type', 'UNKNOWN')
                node_id = f"source_{source.replace('.', '_')}"
                
                self.add_node(
                    node_id,
                    'source',
                    f"{source_type}: {source}",
                    {
                        'source': source,
                        'source_type': source_type,
                        'value_preview': data.get('value_preview', ''),
                    }
                )
                source_nodes[source] = node_id
            
            elif event_type == 'taint_sink_reached':
                # Create sink node
                sink_function = data.get('sink_function', 'unknown')
                vulnerability = data.get('vulnerability_type', 'UNKNOWN')
                severity = data.get('severity', 'UNKNOWN')
                taint_source = data.get('taint_source', 'unknown')
                
                node_id = f"sink_{sink_function}_{id(event)}"
                
                self.add_node(
                    node_id,
                    'sink',
                    f"{sink_function}() [{vulnerability}]",
                    {
                        'sink_function': sink_function,
                        'vulnerability_type': vulnerability,
                        'severity': severity,
                        'taint_source': taint_source,
                        'argument': data.get('sink_argument', ''),
                    }
                )
                
                # Record vulnerability
                self.vulnerabilities.append({
                    'node_id': node_id,
                    'vulnerability_type': vulnerability,
                    'severity': severity,
                    'sink_function': sink_function,
                    'taint_source': taint_source,
                })
                
                # Connect source to sink if source exists
                if taint_source in source_nodes:
                    self.add_edge(source_nodes[taint_source], node_id)
        
        # Second pass: Create propagation nodes
        propagation_counter = 0
        for event in events:
            event_type = event.get('event_type')
            data = event.get('data', {})
            
            if event_type == 'taint_propagation':
                operation = data.get('operation', 'unknown')
                source = data.get('source', 'unknown')
                
                node_id = f"prop_{operation}_{propagation_counter}"
                propagation_counter += 1
                
                self.add_node(
                    node_id,
                    'propagation',
                    f"{operation}()",
                    {
                        'operation': operation,
                        'source': source,
                        'result_preview': data.get('result_preview', ''),
                    }
                )
                
                # Connect source to propagation
                if source in source_nodes:
                    self.add_edge(source_nodes[source], node_id)
    
    def get_paths(self, from_type: str = 'source', to_type: str = 'sink') -> List[List[str]]:
        """Find all paths from nodes of one type to nodes of another type.
        
        Args:
            from_type: Starting node type (default: 'source')
            to_type: Ending node type (default: 'sink')
        
        Returns:
            List of paths, where each path is a list of node IDs
        """
        paths = []
        
        # Find all source nodes
        start_nodes = [nid for nid, node in self.nodes.items() if node.type == from_type]
        
        # DFS from each source
        for start_id in start_nodes:
            self._dfs_paths(start_id, to_type, [], paths)
        
        return paths
    
    def _dfs_paths(self, current_id: str, target_type: str, path: List[str], all_paths: List[List[str]]):
        """Depth-first search to find all paths to target type."""
        path = path + [current_id]
        current_node = self.nodes[current_id]
        
        # If we've reached a target type node, save the path
        if current_node.type == target_type:
            all_paths.append(path)
            return
        
        # Continue to children
        for child_id in current_node.children:
            if child_id not in path:  # Avoid cycles
                self._dfs_paths(child_id, target_type, path, all_paths)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary representation."""
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [{"from": f, "to": t} for f, t in self.edges],
            "vulnerabilities": self.vulnerabilities,
            "stats": {
                "total_nodes": len(self.nodes),
                "sources": len([n for n in self.nodes.values() if n.type == 'source']),
                "propagations": len([n for n in self.nodes.values() if n.type == 'propagation']),
                "sinks": len([n for n in self.nodes.values() if n.type == 'sink']),
                "total_edges": len(self.edges),
                "vulnerabilities": len(self.vulnerabilities),
            }
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export graph as JSON."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def to_mermaid(self) -> str:
        """Generate Mermaid flowchart diagram.
        
        Returns:
            Mermaid diagram as string
        """
        lines = ["flowchart TD"]
        
        # Node definitions with styling
        for node_id, node in self.nodes.items():
            label = node.label.replace('"', "'")
            
            if node.type == 'source':
                # Rounded box for sources
                lines.append(f'    {node_id}["{label}"]')
                lines.append(f'    style {node_id} fill:#90EE90,stroke:#228B22,stroke-width:2px')
            elif node.type == 'sink':
                # Hexagon for sinks
                severity = node.metadata.get('severity', 'UNKNOWN')
                color = '#FF6B6B' if severity == 'CRITICAL' else '#FFA500' if severity == 'HIGH' else '#FFD700'
                lines.append(f'    {node_id}{{"{label}"}}')
                lines.append(f'    style {node_id} fill:{color},stroke:#8B0000,stroke-width:3px')
            else:
                # Rectangle for propagations
                lines.append(f'    {node_id}["{label}"]')
                lines.append(f'    style {node_id} fill:#87CEEB,stroke:#4682B4,stroke-width:1px')
        
        # Edges
        for from_id, to_id in self.edges:
            lines.append(f'    {from_id} --> {to_id}')
        
        return '\n'.join(lines)
    
    def get_summary(self) -> str:
        """Generate human-readable summary of the graph."""
        stats = self.to_dict()['stats']
        
        summary = []
        summary.append("=" * 70)
        summary.append("Dataflow Graph Summary")
        summary.append("=" * 70)
        summary.append(f"Total Nodes: {stats['total_nodes']}")
        summary.append(f"  - Sources: {stats['sources']}")
        summary.append(f"  - Propagations: {stats['propagations']}")
        summary.append(f"  - Sinks: {stats['sinks']}")
        summary.append(f"Total Edges: {stats['total_edges']}")
        summary.append(f"Vulnerabilities: {stats['vulnerabilities']}")
        summary.append("")
        
        if self.vulnerabilities:
            summary.append("Detected Vulnerabilities:")
            for vuln in self.vulnerabilities:
                summary.append(f"  🚨 {vuln['severity']}: {vuln['vulnerability_type']}")
                summary.append(f"     Sink: {vuln['sink_function']}()")
                summary.append(f"     Source: {vuln['taint_source']}")
        
        summary.append("=" * 70)
        return '\n'.join(summary)


def build_graph_from_events(events: List[Dict[str, Any]]) -> DataflowGraph:
    """Convenience function to build a dataflow graph from events.
    
    Args:
        events: List of taint events
    
    Returns:
        DataflowGraph instance
    """
    graph = DataflowGraph()
    graph.build_from_events(events)
    return graph
