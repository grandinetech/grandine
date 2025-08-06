"""
Static analysis utilities for multi-language AST and call graph analysis.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
from collections import defaultdict
import re


def build_call_graph(ast_objects: Dict[Path, Any]) -> Dict[str, Any]:
    """
    Build call graph from AST objects returned by language plugins.
    
    Args:
        ast_objects: Dictionary mapping file paths to plugin AST results
        
    Returns:
        Call graph with function signatures as keys and metadata as values
    """
    graph = defaultdict(dict)
    external_calls = defaultdict(list)
    internal_calls = defaultdict(list)
    
    for file_path, plugin_ast in ast_objects.items():
        if not plugin_ast or "functions" not in plugin_ast:
            continue
            
        plugin = plugin_ast.get("plugin", "unknown")
        
        for fn_sig, meta in plugin_ast["functions"].items():
            graph[fn_sig] = {
                "visibility": meta.get("visibility", "private"),
                "state_mutability": meta.get("mutability", "nonpayable"),
                "external_calls": meta.get("external_calls", []),
                "internal_calls": meta.get("internal_calls", []),
                "state_change_after_call": meta.get("state_change_after", False),
                "file": str(file_path),  # Convert Path to string
                "plugin": plugin,
                "complexity_score": meta.get("complexity_score", 0),
                "parameters": meta.get("parameters", []),
                "return_type": meta.get("return_type", "void"),
                "modifiers": meta.get("modifiers", []),
                "line_number": meta.get("line_number", 0)
            }
            
            # Track external calls for vulnerability analysis
            for call in meta.get("external_calls", []):
                external_calls[fn_sig].append(call)
            
            # Track internal calls for flow analysis
            for call in meta.get("internal_calls", []):
                internal_calls[fn_sig].append(call)
    
    # Build graph structure for visualization
    graph_structure = _build_graph_structure(graph, internal_calls, external_calls)
    
    return {
        "functions": dict(graph),
        "external_calls": dict(external_calls),
        "internal_calls": dict(internal_calls),
        "graph_structure": graph_structure,
        "metadata": {
            "total_functions": len(graph),
            "external_function_count": len([f for f in graph.values() if f["visibility"] in ["public", "external"]]),
            "potential_reentrancy_points": len([f for f in graph.values() if is_potentially_reentrant(f)]),
            "total_internal_calls": sum(len(calls) for calls in internal_calls.values()),
            "total_external_calls": sum(len(calls) for calls in external_calls.values())
        }
    }


def is_potentially_reentrant(node_meta: Dict[str, Any]) -> bool:
    """
    Check if a function is potentially vulnerable to reentrancy attacks.
    
    Args:
        node_meta: Function metadata from call graph
        
    Returns:
        True if function has potential reentrancy vulnerability
    """
    return (
        bool(node_meta.get("external_calls", []))
        and node_meta.get("state_change_after_call", False)
        and node_meta.get("visibility", "private") in ("public", "external")
        and "nonReentrant" not in node_meta.get("modifiers", [])
    )


def score_function(ast_node: Dict[str, Any]) -> int:
    """
    Calculate importance score for a function based on complexity and risk factors.
    
    Args:
        ast_node: Function AST node metadata
        
    Returns:
        Numerical score representing function importance
    """
    score = 0
    
    # External calls increase importance significantly
    external_calls = len(ast_node.get("external_calls", []))
    score += external_calls * 3
    
    # State mutations increase importance
    if ast_node.get("state_change_after_call", False):
        score += 2
    
    # Public/external functions are more important
    if ast_node.get("visibility", "private") in ("public", "external"):
        score += 2
    
    # Functions with modifiers are often important
    modifiers = len(ast_node.get("modifiers", []))
    score += modifiers
    
    # Complexity score from AST analysis
    complexity = ast_node.get("complexity_score", 0)
    score += complexity
    
    return score


def analyze_external_calls(call_graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Analyze external calls to determine their risk level and trustworthiness.
    
    Args:
        call_graph: Call graph from build_call_graph()
        
    Returns:
        Dictionary mapping function signatures to external call analysis
    """
    external_call_map = {}
    
    for fn_sig, fn_meta in call_graph.get("functions", {}).items():
        external_calls = fn_meta.get("external_calls", [])
        
        if external_calls:
            call_analysis = {
                "external": True,
                "state_change_after": fn_meta.get("state_change_after_call", False),
                "calls": [],
                "risk_level": "low"
            }
            
            for call in external_calls:
                call_info = analyze_single_call(call, fn_meta)
                call_analysis["calls"].append(call_info)
                
                # Update risk level based on call analysis
                if call_info["risk_level"] == "high":
                    call_analysis["risk_level"] = "high"
                elif call_info["risk_level"] == "medium" and call_analysis["risk_level"] != "high":
                    call_analysis["risk_level"] = "medium"
            
            external_call_map[fn_sig] = call_analysis
        else:
            external_call_map[fn_sig] = {
                "external": False,
                "state_change_after": False,
                "calls": [],
                "risk_level": "none"
            }
    
    return external_call_map


def analyze_single_call(call: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single external call for security implications.
    
    Args:
        call: External call information
        context: Function context metadata
        
    Returns:
        Analysis result for the call
    """
    call_info = {
        "target": call.get("target", "unknown"),
        "method": call.get("method", "unknown"),
        "is_trusted": False,
        "risk_level": "medium"
    }
    
    target = call.get("target", "")
    method = call.get("method", "")
    
    # Check if call is to a trusted contract (same protocol)
    trusted_patterns = [
        r"this\.",  # Self calls
        r"pool\.",  # Pool contracts
        r"manager\.",  # Manager contracts
        r"registry\.",  # Registry contracts
    ]
    
    for pattern in trusted_patterns:
        if re.match(pattern, target, re.IGNORECASE):
            call_info["is_trusted"] = True
            call_info["risk_level"] = "low"
            break
    
    # High risk patterns
    high_risk_patterns = [
        "call",
        "delegatecall",
        "staticcall",
        "transfer",
        "send"
    ]
    
    if any(pattern in method.lower() for pattern in high_risk_patterns):
        if not call_info["is_trusted"]:
            call_info["risk_level"] = "high"
    
    return call_info


def extract_contract_relationships(ast_objects: Dict[Path, Any]) -> Dict[str, Any]:
    """
    Extract relationships between contracts from AST analysis.
    
    Args:
        ast_objects: Dictionary mapping file paths to plugin AST results
        
    Returns:
        Contract relationship analysis
    """
    relationships = {
        "inheritance": {},
        "imports": {},
        "interfaces": {},
        "libraries": {}
    }
    
    for file_path, plugin_ast in ast_objects.items():
        if not plugin_ast or "contracts" not in plugin_ast:
            continue
        
        for contract_name, contract_meta in plugin_ast["contracts"].items():
            # Track inheritance
            inherits_from = contract_meta.get("inherits", [])
            if inherits_from:
                relationships["inheritance"][contract_name] = inherits_from
            
            # Track imports
            imports = contract_meta.get("imports", [])
            if imports:
                relationships["imports"][contract_name] = imports
            
            # Track interface implementations
            implements = contract_meta.get("implements", [])
            if implements:
                relationships["interfaces"][contract_name] = implements
            
            # Track library usage
            uses_libraries = contract_meta.get("libraries", [])
            if uses_libraries:
                relationships["libraries"][contract_name] = uses_libraries
    
    return relationships


def generate_security_context(call_graph: Dict[str, Any], 
                            external_call_map: Dict[str, Any],
                            relationships: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate structured security context for LLM analysis.
    
    Args:
        call_graph: Function call graph
        external_call_map: External call analysis
        relationships: Contract relationships
        
    Returns:
        Structured security context
    """
    # Get high-importance functions based on scoring
    high_importance_functions = []
    for fn_sig, fn_meta in call_graph.get("functions", {}).items():
        score = score_function(fn_meta)
        if score >= 5:  # Threshold for high importance
            high_importance_functions.append({
                "signature": fn_sig,
                "score": score,
                "file": fn_meta["file"],
                "visibility": fn_meta["visibility"],
                "external_calls": len(fn_meta["external_calls"]),
                "risk_factors": _identify_risk_factors(fn_meta, external_call_map.get(fn_sig, {}))
            })
    
    # Sort by score descending
    high_importance_functions.sort(key=lambda x: x["score"], reverse=True)
    
    return {
        "high_importance_functions": high_importance_functions[:20],  # Top 20 functions
        "external_call_analysis": external_call_map,
        "contract_relationships": relationships,
        "security_metrics": {
            "total_functions": call_graph.get("metadata", {}).get("total_functions", 0),
            "external_functions": call_graph.get("metadata", {}).get("external_function_count", 0),
            "potential_reentrancy": call_graph.get("metadata", {}).get("potential_reentrancy_points", 0),
            "high_risk_calls": len([
                fn for fn, analysis in external_call_map.items() 
                if analysis.get("risk_level") == "high"
            ])
        }
    }


def _build_graph_structure(functions: Dict[str, Any], 
                           internal_calls: Dict[str, List], 
                           external_calls: Dict[str, List]) -> Dict[str, Any]:
    """
    Build graph structure for visualization.
    
    Args:
        functions: Function metadata
        internal_calls: Internal function calls
        external_calls: External function calls
        
    Returns:
        Graph structure with nodes and edges
    """
    nodes = []
    edges = []
    
    # Create nodes for each function
    for func_sig, func_meta in functions.items():
        nodes.append({
            "id": func_sig,
            "label": func_sig.split(".")[-1] if "." in func_sig else func_sig,
            "type": "function",
            "visibility": func_meta.get("visibility", "private"),
            "complexity": func_meta.get("complexity_score", 0),
            "file": func_meta.get("file", ""),
            "line_number": func_meta.get("line_number", 0),
            "risk_level": _calculate_node_risk_level(func_meta)
        })
    
    # Create edges for internal calls
    for caller, calls in internal_calls.items():
        for call in calls:
            target_sig = call.get("full_signature", call.get("target"))
            if target_sig in functions:
                edges.append({
                    "source": caller,
                    "target": target_sig,
                    "type": "internal_call",
                    "line_offset": call.get("line_offset", 0)
                })
    
    # Create edges for external calls
    for caller, calls in external_calls.items():
        for call in calls:
            # Create external node if it doesn't exist
            external_id = f"external_{call.get('target', 'unknown')}"
            if not any(node["id"] == external_id for node in nodes):
                nodes.append({
                    "id": external_id,
                    "label": call.get("target", "unknown"),
                    "type": "external",
                    "visibility": "external",
                    "complexity": 0,
                    "file": "external",
                    "line_number": 0,
                    "risk_level": "high" if call.get("method") in ["call", "delegatecall"] else "medium"
                })
            
            edges.append({
                "source": caller,
                "target": external_id,
                "type": "external_call",
                "method": call.get("method", "unknown"),
                "line_offset": call.get("line_offset", 0)
            })
    
    # Generate DOT format for Graphviz
    dot_format = _generate_dot_format(nodes, edges)
    
    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "dot_format": dot_format
    }

def _calculate_node_risk_level(func_meta: Dict[str, Any]) -> str:
    """
    Calculate risk level for a function node.
    
    Args:
        func_meta: Function metadata
        
    Returns:
        Risk level string
    """
    risk_score = 0
    
    # External visibility increases risk
    if func_meta.get("visibility") in ["public", "external"]:
        risk_score += 2
    
    # External calls increase risk
    risk_score += len(func_meta.get("external_calls", [])) * 2
    
    # State changes after external calls are high risk
    if func_meta.get("state_change_after_call"):
        risk_score += 3
    
    # Complexity increases risk
    risk_score += func_meta.get("complexity_score", 0) // 3
    
    if risk_score >= 5:
        return "high"
    elif risk_score >= 2:
        return "medium"
    else:
        return "low"

def _generate_dot_format(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """
    Generate DOT format for Graphviz visualization.
    
    Args:
        nodes: List of graph nodes
        edges: List of graph edges
        
    Returns:
        DOT format string
    """
    dot_lines = ["digraph CallGraph {"]
    dot_lines.append("  rankdir=TB;")
    dot_lines.append("  node [shape=box, style=filled];")
    
    # Add nodes with color coding by risk level
    for node in nodes:
        risk_colors = {
            "high": "#ff6b6b",
            "medium": "#ffd93d", 
            "low": "#6bcf7f"
        }
        color = risk_colors.get(node.get("risk_level", "low"), "#e0e0e0")
        
        node_attrs = [
            f'fillcolor="{color}"',
            f'label="{node["label"]}"'
        ]
        
        if node["type"] == "external":
            node_attrs.append('shape=ellipse')
        
        dot_lines.append(f'  "{node["id"]}" [{";".join(node_attrs)}];')
    
    # Add edges with different styles
    for edge in edges:
        edge_attrs = []
        if edge["type"] == "external_call":
            edge_attrs.append('color=red')
            edge_attrs.append('style=dashed')
        else:
            edge_attrs.append('color=blue')
        
        attrs_str = f'[{", ".join(edge_attrs)}]' if edge_attrs else ""
        dot_lines.append(f'  "{edge["source"]}" -> "{edge["target"]}" {attrs_str};')
    
    dot_lines.append("}")
    return "\n".join(dot_lines)

def _identify_risk_factors(fn_meta: Dict[str, Any], call_analysis: Dict[str, Any]) -> List[str]:
    """
    Identify security risk factors for a function.
    
    Args:
        fn_meta: Function metadata
        call_analysis: External call analysis for the function
        
    Returns:
        List of identified risk factors
    """
    risk_factors = []
    
    if is_potentially_reentrant(fn_meta):
        risk_factors.append("potential_reentrancy")
    
    if fn_meta.get("visibility") in ["public", "external"]:
        risk_factors.append("external_access")
    
    if call_analysis.get("risk_level") == "high":
        risk_factors.append("high_risk_external_calls")
    
    if fn_meta.get("state_change_after_call"):
        risk_factors.append("state_mutation_after_external_call")
    
    if not fn_meta.get("modifiers"):
        risk_factors.append("no_access_control")
    
    return risk_factors