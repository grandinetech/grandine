#!/usr/bin/env python3
"""
Static analyzer CLI tool for security analysis of source code repositories.
Pure Python implementation with support for multiple languages via plugins.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Import existing analysis modules
from .static_analysis import build_call_graph
from .plugins.solidity_plugin import SolidityPlugin
from .plugins.javascript_plugin import JavaScriptPlugin


class StaticAnalyzer:
    """Main static analyzer class."""
    
    def __init__(self):
        self.plugins = [
            SolidityPlugin(),
            JavaScriptPlugin()
        ]
    
    def analyze_repository(self, repo_path: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Analyze a source code repository for security issues.
        
        Args:
            repo_path: Path to repository root
            
        Returns:
            Tuple of (AST data, Call graph data)
        """
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
        
        # Collect all source files
        source_files = self._collect_source_files(repo_path)
        
        if not source_files:
            return self._empty_ast_result(str(repo_path)), self._empty_callgraph_result(str(repo_path))
        
        # Analyze files using appropriate plugins
        ast_objects = {}
        for file_path in source_files:
            plugin = self._get_plugin_for_file(file_path)
            if plugin:
                try:
                    ast_data = plugin.build_ast(file_path)
                    if ast_data:
                        ast_objects[file_path] = ast_data
                except Exception as e:
                    print(f"Warning: Failed to analyze {file_path}: {e}", file=sys.stderr)
        
        # Generate call graph
        call_graph = build_call_graph(ast_objects)
        
        # Create AST output
        ast_output = {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "repository_path": str(repo_path),
                "total_files_analyzed": len(ast_objects),
                "analyzer_version": "1.0.0"
            },
            "ast_data": {str(k): v for k, v in ast_objects.items()}
        }
        
        # Create call graph output
        callgraph_output = {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "repository_path": str(repo_path),
                "total_functions": len(call_graph.get("functions", {})),
                "analyzer_version": "1.0.0"
            },
            "call_graph": call_graph
        }
        
        return ast_output, callgraph_output
    
    def _collect_source_files(self, repo_path: Path) -> List[Path]:
        """Collect all source files that can be analyzed."""
        source_files = []
        
        # Get all file extensions supported by plugins
        supported_extensions = set()
        for plugin in self.plugins:
            supported_extensions.update(plugin.extensions())
        
        # Get excluded directories from plugins
        excluded_dirs = set()
        for plugin in self.plugins:
            excluded_dirs.update(plugin.get_excluded_dirs())
        
        # Common additional exclusions
        excluded_dirs.update(['node_modules', '.git', '__pycache__', 'venv', '.env'])
        
        # Walk directory tree
        for path in repo_path.rglob('*'):
            if path.is_file() and path.suffix in supported_extensions:
                # Check if file is in excluded directory
                if not any(excluded_dir in path.parts for excluded_dir in excluded_dirs):
                    source_files.append(path)
        
        return source_files
    
    def _get_plugin_for_file(self, file_path: Path) -> Any:
        """Get appropriate plugin for file extension."""
        file_ext = file_path.suffix
        for plugin in self.plugins:
            if file_ext in plugin.extensions():
                return plugin
        return None
    
    def _empty_ast_result(self, repo_path: str) -> Dict[str, Any]:
        """Return empty AST result when no files found."""
        return {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "repository_path": repo_path,
                "total_files_analyzed": 0,
                "analyzer_version": "1.0.0"
            },
            "ast_data": {}
        }
    
    def _empty_callgraph_result(self, repo_path: str) -> Dict[str, Any]:
        """Return empty call graph result when no files found."""
        return {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "repository_path": repo_path,
                "total_functions": 0,
                "analyzer_version": "1.0.0"
            },
            "call_graph": {
                "functions": {},
                "external_calls": {},
                "metadata": {
                    "total_functions": 0,
                    "external_function_count": 0,
                    "potential_reentrancy_points": 0
                }
            }
        }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Static security analyzer for source code repositories",
        prog="python -m utils.static_analyzer"
    )
    parser.add_argument(
        "repo_path",
        type=Path,
        help="Path to repository to analyze"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs"),
        help="Output directory for analysis results (default: outputs)"
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        analyzer = StaticAnalyzer()
        
        if args.verbose:
            print(f"Analyzing repository: {args.repo_path}")
        
        # Run analysis
        ast_result, callgraph_result = analyzer.analyze_repository(args.repo_path)
        
        if args.verbose:
            print(f"Analyzed {ast_result['analysis_metadata']['total_files_analyzed']} files")
            print(f"Found {callgraph_result['analysis_metadata']['total_functions']} functions")
            
            # Print graph statistics
            call_graph = callgraph_result.get("call_graph", {})
            metadata = call_graph.get("metadata", {})
            graph_structure = call_graph.get("graph_structure", {})
            
            if metadata:
                print(f"External functions: {metadata.get('external_function_count', 0)}")
                print(f"Internal calls: {metadata.get('total_internal_calls', 0)}")
                print(f"External calls: {metadata.get('total_external_calls', 0)}")
                print(f"Potential reentrancy points: {metadata.get('potential_reentrancy_points', 0)}")
            
            if graph_structure:
                print(f"Graph nodes: {graph_structure.get('node_count', 0)}")
                print(f"Graph edges: {graph_structure.get('edge_count', 0)}")
        
        # Create outputs directory
        outputs_dir = args.output_dir
        outputs_dir.mkdir(exist_ok=True)
        
        # Write AST output
        ast_output_path = outputs_dir / "00_AST.json"
        with open(ast_output_path, 'w') as f:
            json.dump(ast_result, f, indent=2, default=str)
        
        # Write call graph output
        callgraph_output_path = outputs_dir / "00_callgraph.json"
        with open(callgraph_output_path, 'w') as f:
            json.dump(callgraph_result, f, indent=2, default=str)
        
        # Create callgraphs directory and write DOT format
        callgraphs_dir = outputs_dir / "callgraphs"
        callgraphs_dir.mkdir(exist_ok=True)
        
        if "graph_structure" in callgraph_result.get("call_graph", {}):
            dot_content = callgraph_result["call_graph"]["graph_structure"].get("dot_format")
            if dot_content:
                dot_output_path = callgraphs_dir / "combined_callgraph.dot"
                with open(dot_output_path, 'w') as f:
                    f.write(dot_content)
                
                if args.verbose:
                    print(f"Combined call graph written to: {dot_output_path}")
        
        # Report on Slither-generated DOT files
        for file_path, plugin_ast in ast_result.get("ast_data", {}).items():
            if plugin_ast.get("dot_files"):
                if args.verbose:
                    print(f"Slither call graphs in: {callgraphs_dir}/")
                    for dot_file in plugin_ast["dot_files"]:
                        dot_name = Path(dot_file).name
                        print(f"  - {dot_name}")
                    print("To visualize: dot -Tpng <file>.dot -o <file>.png")
                break
        
        if args.verbose:
            print(f"AST data written to: {ast_output_path}")
            print(f"Call graph written to: {callgraph_output_path}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())