"""
Solidity language plugin for AST analysis using multiple approaches.
"""

import re
import subprocess
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from .base_plugin import LanguagePlugin


class SolidityPlugin(LanguagePlugin):
    """Solidity analysis plugin with fallback parsing strategies."""
    
    def extensions(self) -> List[str]:
        return ['.sol']
    
    def get_excluded_dirs(self) -> List[str]:
        return ['node_modules', 'lib/openzeppelin', 'lib/forge-std', 'out', 'cache']
    
    def is_available(self) -> bool:
        """Check if Solidity analysis tools are available."""
        # Use regex parsing (always available)
        return True
    
    def build_ast(self, file_path: Path) -> Dict[str, Any]:
        """
        Build AST for Solidity file using Slither if available, with regex fallback.
        
        Args:
            file_path: Path to Solidity file
            
        Returns:
            AST data dictionary
        """
        # Try Slither first for better accuracy
        slither_result = self._build_ast_with_slither(file_path)
        if slither_result and "error" not in slither_result:
            return slither_result
        
        # Fallback to regex parsing
        return self._build_ast_with_regex(file_path)
    
    
    def _build_ast_with_regex(self, file_path: Path) -> Dict[str, Any]:
        """Build AST using regex-based parsing."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return self._parse_solidity_content(content, file_path)
            
        except Exception as e:
            return {
                "plugin": "SolidityPlugin",
                "method": "regex_fallback",
                "error": str(e),
                "contracts": {},
                "functions": {},
                "imports": []
            }
    
    def _build_ast_with_slither(self, file_path: Path) -> Dict[str, Any]:
        """Build AST using Slither static analyzer."""
        try:
            # Run Slither on the file's directory to get call graph
            project_root = self._find_project_root(file_path)
            if not project_root:
                return {"error": "Could not find project root"}
            
            # Run Slither with JSON output
            cmd = [
                "slither", str(project_root),
                "--print", "call-graph",
                "--json", "-",
                "--disable-color"
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=project_root,
                timeout=60
            )
            
            if result.returncode != 0:
                return {"error": f"Slither failed: {result.stderr}"}
            
            # Parse Slither JSON output
            slither_data = json.loads(result.stdout) if result.stdout.strip() else {}
            
            # Convert Slither data to our format
            return self._convert_slither_to_ast(slither_data, file_path, project_root)
            
        except subprocess.TimeoutExpired:
            return {"error": "Slither timeout"}
        except Exception as e:
            return {"error": f"Slither execution failed: {str(e)}"}
    
    def _find_project_root(self, file_path: Path) -> Optional[Path]:
        """Find the project root by looking for foundry.toml, hardhat.config.js, etc."""
        current = file_path.parent
        
        # Look for common Solidity project files
        project_files = [
            "foundry.toml", "hardhat.config.js", "hardhat.config.ts", 
            "truffle-config.js", "package.json", "dapp", "brownie-config.yaml"
        ]
        
        while current != current.parent:  # Not at filesystem root
            for project_file in project_files:
                if (current / project_file).exists():
                    return current
            current = current.parent
        
        return None
    
    def _convert_slither_to_ast(self, slither_data: Dict[str, Any], file_path: Path, project_root: Path) -> Dict[str, Any]:
        """Convert Slither output to our AST format."""
        try:
            functions = {}
            contracts = {}
            
            # Look for call graph DOT files
            dot_files = list(project_root.glob("*.call-graph.dot"))
            
            if dot_files:
                # Parse the main call graph
                all_contracts_dot = next((f for f in dot_files if "all_contracts" in f.name), None)
                if all_contracts_dot:
                    functions, contracts = self._parse_dot_file(all_contracts_dot)
            
            # If we have Slither JSON data, enhance with that info
            if "printers" in slither_data:
                for printer in slither_data["printers"]:
                    if "call-graph" in printer.get("type", ""):
                        # Enhance with Slither printer data
                        pass
            
            return {
                "plugin": "SolidityPlugin",
                "method": "slither",
                "pragma_version": "unknown",
                "contracts": contracts,
                "functions": functions,
                "imports": [],
                "slither_available": True,
                "dot_files": [str(f) for f in dot_files]
            }
            
        except Exception as e:
            return {"error": f"Failed to convert Slither data: {str(e)}"}
    
    def _parse_dot_file(self, dot_file: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """Parse Slither-generated DOT file to extract function relationships."""
        functions = {}
        contracts = {}
        
        try:
            with open(dot_file, 'r') as f:
                dot_content = f.read()
            
            # Extract subgraph clusters (contracts)
            subgraph_pattern = r'subgraph cluster_\d+_(\w+) \{\s*label = "(\w+)"'
            contract_matches = re.finditer(subgraph_pattern, dot_content)
            
            for match in contract_matches:
                contract_name = match.group(2)
                contracts[contract_name] = {
                    "type": "contract",
                    "inherits": [],
                    "line_number": 0
                }
            
            # Extract function nodes
            node_pattern = r'"(\d+)_(\w+)" \[label="(\w+)"\]'
            node_matches = re.finditer(node_pattern, dot_content)
            
            for match in node_matches:
                contract_id = match.group(1)
                func_name = match.group(3)
                
                # Find the contract for this function
                contract_name = self._find_contract_for_function(dot_content, contract_id)
                func_signature = f"{contract_name}.{func_name}" if contract_name else func_name
                
                functions[func_signature] = {
                    "visibility": "public",  # Slither usually shows public functions
                    "mutability": "nonpayable",
                    "external_calls": [],
                    "internal_calls": [],
                    "state_change_after": False,
                    "complexity_score": 1,
                    "parameters": [],
                    "return_type": "void",
                    "modifiers": [],
                    "line_number": 0,
                    "contract": contract_name or "unknown"
                }
            
            # Extract edges (function calls)
            edge_pattern = r'"(\d+_\w+)" -> "(\d+_\w+)"'
            edge_matches = re.finditer(edge_pattern, dot_content)
            
            for match in edge_matches:
                source = match.group(1)
                target = match.group(2)
                
                # Find the corresponding function and add the call
                source_func = self._find_function_by_node_id(functions, source)
                target_func = self._find_function_by_node_id(functions, target)
                
                if source_func and target_func:
                    if source_func not in functions:
                        continue
                    
                    # Determine if it's internal or external call
                    source_contract = functions[source_func].get("contract")
                    target_contract = functions[target_func].get("contract")
                    
                    call_info = {
                        "target": target_func.split(".")[-1],
                        "full_signature": target_func,
                        "call_type": "internal" if source_contract == target_contract else "external",
                        "line_offset": 0
                    }
                    
                    if call_info["call_type"] == "internal":
                        functions[source_func]["internal_calls"].append(call_info)
                    else:
                        functions[source_func]["external_calls"].append(call_info)
            
            return functions, contracts
            
        except Exception as e:
            print(f"Warning: Failed to parse DOT file {dot_file}: {e}")
            return {}, {}
    
    def _find_contract_for_function(self, dot_content: str, contract_id: str) -> Optional[str]:
        """Find which contract a function belongs to based on its ID."""
        # Look for the subgraph that contains this contract_id
        pattern = f'subgraph cluster_{contract_id}_(\\w+)'
        match = re.search(pattern, dot_content)
        return match.group(1) if match else None
    
    def _find_function_by_node_id(self, functions: Dict[str, Any], node_id: str) -> Optional[str]:
        """Find function signature by node ID."""
        # Extract function name from node_id (format: contract_id_function_name)
        parts = node_id.split("_", 1)
        if len(parts) < 2:
            return None
        
        func_name = parts[1]
        
        # Find the function with this name
        for func_sig in functions.keys():
            if func_sig.endswith(f".{func_name}") or func_sig == func_name:
                return func_sig
        
        return None
    
    
    def _parse_solidity_content(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Parse Solidity content using regex patterns."""
        contracts = {}
        functions = {}
        imports = []
        
        # Extract pragma version
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
        pragma_version = pragma_match.group(1) if pragma_match else "unknown"
        
        # Extract imports
        import_matches = re.findall(r'import\s+["\']([^"\']+)["\']', content)
        imports = import_matches
        
        # Extract contracts
        contract_pattern = r'(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
        contract_matches = re.finditer(contract_pattern, content)
        
        for match in contract_matches:
            contract_type = match.group(1)
            contract_name = match.group(2)
            inherits = match.group(3).strip() if match.group(3) else ""
            
            contracts[contract_name] = {
                "type": contract_type,
                "inherits": [x.strip() for x in inherits.split(',') if x.strip()],
                "line_number": content[:match.start()].count('\n') + 1
            }
        
        # Extract functions
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\{'
        function_matches = re.finditer(function_pattern, content)
        
        for match in function_matches:
            func_name = match.group(1)
            func_modifiers = match.group(2).strip()
            
            # Determine contract for this function
            func_start = match.start()
            current_contract = self._find_containing_contract(content, func_start, contracts)
            
            func_sig = f"{current_contract}.{func_name}" if current_contract else func_name
            
            # Parse visibility and mutability
            visibility = self._extract_visibility(func_modifiers)
            mutability = self._extract_mutability(func_modifiers)
            modifiers = self._extract_modifiers(func_modifiers)
            
            # Analyze function body for calls
            func_body = self._extract_function_body(content, match.end())
            external_calls = self._find_external_calls(func_body)
            state_change_after = self._has_state_changes_after_calls(func_body)
            
            functions[func_sig] = {
                "visibility": visibility,
                "mutability": mutability,
                "external_calls": external_calls,
                "internal_calls": [],  # Will be populated in second pass
                "state_change_after": state_change_after,
                "complexity_score": self._calculate_complexity_from_body(func_body),
                "parameters": [],  # Would need more complex parsing
                "return_type": "void",  # Would need more complex parsing
                "modifiers": modifiers,
                "line_number": content[:match.start()].count('\n') + 1,
                "body": func_body  # Store for second pass analysis
            }
        
        # Second pass: analyze internal calls now that we have all functions
        for func_sig, func_data in functions.items():
            if "body" in func_data:
                internal_calls = self._find_internal_calls(func_data["body"], functions)
                func_data["internal_calls"] = internal_calls
                # Remove body to keep output clean
                del func_data["body"]
        
        return {
            "plugin": "SolidityPlugin",
            "method": "regex",
            "pragma_version": pragma_version,
            "contracts": contracts,
            "functions": functions,
            "imports": imports
        }
    
    def _find_containing_contract(self, content: str, position: int, contracts: Dict[str, Any]) -> Optional[str]:
        """Find which contract contains a function at given position."""
        content_before = content[:position]
        
        # Find the last contract declaration before this position
        contract_pattern = r'(contract|interface|library)\s+(\w+)'
        matches = list(re.finditer(contract_pattern, content_before))
        
        if matches:
            return matches[-1].group(2)
        return None
    
    def _extract_visibility(self, modifiers: str) -> str:
        """Extract visibility from function modifiers."""
        if 'public' in modifiers:
            return 'public'
        elif 'external' in modifiers:
            return 'external'
        elif 'internal' in modifiers:
            return 'internal'
        else:
            return 'private'
    
    def _extract_mutability(self, modifiers: str) -> str:
        """Extract state mutability from function modifiers."""
        if 'pure' in modifiers:
            return 'pure'
        elif 'view' in modifiers:
            return 'view'
        elif 'payable' in modifiers:
            return 'payable'
        else:
            return 'nonpayable'
    
    def _extract_modifiers(self, modifiers: str) -> List[str]:
        """Extract custom modifiers from function declaration."""
        # Simple heuristic: words that are not keywords
        keywords = {'public', 'private', 'external', 'internal', 'view', 'pure', 'payable', 'override', 'virtual'}
        words = re.findall(r'\b\w+\b', modifiers)
        return [word for word in words if word not in keywords]
    
    def _extract_function_body(self, content: str, start_pos: int) -> str:
        """Extract function body starting from given position."""
        brace_count = 1
        pos = start_pos
        
        while pos < len(content) and brace_count > 0:
            char = content[pos]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            pos += 1
        
        return content[start_pos:pos-1] if brace_count == 0 else ""
    
    def _find_external_calls(self, func_body: str) -> List[Dict[str, Any]]:
        """Find external calls in function body."""
        external_calls = []
        
        # Pattern for contract calls: contractVar.method()
        call_patterns = [
            r'(\w+)\.(\w+)\s*\(',
            r'(address|payable)\s*\([^)]+\)\.call\s*\(',
            r'(\w+)\.transfer\s*\(',
            r'(\w+)\.send\s*\('
        ]
        
        for pattern in call_patterns:
            matches = re.finditer(pattern, func_body)
            for match in matches:
                external_calls.append({
                    "target": match.group(1),
                    "method": match.group(2) if len(match.groups()) > 1 else "call",
                    "line_offset": func_body[:match.start()].count('\n')
                })
        
        return external_calls
    
    def _find_internal_calls(self, func_body: str, functions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find internal function calls within the same contract or project."""
        internal_calls = []
        
        # Pattern for function calls: functionName()
        function_call_pattern = r'\b(\w+)\s*\('
        matches = re.finditer(function_call_pattern, func_body)
        
        for match in matches:
            called_function = match.group(1)
            
            # Skip common keywords and operators
            if called_function in ['if', 'for', 'while', 'require', 'assert', 'revert', 'emit', 'return']:
                continue
            
            # Check if it's a known function in our analysis
            for func_sig in functions.keys():
                if func_sig.endswith(f'.{called_function}') or func_sig == called_function:
                    internal_calls.append({
                        "target": called_function,
                        "full_signature": func_sig,
                        "call_type": "internal",
                        "line_offset": func_body[:match.start()].count('\n')
                    })
                    break
        
        return internal_calls
    
    def _has_state_changes_after_calls(self, func_body: str) -> bool:
        """Check if there are state changes after external calls."""
        # Simple heuristic: look for assignment operations after call patterns
        lines = func_body.split('\n')
        
        for i, line in enumerate(lines):
            if any(pattern in line for pattern in ['.call(', '.transfer(', '.send(']):
                # Check subsequent lines for state changes
                for j in range(i + 1, len(lines)):
                    if re.search(r'\w+\s*[\+\-\*\/]?=', lines[j]):
                        return True
        
        return False
    
    def _calculate_complexity_from_body(self, func_body: str) -> int:
        """Calculate complexity score from function body."""
        complexity = 0
        
        # Count control flow statements
        complexity += len(re.findall(r'\b(if|for|while|do)\b', func_body))
        
        # Count external calls
        complexity += len(re.findall(r'\.\w+\s*\(', func_body))
        
        # Count state variable assignments
        complexity += len(re.findall(r'\w+\s*=', func_body))
        
        return complexity
    
    
    def summarize(self, ast_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary from Solidity AST data."""
        functions = ast_data.get("functions", {})
        contracts = ast_data.get("contracts", {})
        
        # Get top functions by importance
        top_functions = []
        for func_sig, func_data in functions.items():
            score = (
                len(func_data.get("external_calls", [])) * 3 +
                (2 if func_data.get("state_change_after") else 0) +
                func_data.get("complexity_score", 0)
            )
            
            if score >= 3:  # Threshold for inclusion
                top_functions.append({
                    "signature": func_sig,
                    "visibility": func_data.get("visibility"),
                    "score": score,
                    "risk_factors": self._identify_risk_factors(func_data)
                })
        
        # Sort by score
        top_functions.sort(key=lambda x: x["score"], reverse=True)
        
        return {
            "summary_type": "solidity_analysis",
            "contracts_count": len(contracts),
            "functions_count": len(functions),
            "external_functions": len([f for f in functions.values() if f.get("visibility") in ["public", "external"]]),
            "top_functions": top_functions[:10],  # Top 10 functions
            "pragma_version": ast_data.get("pragma_version", "unknown"),
            "imports": ast_data.get("imports", []),
            "analysis_method": ast_data.get("method", "unknown"),
            "slither_available": ast_data.get("slither_available", False),
            "dot_files": ast_data.get("dot_files", [])
        }
    
    def _identify_risk_factors(self, func_data: Dict[str, Any]) -> List[str]:
        """Identify risk factors for a function."""
        risks = []
        
        if func_data.get("external_calls"):
            risks.append("external_calls")
        
        if func_data.get("state_change_after"):
            risks.append("state_change_after_call")
        
        if func_data.get("visibility") in ["public", "external"]:
            risks.append("external_access")
        
        if func_data.get("mutability") == "payable":
            risks.append("payable")
        
        return risks