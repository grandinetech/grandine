"""
JavaScript/TypeScript language plugin for AST analysis.
"""

import re
import json
from typing import Dict, Any, List
from pathlib import Path
from .base_plugin import LanguagePlugin


class JavaScriptPlugin(LanguagePlugin):
    """JavaScript/TypeScript analysis plugin."""
    
    def extensions(self) -> List[str]:
        return ['.js', '.ts', '.jsx', '.tsx']
    
    def get_excluded_dirs(self) -> List[str]:
        return ['node_modules', 'dist', 'build', '.next', 'coverage']
    
    def is_available(self) -> bool:
        """JavaScript parsing is always available with regex fallback."""
        return True
    
    def build_ast(self, file_path: Path) -> Dict[str, Any]:
        """
        Build AST for JavaScript/TypeScript file.
        
        Args:
            file_path: Path to JavaScript/TypeScript file
            
        Returns:
            AST data dictionary
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return self._parse_javascript_content(content, file_path)
            
        except Exception as e:
            return {
                "plugin": "JavaScriptPlugin",
                "method": "regex",
                "error": str(e),
                "functions": {},
                "classes": {},
                "imports": []
            }
    
    def _parse_javascript_content(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Parse JavaScript content using regex patterns."""
        functions = {}
        classes = {}
        imports = []
        
        # Extract imports/requires
        import_patterns = [
            r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
            r'require\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'import\s*\(\s*["\']([^"\']+)["\']\s*\)'
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, content)
            imports.extend(matches)
        
        # Extract classes
        class_pattern = r'class\s+(\w+)(?:\s+extends\s+(\w+))?\s*\{'
        class_matches = re.finditer(class_pattern, content)
        
        for match in class_matches:
            class_name = match.group(1)
            extends = match.group(2)
            
            classes[class_name] = {
                "extends": extends,
                "line_number": content[:match.start()].count('\n') + 1
            }
        
        # Extract functions (regular functions, arrow functions, methods)
        function_patterns = [
            r'function\s+(\w+)\s*\([^)]*\)\s*\{',  # Regular functions
            r'(\w+)\s*:\s*function\s*\([^)]*\)\s*\{',  # Object methods
            r'(\w+)\s*\([^)]*\)\s*\{',  # Class methods
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',  # Arrow functions
            r'(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{'  # Arrow function assignments
        ]
        
        for pattern in function_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                func_name = match.group(1)
                
                # Determine containing class if any
                func_start = match.start()
                containing_class = self._find_containing_class(content, func_start, classes)
                
                func_sig = f"{containing_class}.{func_name}" if containing_class else func_name
                
                # Analyze function body
                func_body = self._extract_function_body_js(content, match.end())
                external_calls = self._find_external_calls_js(func_body)
                async_calls = self._find_async_calls(func_body)
                
                functions[func_sig] = {
                    "visibility": "public",  # JavaScript doesn't have explicit visibility
                    "mutability": "mutable",  # JavaScript is always mutable
                    "external_calls": external_calls,
                    "async_calls": async_calls,
                    "state_change_after": self._has_state_changes_js(func_body),
                    "complexity_score": self._calculate_complexity_js(func_body),
                    "parameters": [],  # Would need more complex parsing
                    "return_type": "any",  # JavaScript is dynamically typed
                    "modifiers": self._extract_js_modifiers(content, match.start()),
                    "line_number": content[:match.start()].count('\n') + 1
                }
        
        return {
            "plugin": "JavaScriptPlugin",
            "method": "regex",
            "functions": functions,
            "classes": classes,
            "imports": imports
        }
    
    def _find_containing_class(self, content: str, position: int, classes: Dict[str, Any]) -> str:
        """Find which class contains a function at given position."""
        content_before = content[:position]
        
        # Find the last class declaration before this position
        class_pattern = r'class\s+(\w+)'
        matches = list(re.finditer(class_pattern, content_before))
        
        if matches:
            return matches[-1].group(1)
        return None
    
    def _extract_function_body_js(self, content: str, start_pos: int) -> str:
        """Extract JavaScript function body."""
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
    
    def _find_external_calls_js(self, func_body: str) -> List[Dict[str, Any]]:
        """Find external calls in JavaScript function body."""
        external_calls = []
        
        # Pattern for method calls: object.method()
        call_patterns = [
            r'(\w+)\.(\w+)\s*\(',
            r'await\s+(\w+)\.(\w+)\s*\(',
            r'(\w+)\[(["\']?\w+["\']?)\]\s*\('
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
    
    def _find_async_calls(self, func_body: str) -> List[Dict[str, Any]]:
        """Find async calls and promises in function body."""
        async_calls = []
        
        # Pattern for async operations
        async_patterns = [
            r'await\s+(\w+)',
            r'\.then\s*\(',
            r'\.catch\s*\(',
            r'Promise\.\w+\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]
        
        for pattern in async_patterns:
            matches = re.finditer(pattern, func_body)
            for match in matches:
                async_calls.append({
                    "type": "async_operation",
                    "pattern": match.group(0),
                    "line_offset": func_body[:match.start()].count('\n')
                })
        
        return async_calls
    
    def _has_state_changes_js(self, func_body: str) -> bool:
        """Check if there are state changes in JavaScript function."""
        # Look for assignment operations
        assignment_patterns = [
            r'\w+\s*[+\-*/%]?=',
            r'\w+\.\w+\s*=',
            r'\w+\[\w+\]\s*=',
            r'this\.\w+\s*='
        ]
        
        for pattern in assignment_patterns:
            if re.search(pattern, func_body):
                return True
        
        return False
    
    def _calculate_complexity_js(self, func_body: str) -> int:
        """Calculate complexity score from JavaScript function body."""
        complexity = 0
        
        # Count control flow statements
        complexity += len(re.findall(r'\b(if|for|while|do|switch|try|catch)\b', func_body))
        
        # Count function calls
        complexity += len(re.findall(r'\w+\s*\(', func_body))
        
        # Count async operations
        complexity += len(re.findall(r'\b(await|then|catch)\b', func_body))
        
        return complexity
    
    def _extract_js_modifiers(self, content: str, func_pos: int) -> List[str]:
        """Extract JavaScript function modifiers (async, static, etc.)."""
        modifiers = []
        
        # Look backwards from function position for modifiers
        content_before = content[:func_pos]
        line_start = content_before.rfind('\n') + 1
        line_content = content[line_start:func_pos]
        
        if 'async' in line_content:
            modifiers.append('async')
        if 'static' in line_content:
            modifiers.append('static')
        if 'export' in line_content:
            modifiers.append('export')
        
        return modifiers
    
    def summarize(self, ast_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary from JavaScript AST data."""
        functions = ast_data.get("functions", {})
        classes = ast_data.get("classes", {})
        
        # Get top functions by importance
        top_functions = []
        for func_sig, func_data in functions.items():
            score = (
                len(func_data.get("external_calls", [])) * 2 +
                len(func_data.get("async_calls", [])) * 2 +
                (2 if func_data.get("state_change_after") else 0) +
                func_data.get("complexity_score", 0)
            )
            
            if score >= 3:  # Threshold for inclusion
                top_functions.append({
                    "signature": func_sig,
                    "score": score,
                    "modifiers": func_data.get("modifiers", []),
                    "risk_factors": self._identify_js_risk_factors(func_data)
                })
        
        # Sort by score
        top_functions.sort(key=lambda x: x["score"], reverse=True)
        
        return {
            "summary_type": "javascript_analysis",
            "classes_count": len(classes),
            "functions_count": len(functions),
            "async_functions": len([f for f in functions.values() if 'async' in f.get("modifiers", [])]),
            "top_functions": top_functions[:10],  # Top 10 functions
            "imports": ast_data.get("imports", [])
        }
    
    def _identify_js_risk_factors(self, func_data: Dict[str, Any]) -> List[str]:
        """Identify risk factors for a JavaScript function."""
        risks = []
        
        if func_data.get("external_calls"):
            risks.append("external_calls")
        
        if func_data.get("async_calls"):
            risks.append("async_operations")
        
        if func_data.get("state_change_after"):
            risks.append("state_mutations")
        
        if 'async' in func_data.get("modifiers", []):
            risks.append("async_function")
        
        return risks