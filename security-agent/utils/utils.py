"""
Utility functions for security analysis with enhanced plugin support.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

from agents import Agent, Runner, WebSearchTool
from openai import OpenAI

# Import plugin system
from .static_analysis import build_call_graph, generate_security_context, analyze_external_calls, extract_contract_relationships
from .plugins.base_plugin import LanguagePlugin


def create_agent(name: str, model: str, prompt: str) -> Agent:
    """Generic agent factory."""
    return Agent(name=name, model=model, instructions=prompt)


class PluginManager:
    """Manager for language-specific analysis plugins."""
    
    def __init__(self):
        self.plugins = {}
        self._load_plugins()
    
    def _load_plugins(self):
        """Dynamically load all available plugins."""
        try:
            # Load Solidity plugin
            from .plugins.solidity_plugin import SolidityPlugin
            solidity_plugin = SolidityPlugin()
            if solidity_plugin.is_available():
                for ext in solidity_plugin.extensions():
                    self.plugins[ext] = solidity_plugin
                print(f"✅ Loaded SolidityPlugin for {solidity_plugin.extensions()}")
            else:
                print("⚠️  SolidityPlugin dependencies not available")
        except Exception as e:
            print(f"⚠️  Failed to load SolidityPlugin: {e}")
        
        try:
            # Load JavaScript plugin
            from .plugins.javascript_plugin import JavaScriptPlugin
            js_plugin = JavaScriptPlugin()
            if js_plugin.is_available():
                for ext in js_plugin.extensions():
                    self.plugins[ext] = js_plugin
                print(f"✅ Loaded JavaScriptPlugin for {js_plugin.extensions()}")
        except Exception as e:
            print(f"⚠️  Failed to load JavaScriptPlugin: {e}")
    
    def get_supported_extensions(self) -> List[str]:
        """Get all supported file extensions."""
        return list(self.plugins.keys())
    
    def get_plugin_for_file(self, file_path: Path) -> Optional[LanguagePlugin]:
        """Get appropriate plugin for a file."""
        suffix = file_path.suffix.lower()
        return self.plugins.get(suffix)
    
    def get_excluded_dirs(self) -> List[str]:
        """Get all excluded directories from all plugins."""
        excluded = set(['node_modules', '.git', 'build', 'dist', 'out', '.env', '__pycache__'])
        
        for plugin in set(self.plugins.values()):
            excluded.update(plugin.get_excluded_dirs())
        
        return list(excluded)


class DeepResearchRunner:
    """GPT-4o + WebSearch 高速コンテキスト分析エージェント"""
    
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    def run_deep_research(self, service_name: str, system_prompt: str, model: str, document_urls: List[str] = None) -> Dict[str, Any]:
        """GPT-4o + WebSearch で高速コンテキスト分析実行"""
        user_query = f"{service_name}について包括的にリサーチしてください。特に以下の情報を重点的に調査してください：\n"
        user_query += f"- {service_name}の公式ドキュメント、技術仕様\n"
        user_query += f"- {service_name}のBug Bountyプログラム（存在する場合）\n"
        user_query += f"- {service_name}の過去のセキュリティ報告や脆弱性開示\n"
        user_query += f"- {service_name}と同様の技術を使用したサービスでの既知の攻撃パターン\n"
        user_query += f"- {service_name}のアーキテクチャ、セキュリティ機能、権限管理\n"
        
        # Add document URLs if provided
        if document_urls:
            user_query += f"\n**重要**: 以下のドキュメントURLの内容を必ず分析に含めてください：\n"
            for i, url in enumerate(document_urls, 1):
                user_query += f"{i}. {url}\n"
            user_query += "\nこれらのドキュメントの内容を詳細に調査し、セキュリティ分析に活用してください。\n"
        
        user_query += f"\n必要に応じて、Webサーチ、コード解析、ドキュメント検索などのツールを活用してください。"
        
        try:
            print(f"🔬 Creating GPT-4o + WebSearch agent with model: {model}")
            
            # GPT-4o + WebSearch 高速分析エージェント
            research_agent = Agent(
                name="GPT-4o Research Assistant",
                model=model,
                tools=[
                    WebSearchTool(),                                    # 戦略的リアルタイム検索
                ],
                instructions=system_prompt
            )
            
            print(f"🔍 Starting GPT-4o + WebSearch analysis for: {service_name}")
            print("🛠️  Available tools: WebSearch")
            print("⏳ Efficient analysis in progress...")
            
            # エージェント実行
            response = Runner.run_sync(
                starting_agent=research_agent,
                input=user_query
            )
            
            print(f"✅ GPT-4o + WebSearch analysis completed")
            print(f"📊 Response length: {len(str(response.final_output))} characters")
            
            # Extract and return the response
            final_output = response.final_output
            result = self._extract_json_from_response(final_output)
            
            # Add research metadata
            result["research_method"] = "GPT-4o + WebSearch Strategic Analysis"
            result["research_timestamp"] = "2025-01-06"
            result["tools_used"] = ["WebSearchTool"]
            
            return result
            
        except Exception as e:
            print(f"GPT-4o + WebSearch analysis error: {e}")
            # フォールバック結果
            return {
                "error": f"GPT-4o + WebSearch analysis failed: {str(e)}",
                "service_overview": f"{service_name}の分析を実行中にエラーが発生しました。",
                "bug_bounty_scope": "Bug Bountyプログラムの詳細を手動で確認してください。",
                "security_critical_areas": ["権限管理", "アクセス制御", "データ整合性"],
                "potential_attack_points": ["認証回避", "権限昇格", "データ改ざん"],
                "historical_vulnerabilities": ["過去の脆弱性事例を調査中"],
                "research_sources": ["公式ドキュメント", "セキュリティ報告書"],
                "tools_attempted": ["WebSearchTool"]
            }
    
    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from Deep Research response."""
        try:
            if isinstance(response, str):
                # First try to parse the entire response as JSON
                try:
                    return json.loads(response.strip())
                except json.JSONDecodeError:
                    pass
                
                # Try to extract JSON from markdown code blocks
                json_code_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
                if json_code_match:
                    try:
                        return json.loads(json_code_match.group(1))
                    except json.JSONDecodeError:
                        pass
                
                # Try to find JSON object in the response
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
                if json_match:
                    try:
                        # Clean up the JSON string before parsing
                        json_str = json_match.group()
                        # Remove any trailing content after the last }
                        json_str = re.sub(r'\}[^}]*$', '}', json_str)
                        return json.loads(json_str)
                    except json.JSONDecodeError:
                        pass
                
                # Create a fallback response maintaining the original structure
                return {
                    "raw_response": response[:1000] + "..." if len(response) > 1000 else response,
                    "error": "Failed to extract JSON from agent response"
                }
            else:
                return response
        except Exception as e:
            return {"raw_response": str(response), "error": f"Failed to parse response: {str(e)}"}


class DocumentLoader:
    """Document and source code loading utilities with plugin support."""
    
    def __init__(self):
        self.plugin_manager = PluginManager()
    
    @staticmethod
    def load_documents(doc_path: str) -> str:
        """Load all documents from a directory."""
        doc_contents = []
        doc_dir = Path(doc_path)
        
        if not doc_dir.exists():
            return ""
        
        for file_path in doc_dir.rglob("*.md"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    doc_contents.append(f"=== {file_path.name} ===\n{content}\n")
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
                
        return "\n".join(doc_contents)

    def load_source_code(self, source_path: str, extensions: List[str] = None, exclude_test_files: bool = True) -> Dict[str, Any]:
        """Load source code files from a directory with intelligent analysis and AST generation."""
        if extensions is None:
            extensions = self.plugin_manager.get_supported_extensions()
        
        source_dir = Path(source_path)
        
        if not source_dir.exists():
            return {"error": "Source path does not exist", "files": [], "summary": "", "asts": {}}
        
        # Get excluded directories from plugins
        excluded_dirs = self.plugin_manager.get_excluded_dirs()
        
        # Categorize files
        implementation_files = []
        test_files = []
        interface_files = []
        asts = {}  # Store AST data
        
        for ext in extensions:
            for file_path in source_dir.rglob(f"*{ext}"):
                try:
                    rel_path = file_path.relative_to(source_dir)
                    rel_path_str = str(rel_path)
                    
                    # Skip excluded directories
                    if any(skip in rel_path_str for skip in excluded_dirs):
                        continue
                    
                    # Categorize files
                    if any(test_dir in rel_path_str for test_dir in ['test/', 'tests/', '__tests__']) or rel_path_str.endswith('.t.sol'):
                        test_files.append(rel_path)
                    elif rel_path_str.startswith('I') and ext == '.sol':  # Interface files
                        interface_files.append(rel_path)
                    else:
                        implementation_files.append(rel_path)
                        
                        # Generate AST for implementation files
                        plugin = self.plugin_manager.get_plugin_for_file(file_path)
                        if plugin:
                            try:
                                ast_data = plugin.build_ast(file_path)
                                asts[str(rel_path)] = ast_data  # Convert Path to string for JSON serialization
                            except Exception as e:
                                print(f"⚠️  AST generation failed for {file_path}: {e}")
                        
                except Exception as e:
                    print(f"Error categorizing {file_path}: {e}")
        
        # Generate call graph and security context from ASTs
        call_graph = build_call_graph(asts)
        external_call_map = analyze_external_calls(call_graph)
        
        # Load implementation files with intelligent chunking based on importance scoring
        loaded_files = []
        total_chars = 0
        max_total_chars = 12000  # Dynamic token limit (model input limit 60%)
        
        # Prioritize files based on AST analysis and naming
        prioritized_files = self._prioritize_files(implementation_files, asts)
        
        # Load files in priority order using hierarchical approach
        loaded_tokens = 0
        
        for rel_path, priority_score in prioritized_files:
            if loaded_tokens >= max_total_chars:
                break
                
            try:
                file_path = source_dir / rel_path
                plugin = self.plugin_manager.get_plugin_for_file(file_path)
                
                # Read original content
                with open(file_path, "r", encoding="utf-8") as f:
                    original_content = f.read()
                
                # L1: Extract outline (always include if possible)
                outline = self._extract_outline(original_content)
                outline_size = len(outline)
                
                if self._can_add_content(outline_size, loaded_tokens):
                    final_content = f"=== {rel_path} (L1 Outline) ===\n{outline}"
                    loaded_tokens += outline_size
                    
                    # L2: Add hotspots if AST available and space permits
                    if str(rel_path) in asts:
                        ast_data = asts[str(rel_path)]
                        hotspots = self._extract_hotspots(file_path, ast_data, original_content)
                        hotspots_size = len(hotspots)
                        
                        has_hotspots = False
                        if hotspots and self._can_add_content(hotspots_size, loaded_tokens):
                            final_content += f"\n\n=== {rel_path} (L2 HotSpots) ===\n{hotspots}"
                            loaded_tokens += hotspots_size
                            has_hotspots = True
                        elif hotspots:
                            print(f"⚠️ Skipping hotspots for {rel_path} (size: {hotspots_size}, would exceed limit)")
                    
                    loaded_files.append({
                        "path": str(rel_path),
                        "content": final_content,
                        "size": len(final_content),
                        "type": "hierarchical",
                        "priority_score": priority_score,
                        "has_ast": str(rel_path) in asts,
                        "layers_loaded": ["L1"] + (["L2"] if str(rel_path) in asts and has_hotspots else [])
                    })
                    
                    print(f"✅ Loaded {rel_path} (L1+L2: {len(final_content)} chars, total: {loaded_tokens})")
                    
                else:
                    print(f"⚠️ Skipping {rel_path} (outline size: {outline_size}, would exceed limit)")
                    break
                
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        
        total_chars = loaded_tokens
        
        # Create analysis summary  
        l1_loaded = sum(1 for f in loaded_files if "L1" in f.get("layers_loaded", []))
        l2_loaded = sum(1 for f in loaded_files if "L2" in f.get("layers_loaded", []))
        
        summary = f"""Enhanced Hierarchical Source Code Analysis Summary:
- Total files found: {len(implementation_files) + len(test_files) + len(interface_files)}
- Implementation files: {len(implementation_files)}
- Test files: {len(test_files)}
- Interface files: {len(interface_files)}
- Files loaded for analysis: {len(loaded_files)}
- L1 (Outline) loaded: {l1_loaded} files
- L2 (HotSpots) loaded: {l2_loaded} files
- Total characters analyzed: {total_chars}
- AST generated for: {len(asts)} files
- Call graph functions: {call_graph.get('metadata', {}).get('total_functions', 0)}
- External functions: {call_graph.get('metadata', {}).get('external_function_count', 0)}
- Potential reentrancy points: {call_graph.get('metadata', {}).get('potential_reentrancy_points', 0)}

Hierarchical Analysis Results:
"""
        
        if implementation_files:
            summary += "\nImplementation Files:\n"
            for f in implementation_files[:10]:  # Show first 10
                priority = next((score for path, score in prioritized_files if path == f), 0)
                summary += f"- {f} (priority: {priority})\n"
            if len(implementation_files) > 10:
                summary += f"... and {len(implementation_files) - 10} more\n"
        
        if test_files:
            summary += "\nTest Files (excluded from analysis):\n"
            for f in test_files[:5]:  # Show first 5
                summary += f"- {f}\n"
            if len(test_files) > 5:
                summary += f"... and {len(test_files) - 5} more\n"
        
        return {
            "files": loaded_files,
            "summary": summary,
            "file_counts": {
                "implementation": len(implementation_files),
                "test": len(test_files),
                "interface": len(interface_files),
                "loaded": len(loaded_files),
                "l1_loaded": l1_loaded,
                "l2_loaded": l2_loaded
            },
            "total_chars": total_chars,
            "asts": asts,
            "call_graph": call_graph,
            "external_call_map": external_call_map,
            "hierarchical_analysis": {
                "max_token_limit": max_total_chars,
                "tokens_used": total_chars,
                "efficiency": f"{(total_chars/max_total_chars)*100:.1f}%"
            }
        }

    def _prioritize_files(self, files: List[Path], asts: Dict[Path, Any]) -> List[tuple]:
        """Prioritize files based on importance scoring."""
        prioritized = []
        
        for file_path in files:
            score = 0
            file_name = file_path.name.lower()
            
            # Name-based scoring
            important_keywords = ['manager', 'pool', 'token', 'operations', 'registry', 'controller', 'main', 'core']
            score += sum(3 for keyword in important_keywords if keyword in file_name)
            
            # AST-based scoring
            file_path_str = str(file_path)
            if file_path_str in asts:
                ast_data = asts[file_path_str]
                functions = ast_data.get("functions", {})
                
                # Score based on function count and complexity
                score += len(functions)
                score += sum(len(f.get("external_calls", [])) * 2 for f in functions.values())
                score += sum(1 for f in functions.values() if f.get("visibility") in ["public", "external"])
            
            prioritized.append((file_path, score))
        
        # Sort by score descending
        prioritized.sort(key=lambda x: x[1], reverse=True)
        return prioritized
    
    def _create_summary_content(self, file_path: Path, ast_data: Dict[str, Any], summary: Dict[str, Any]) -> str:
        """Create summarized content from AST data."""
        content_parts = [
            f"// File: {file_path}",
            f"// Summary: {summary.get('summary_type', 'unknown')} analysis",
            f"// Functions: {summary.get('functions_count', 0)}",
            f"// Contracts: {summary.get('contracts_count', 0)}",
            ""
        ]
        
        # Add top functions
        for func in summary.get("top_functions", [])[:10]:
            content_parts.append(f"// HIGH PRIORITY: {func['signature']} (score: {func.get('score', 0)})")
            if func.get("risk_factors"):
                content_parts.append(f"//   Risk factors: {', '.join(func['risk_factors'])}")
        
        # Add import information
        imports = summary.get("imports", [])
        if imports:
            content_parts.append("\n// Key imports:")
            for imp in imports[:5]:
                content_parts.append(f"// import {imp}")
        
        return "\n".join(content_parts)
    
    def _can_add_content(self, content_len: int, current_total: int) -> bool:
        """Check if content can be added without exceeding token limit."""
        return (current_total + content_len) <= 12000  # Dynamic token limit
    
    def _extract_outline(self, content: str) -> str:
        """Extract L1 outline: contract/library/interface names and public/external function signatures."""
        lines = content.splitlines()
        outline_lines = []
        
        for line in lines:
            stripped = line.strip()
            # Header info (pragma, import, SPDX)
            if any(keyword in stripped for keyword in ['pragma ', 'import ', 'SPDX-License-Identifier']):
                outline_lines.append(line)
            # Contract/library/interface declarations
            elif re.match(r'\s*(contract|library|interface)\s+\w+', stripped):
                outline_lines.append(line)
            # Public/external function signatures
            elif re.match(r'\s*function\s+\w+.*\b(public|external)\b', stripped):
                outline_lines.append(line)
            # Important modifiers and events
            elif re.match(r'\s*(modifier|event)\s+\w+', stripped):
                outline_lines.append(line)
            
            # Limit outline size
            if len(outline_lines) >= 100:
                break
                
        if len(outline_lines) >= 100:
            outline_lines.append("// ... (outline truncated)")
        
        return "\n".join(outline_lines)
    
    def _extract_hotspots(self, file_path: Path, ast_data: Dict[str, Any], content: str) -> str:
        """Extract L2 hotspots: high-importance functions with partial content."""
        if not ast_data or "functions" not in ast_data:
            return ""
        
        hotspots = []
        functions = ast_data["functions"]
        
        # Sort functions by importance (external/public functions with state changes)
        important_functions = []
        for func_name, func_data in functions.items():
            score = 0
            if func_data.get("visibility") in ["public", "external"]:
                score += 10
            if func_data.get("mutability") in ["nonpayable", "payable"]:  # State changing
                score += 5
            if func_data.get("external_calls"):
                score += 3
            if len(func_data.get("modifiers", [])) > 0:
                score += 2
            
            important_functions.append((func_name, func_data, score))
        
        # Sort by score and take top 2-3 functions
        important_functions.sort(key=lambda x: x[2], reverse=True)
        
        lines = content.splitlines()
        for func_name, func_data, score in important_functions[:2]:
            line_num = func_data.get("line_number", 0)
            if line_num > 0 and line_num <= len(lines):
                # Extract function content (head + tail approach)
                func_start = max(0, line_num - 1)
                func_lines = []
                brace_count = 0
                in_function = False
                
                for i in range(func_start, min(len(lines), func_start + 50)):  # Max 50 lines per function
                    line = lines[i]
                    func_lines.append(line)
                    
                    if 'function' in line and func_name in line:
                        in_function = True
                    
                    if in_function:
                        brace_count += line.count('{') - line.count('}')
                        if brace_count <= 0 and '{' in line:
                            break
                
                if len(func_lines) > 20:
                    # Head + tail approach for long functions
                    head_lines = func_lines[:15]
                    tail_lines = func_lines[-5:]
                    func_content = "\n".join(head_lines) + "\n    // ... (function body truncated)\n" + "\n".join(tail_lines)
                else:
                    func_content = "\n".join(func_lines)
                
                hotspots.append(f"// HIGH PRIORITY: {func_name} (score: {score})\n{func_content}")
        
        return "\n\n".join(hotspots)
    
    def request_full_source(self, source_path: str, target_files: List[str]) -> Dict[str, str]:
        """L3 Deep Analysis: Request full source code for specific files (used for PoC generation)."""
        full_sources = {}
        source_dir = Path(source_path)
        
        for file_name in target_files:
            file_path = source_dir / file_name
            try:
                if file_path.exists():
                    with open(file_path, "r", encoding="utf-8") as f:
                        full_sources[file_name] = f.read()
                    print(f"✅ L3 Deep: Loaded full source for {file_name} ({len(full_sources[file_name])} chars)")
                else:
                    print(f"⚠️ L3 Deep: File not found: {file_name}")
            except Exception as e:
                print(f"❌ L3 Deep: Error loading {file_name}: {e}")
        
        return full_sources
    
    def _create_fallback_summary(self, content: str) -> str:
        """Create fallback summary for files without AST."""
        lines = content.split('\n')
        summary_lines = []
        
        for line in lines:
            stripped = line.strip()
            if any(keyword in stripped for keyword in ['contract ', 'interface ', 'library ', 'function ', 'class ', 'def ']):
                summary_lines.append(line)
            if len(summary_lines) >= 30:  # Reduced from 50
                break
        
        summary_lines.append("\n// ... (file truncated for analysis)")
        return "\n".join(summary_lines)
    
    @staticmethod
    def prepare_context(doc_path: str = None, source_path: str = None) -> Dict[str, Any]:
        """Prepare enhanced context dictionary with documents and source code analysis."""
        context = {}
        loader = DocumentLoader()
        
        if doc_path:
            docs = DocumentLoader.load_documents(doc_path)
            if docs:
                context["reference_documents"] = docs[:5000]  # Limit size
                
        if source_path:
            source_analysis = loader.load_source_code(source_path)
            if source_analysis and "files" in source_analysis:
                # Create structured context
                context["source_code_analysis"] = {
                    "summary": source_analysis.get("summary", ""),
                    "file_counts": source_analysis.get("file_counts", {}),
                    "total_chars": source_analysis.get("total_chars", 0)
                }
                
                # Add enhanced AST and call graph information
                if "asts" in source_analysis:
                    context["asts"] = source_analysis["asts"]
                
                if "call_graph" in source_analysis:
                    context["call_graph"] = source_analysis["call_graph"]
                
                if "external_call_map" in source_analysis:
                    context["external_call_map"] = source_analysis["external_call_map"]
                
                # Add hierarchical source code content
                source_content = ""
                for file_info in source_analysis["files"]:
                    # Content is already formatted with headers in hierarchical mode
                    if file_info.get("type") == "hierarchical":
                        source_content += "\n" + file_info["content"] + "\n"
                    else:
                        # Fallback for non-hierarchical files
                        source_content += f"\n=== {file_info['path']} ==="
                        if file_info.get("has_ast"):
                            source_content += f" (Priority: {file_info.get('priority_score', 0)}) "
                        source_content += "\n"
                        source_content += file_info["content"]
                        source_content += "\n"
                
                context["target_source_code"] = source_content
                
                # Add enhanced contract analysis
                if any(f["path"].endswith(".sol") for f in source_analysis["files"]):
                    context["contract_analysis"] = DocumentLoader._analyze_solidity_contracts(source_analysis["files"])
                
                # Add security context from static analysis
                if "call_graph" in source_analysis and "external_call_map" in source_analysis:
                    relationships = extract_contract_relationships(source_analysis["asts"])
                    security_context = generate_security_context(
                        source_analysis["call_graph"],
                        source_analysis["external_call_map"],
                        relationships
                    )
                    context["security_context"] = security_context
                
        return context
    
    @staticmethod
    def _analyze_solidity_contracts(files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze Solidity contracts for relationships and key functions."""
        contracts = {}
        imports = {}
        
        for file_info in files:
            if not file_info["path"].endswith(".sol"):
                continue
                
            content = file_info["content"]
            file_path = file_info["path"]
            
            # Extract contract/interface/library definitions
            contract_matches = re.findall(r'(contract|interface|library)\s+(\w+)', content)
            if contract_matches:
                contracts[file_path] = {
                    "definitions": contract_matches,
                    "functions": [],
                    "modifiers": [],
                    "events": [],
                    "imports": []
                }
                
                # Extract functions
                function_matches = re.findall(r'function\s+(\w+)\s*\([^)]*\)\s*[^{]*', content)
                contracts[file_path]["functions"] = function_matches
                
                # Extract modifiers
                modifier_matches = re.findall(r'modifier\s+(\w+)', content)
                contracts[file_path]["modifiers"] = modifier_matches
                
                # Extract events
                event_matches = re.findall(r'event\s+(\w+)', content)
                contracts[file_path]["events"] = event_matches
                
                # Extract imports
                import_matches = re.findall(r'import\s+["\']([^"\']+)["\']', content)
                contracts[file_path]["imports"] = import_matches
        
        return {
            "contracts": contracts,
            "total_contracts": len(contracts),
            "analysis_note": "Contract relationships and key functions extracted for security analysis"
        }


class AgentRunner:
    """Utility class for running agents with enhanced JSON extraction."""
    
    @staticmethod
    def extract_json_from_response(response: str) -> Dict[str, Any]:
        """Extract JSON from agent response with enhanced parsing."""
        try:
            if isinstance(response, str):
                # First try to parse the entire response as JSON
                try:
                    return json.loads(response.strip())
                except json.JSONDecodeError:
                    pass
                
                # Try to extract JSON from markdown code blocks
                json_code_patterns = [
                    r'```(?:json)?\s*({.*?})\s*```',
                    r'```(?:json)?\s*(\[.*?\])\s*```'
                ]
                
                for pattern in json_code_patterns:
                    match = re.search(pattern, response, re.DOTALL)
                    if match:
                        try:
                            return json.loads(match.group(1))
                        except json.JSONDecodeError:
                            continue
                
                # Try to find JSON object in the response
                json_patterns = [
                    r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
                    r'\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]'
                ]
                
                for pattern in json_patterns:
                    match = re.search(pattern, response, re.DOTALL)
                    if match:
                        try:
                            json_str = match.group()
                            # Clean up common issues
                            json_str = re.sub(r'\}[^}]*$', '}', json_str)  # Remove trailing content
                            json_str = re.sub(r',$(?=\s*[}\]])', '', json_str, flags=re.MULTILINE)  # Remove trailing commas
                            return json.loads(json_str)
                        except json.JSONDecodeError:
                            continue
                
                
                return {"raw_response": response[:1000] + "..." if len(response) > 1000 else response}
            else:
                return response
        except Exception as e:
            return {"raw_response": str(response), "parse_error": str(e)}
    
    @staticmethod
    def run_agent_with_json_extraction(agent, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run agent and extract JSON from response with validation."""
        try:
            response = Runner.run_sync(
                starting_agent=agent,
                input=json.dumps(input_data, ensure_ascii=False, indent=2)
            )
            
            result = AgentRunner.extract_json_from_response(response.final_output)
            
            # Validate result structure
            if "raw_response" in result and len(result) == 1:
                print(f"⚠️  Failed to extract JSON from agent response, using raw response")
            
            return result
            
        except Exception as e:
            print(f"⚠️  Agent execution failed: {e}")
            return {"error": str(e), "agent_name": getattr(agent, 'name', 'unknown')}
    
    @staticmethod
    def save_output(filepath: str, data: Any) -> str:
        """Save output to file with enhanced formatting."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                if isinstance(data, (dict, list)):
                    json.dump(data, f, ensure_ascii=False, indent=2)
                else:
                    f.write(str(data))
            
            print(f"💾 Saved output to {filepath}")
            return filepath
            
        except Exception as e:
            print(f"⚠️  Failed to save output to {filepath}: {e}")
            return filepath


class ScenarioProcessor:
    """Utility class for processing attack scenarios and reviews."""
    
    @staticmethod
    def get_approved_scenarios(scenarios_json: Dict[str, Any], 
                             reviews_json: Dict[str, Any], 
                             loop_number: int) -> list:
        """Extract approved scenarios from scenarios and reviews."""
        approved_scenarios = []
        
        if "reviews" in reviews_json:
            for i, review in enumerate(reviews_json["reviews"]):
                if review.get("status", "").upper() == "OK":
                    if i < len(scenarios_json.get("scenarios", [])):
                        approved_scenarios.append({
                            "scenario": scenarios_json["scenarios"][i],
                            "review": review,
                            "loop_number": loop_number
                        })
        
        return approved_scenarios
    
    @staticmethod
    def create_approved_data(approved_scenarios: list, 
                           reviews_json: Dict[str, Any], 
                           scenarios_json: Dict[str, Any], 
                           loop_number: int) -> Dict[str, Any]:
        """Create approved scenarios data structure."""
        return {
            "approved_scenarios": approved_scenarios,
            "overall_review": reviews_json.get("overall_comment", ""),
            "total_approved": len(approved_scenarios),
            "total_scenarios": len(scenarios_json.get("scenarios", [])),
            "loop_number": loop_number
        }