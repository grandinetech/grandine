"""
Base plugin interface for language-specific AST analysis.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pathlib import Path


class LanguagePlugin(ABC):
    """Abstract base class for language-specific analysis plugins."""
    
    @abstractmethod
    def extensions(self) -> List[str]:
        """
        Return list of file extensions this plugin handles.
        
        Returns:
            List of file extensions (e.g., ['.sol', '.vy'])
        """
        pass
    
    @abstractmethod
    def build_ast(self, file_path: Path) -> Dict[str, Any]:
        """
        Build AST for a source file.
        
        Args:
            file_path: Path to source file
            
        Returns:
            Dictionary containing AST information
        """
        pass
    
    @abstractmethod
    def summarize(self, ast_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create summary from AST data.
        
        Args:
            ast_data: AST data from build_ast()
            
        Returns:
            Summarized AST information
        """
        pass
    
    def name(self) -> str:
        """Return plugin name."""
        return self.__class__.__name__
    
    def is_available(self) -> bool:
        """Check if plugin dependencies are available."""
        return True
    
    def get_excluded_dirs(self) -> List[str]:
        """Get list of directories to exclude for this language."""
        return []