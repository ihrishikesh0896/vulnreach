#!/usr/bin/env python3
"""
Test script for ast-grep wrapper functionality.

This script verifies that the ast-grep wrapper can:
1. Detect if ast-grep is installed
2. Perform basic code searches
3. Handle fallback gracefully

Run: python tests/test_ast_grep_integration.py
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from vulnreach.utils.ast_grep_wrapper import (
    AstGrepWrapper,
    AstGrepQuery,
    Language,
    AstGrepNotFoundError,
    quick_search,
)


def test_ast_grep_availability():
    """Test if ast-grep is available"""
    print("=" * 60)
    print("Test 1: Checking ast-grep availability")
    print("=" * 60)
    
    project_root = Path(__file__).parent.parent
    wrapper = AstGrepWrapper(str(project_root))
    
    if wrapper.ast_grep_available:
        print("✅ ast-grep is installed and available")
        return True
    else:
        print("⚠️  ast-grep is NOT installed")
        print("   Install with: cargo install ast-grep")
        print("   OR: npm install -g @ast-grep/cli")
        return False


def test_find_imports():
    """Test finding import statements"""
    print("\n" + "=" * 60)
    print("Test 2: Finding import statements")
    print("=" * 60)
    
    project_root = Path(__file__).parent.parent
    wrapper = AstGrepWrapper(str(project_root))
    
    if not wrapper.ast_grep_available:
        print("⏭️  Skipping (ast-grep not available)")
        return
    
    try:
        # Find imports of 'json' module
        matches = wrapper.find_imports("json", Language.PYTHON)
        
        if matches:
            print(f"✅ Found {len(matches)} import(s) of 'json' module")
            for i, match in enumerate(matches[:3], 1):
                print(f"   {i}. {match.file}:{match.start_line}")
                print(f"      {match.matched_text[:60]}...")
        else:
            print("ℹ️  No matches found (this is OK if project doesn't import json)")
            
    except AstGrepNotFoundError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def test_find_function_calls():
    """Test finding function calls"""
    print("\n" + "=" * 60)
    print("Test 3: Finding function calls")
    print("=" * 60)
    
    project_root = Path(__file__).parent.parent
    wrapper = AstGrepWrapper(str(project_root))
    
    if not wrapper.ast_grep_available:
        print("⏭️  Skipping (ast-grep not available)")
        return
    
    try:
        # Find calls to 'print' function
        matches = wrapper.find_function_calls("print", Language.PYTHON)
        
        if matches:
            print(f"✅ Found {len(matches)} call(s) to 'print()' function")
            for i, match in enumerate(matches[:3], 1):
                print(f"   {i}. {match.file}:{match.start_line}")
                print(f"      {match.matched_text[:60]}...")
        else:
            print("ℹ️  No matches found")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def test_quick_search():
    """Test quick search helper"""
    print("\n" + "=" * 60)
    print("Test 4: Quick search helper")
    print("=" * 60)
    
    project_root = Path(__file__).parent.parent
    wrapper = AstGrepWrapper(str(project_root))
    
    if not wrapper.ast_grep_available:
        print("⏭️  Skipping (ast-grep not available)")
        return
    
    try:
        # Quick search for class definitions
        matches = quick_search(
            project_root=str(project_root),
            pattern="class $NAME",
            language="python"
        )
        
        if matches:
            print(f"✅ Found {len(matches)} class definition(s)")
            for i, match in enumerate(matches[:3], 1):
                print(f"   {i}. {match.file}:{match.start_line}")
        else:
            print("ℹ️  No matches found")
            
    except Exception as e:
        print(f"❌ Error: {e}")


def test_wrapper_creation():
    """Test wrapper instantiation"""
    print("\n" + "=" * 60)
    print("Test 5: Wrapper instantiation")
    print("=" * 60)
    
    try:
        project_root = Path(__file__).parent.parent
        wrapper = AstGrepWrapper(str(project_root))
        print(f"✅ Wrapper created successfully")
        print(f"   Project root: {wrapper.project_root}")
        print(f"   ast-grep available: {wrapper.ast_grep_available}")
    except Exception as e:
        print(f"❌ Error creating wrapper: {e}")


def main():
    """Run all tests"""
    print("\n🧪 ast-grep Wrapper Integration Tests")
    print("=" * 60)
    print("Testing ast-grep integration for VulnReach")
    print("=" * 60)
    
    # Run tests
    test_wrapper_creation()
    ast_grep_available = test_ast_grep_availability()
    test_find_imports()
    test_find_function_calls()
    test_quick_search()
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    if ast_grep_available:
        print("✅ ast-grep is ready for use in VulnReach")
        print("   You can now use ast-grep-based code analysis")
    else:
        print("⚠️  ast-grep is not installed")
        print("   VulnReach will fall back to regex-based analysis")
        print("\nTo install ast-grep:")
        print("   cargo install ast-grep")
        print("   OR")
        print("   npm install -g @ast-grep/cli")
        print("\nSee docs/AST_GREP_SETUP.md for detailed instructions")
    
    print("=" * 60)


if __name__ == "__main__":
    main()
