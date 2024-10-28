# A2LImporterTest.py
#@category A2L
#@menupath Tools.A2L.Test
#@toolbar

import os
import sys
import traceback

def test_environment():
    """Test the Ghidra script environment"""
    try:
        print("\nTesting Ghidra environment...")
        
        # Test Ghidra imports
        print("\nTesting Ghidra imports...")
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.listing import CodeUnit
        from ghidra.program.model.symbol import SourceType
        print("Ghidra imports successful")
        
        # Test Java/Swing imports
        print("\nTesting Java/Swing imports...")
        from java.awt import BorderLayout, Dimension
        from javax.swing import JFrame, JPanel
        print("Java/Swing imports successful")
        
        # Test current program
        print("\nTesting current program...")
        current_program = getCurrentProgram()
        if current_program:
            print("Current program: " + current_program.getName())
        else:
            print("No program currently open")
        
        # Print Python path
        print("\nPython path:")
        for p in sys.path:
            print("  " + str(p))
        
        return True
        
    except Exception as e:
        print("Error during environment test: " + str(e))
        print("Traceback:")
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("Starting A2L Importer test...")
    if test_environment():
        print("\nEnvironment test successful!")
    else:
        print("\nEnvironment test failed!")