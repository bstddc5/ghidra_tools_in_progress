# ghidra_a2l_importer/__main__.py
"""A2L Importer for Ghidra"""
#@category A2L
#@menupath Tools.A2L.Import
#@toolbar

import os
import sys
import traceback

# Simple logger implementation
class Logger(object):
    @classmethod
    def debug(cls, msg): print("[DEBUG] " + str(msg))
    @classmethod
    def info(cls, msg): print("[INFO] " + str(msg))
    @classmethod
    def error(cls, msg): print("[ERROR] " + str(msg))

try:
    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    
    Logger.info("Starting A2L Import Tool")
    Logger.debug("Script directory: {}".format(script_dir))
    Logger.debug("Python path: {}".format(sys.path))
    
    # Import GUI
    from gui.main_window import A2LImporterGUI
    
    def run_script():
        """Main script entry point"""
        try:
            gui = A2LImporterGUI(state)
            if gui.current_program:
                gui.setVisible(True)
                Logger.info("GUI initialized successfully")
            else:
                Logger.error("No program is currently open")
        except Exception as e:
            Logger.error("Error running script: {}".format(str(e)))
            Logger.debug("Traceback: {}".format(traceback.format_exc()))
    
    if __name__ == '__main__':
        run_script()
        
except Exception as e:
    Logger.error("Error during script initialization: {}".format(str(e)))
    Logger.debug("Traceback: {}".format(traceback.format_exc()))