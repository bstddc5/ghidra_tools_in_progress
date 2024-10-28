# utils/logger.py

class Logger(object):
    """Simple logging utility for the A2L importer"""
    
    DEBUG = True
    
    @classmethod
    def debug(cls, message):
        """Log debug message"""
        if cls.DEBUG:
            print("[DEBUG] {}".format(message))
    
    @classmethod
    def info(cls, message):
        """Log info message"""
        print("[INFO] {}".format(message))
    
    @classmethod
    def error(cls, message):
        """Log error message"""
        print("[ERROR] {}".format(message))
    
    @classmethod
    def warning(cls, message):
        """Log warning message"""
        print("[WARNING] {}".format(message))