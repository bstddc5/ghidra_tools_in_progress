"""Logging utility for A2L Importer"""

class Logger(object):
    DEBUG = True
    
    @classmethod
    def debug(cls, msg):
        if cls.DEBUG:
            print("[DEBUG] {}".format(msg))
    
    @classmethod
    def info(cls, msg):
        print("[INFO] {}".format(msg))
    
    @classmethod
    def error(cls, msg):
        print("[ERROR] {}".format(msg))
    
    @classmethod
    def warning(cls, msg):
        print("[WARNING] {}".format(msg))
