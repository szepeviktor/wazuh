import os
import shuffle

def pytest_sessionfinish():
    """Remove the log file created by the tested functions."""
    os.remove(shuffle.LOG_FILE)