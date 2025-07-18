#!/usr/bin/env python3
"""
Logger module for AD-Automaton
Provides standardized logging with color-coded console output and file logging.
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional

# ANSI color codes for console output
class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Regular colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels."""
    
    LEVEL_COLORS = {
        logging.DEBUG: Colors.BRIGHT_BLACK,
        logging.INFO: Colors.BLUE,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BRIGHT_RED + Colors.BOLD,
    }
    
    def __init__(self, fmt=None, datefmt=None, use_colors=True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()
    
    def format(self, record):
        """Format the log record with colors if enabled."""
        if self.use_colors:
            # Add color to the level name
            level_color = self.LEVEL_COLORS.get(record.levelno, '')
            
            # Store original level name
            original_levelname = record.levelname
            
            # Create colored level name with padding for alignment
            if level_color:
                colored_levelname = f"{level_color}{record.levelname:<8}{Colors.RESET}"
            else:
                colored_levelname = f"{record.levelname:<8}"
            
            # Temporarily modify the record
            record.levelname = colored_levelname
            
            # Format the message
            formatted = super().format(record)
            
            # Restore original level name
            record.levelname = original_levelname
            
            return formatted
        else:
            return super().format(record)

class SuccessFilter(logging.Filter):
    """Custom filter to handle SUCCESS level logs."""
    
    def filter(self, record):
        # Allow all records except SUCCESS if handler doesn't want them
        return True

def add_success_level():
    """Add a custom SUCCESS logging level."""
    SUCCESS_LEVEL = 25  # Between INFO (20) and WARNING (30)
    
    def success(self, message, *args, **kwargs):
        if self.isEnabledFor(SUCCESS_LEVEL):
            self._log(SUCCESS_LEVEL, message, args, **kwargs)
    
    # Add the method to Logger class
    logging.Logger.success = success
    
    # Add the level to the logging module
    logging.addLevelName(SUCCESS_LEVEL, 'SUCCESS')
    
    # Add color for SUCCESS level
    ColoredFormatter.LEVEL_COLORS[SUCCESS_LEVEL] = Colors.BRIGHT_GREEN

def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """
    Set up the logging configuration for AD-Automaton.
    
    Args:
        verbose: Enable debug-level logging
        log_file: Path to log file for persistent logging
    """
    # Add custom SUCCESS level
    add_success_level()
    
    # Determine log level
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Console format with colors
    console_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    console_formatter = ColoredFormatter(
        fmt=console_format,
        datefmt="%H:%M:%S",
        use_colors=True
    )
    console_handler.setFormatter(console_formatter)
    
    # Add filter for success messages
    console_handler.addFilter(SuccessFilter())
    
    root_logger.addHandler(console_handler)
    
    # File handler if log file is specified
    if log_file:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setLevel(logging.DEBUG)  # Always log everything to file
            
            # File format without colors but with more detail
            file_format = "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s"
            file_formatter = logging.Formatter(
                fmt=file_format,
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_formatter)
            
            root_logger.addHandler(file_handler)
            
            # Log the logging setup
            logger = logging.getLogger(__name__)
            logger.info(f"Logging initialized - Level: {logging.getLevelName(log_level)}")
            logger.info(f"Log file: {log_file}")
            
        except Exception as e:
            # If file logging fails, continue with console only
            console_logger = logging.getLogger(__name__)
            console_logger.warning(f"Failed to setup file logging: {e}")
    
    # Configure third-party loggers to be less verbose
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('subprocess').setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)

def log_banner(message: str, logger: Optional[logging.Logger] = None) -> None:
    """
    Log a banner message for phase transitions.
    
    Args:
        message: Banner message to display
        logger: Logger instance (uses root logger if None)
    """
    if logger is None:
        logger = logging.getLogger()
    
    banner_length = max(60, len(message) + 10)
    banner_char = "="
    
    border = banner_char * banner_length
    padded_message = f"{banner_char * 3} {message} {banner_char * 3}"
    
    # Center the message
    padding_needed = banner_length - len(padded_message)
    left_padding = padding_needed // 2
    right_padding = padding_needed - left_padding
    
    centered_message = banner_char * left_padding + padded_message + banner_char * right_padding
    
    logger.info("")
    logger.info(border)
    logger.info(centered_message)
    logger.info(border)
    logger.info("")

def log_phase_start(phase_name: str, description: str = "") -> None:
    """
    Log the start of a new phase.
    
    Args:
        phase_name: Name of the phase starting
        description: Optional description of the phase
    """
    logger = logging.getLogger(__name__)
    
    if description:
        message = f"STARTING {phase_name}: {description}"
    else:
        message = f"STARTING {phase_name}"
    
    log_banner(message, logger)

def log_phase_complete(phase_name: str, summary: str = "") -> None:
    """
    Log the completion of a phase.
    
    Args:
        phase_name: Name of the completed phase
        summary: Optional summary of results
    """
    logger = logging.getLogger(__name__)
    
    if summary:
        message = f"COMPLETED {phase_name}: {summary}"
    else:
        message = f"COMPLETED {phase_name}"
    
    log_banner(message, logger)
    logger.success(f"Phase {phase_name} completed successfully")

def log_tool_execution(tool_name: str, command: str, logger: Optional[logging.Logger] = None) -> None:
    """
    Log the execution of an external tool.
    
    Args:
        tool_name: Name of the tool being executed
        command: Command being executed
        logger: Logger instance
    """
    if logger is None:
        logger = logging.getLogger()
    
    logger.info(f"Executing {tool_name}: {command}")

def log_tool_result(tool_name: str, exit_code: int, output_lines: int = 0, 
                   errors: int = 0, logger: Optional[logging.Logger] = None) -> None:
    """
    Log the result of tool execution.
    
    Args:
        tool_name: Name of the tool that was executed
        exit_code: Exit code from the tool
        output_lines: Number of output lines produced
        errors: Number of errors encountered
        logger: Logger instance
    """
    if logger is None:
        logger = logging.getLogger()
    
    if exit_code == 0:
        logger.success(f"{tool_name} completed successfully - {output_lines} lines of output")
    else:
        logger.error(f"{tool_name} failed with exit code {exit_code}")
        if errors > 0:
            logger.error(f"{tool_name} encountered {errors} errors")

def log_discovery(item_type: str, count: int, details: str = "", 
                 logger: Optional[logging.Logger] = None) -> None:
    """
    Log discovery of new items (hosts, credentials, etc.).
    
    Args:
        item_type: Type of items discovered (e.g., "hosts", "credentials")
        count: Number of items discovered
        details: Additional details about the discovery
        logger: Logger instance
    """
    if logger is None:
        logger = logging.getLogger()
    
    if count > 0:
        message = f"Discovered {count} {item_type}"
        if details:
            message += f": {details}"
        logger.success(message)
    else:
        logger.info(f"No {item_type} discovered")

def log_error_with_context(error: Exception, context: str, 
                          logger: Optional[logging.Logger] = None) -> None:
    """
    Log an error with additional context.
    
    Args:
        error: Exception that occurred
        context: Additional context about when/where the error occurred
        logger: Logger instance
    """
    if logger is None:
        logger = logging.getLogger()
    
    logger.error(f"Error in {context}: {str(error)}")
    logger.debug(f"Exception details: {type(error).__name__}: {str(error)}")

# Module-level convenience functions for common operations
def info(message: str) -> None:
    """Log an info message."""
    logging.getLogger().info(message)

def success(message: str) -> None:
    """Log a success message."""
    logging.getLogger().success(message)

def warning(message: str) -> None:
    """Log a warning message."""
    logging.getLogger().warning(message)

def error(message: str) -> None:
    """Log an error message."""
    logging.getLogger().error(message)

def debug(message: str) -> None:
    """Log a debug message."""
    logging.getLogger().debug(message)

def critical(message: str) -> None:
    """Log a critical message."""
    logging.getLogger().critical(message) 