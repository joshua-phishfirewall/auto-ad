#!/usr/bin/env python3
"""
Command Executor for AD-Automaton
Provides standardized execution of external tools with timeout, logging, and error handling.
"""

import subprocess
import threading
import signal
import os
import time
import logging
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

@dataclass
class ExecutionResult:
    """Data class for command execution results."""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    timed_out: bool = False
    error: Optional[str] = None

class CommandExecutor:
    """
    Executes external commands with standardized error handling, logging, and timeout management.
    Designed for secure execution of penetration testing tools.
    """
    
    def __init__(self, default_timeout: int = 300, working_directory: Optional[str] = None):
        """
        Initialize the command executor.
        
        Args:
            default_timeout: Default timeout in seconds for command execution
            working_directory: Default working directory for commands
        """
        self.default_timeout = default_timeout
        self.working_directory = working_directory
        self.logger = logging.getLogger(__name__)
        self.active_processes: Dict[int, subprocess.Popen] = {}
        self.process_lock = threading.Lock()
    
    def execute(self, command: str, timeout: Optional[int] = None, 
                capture_output: bool = True, text: bool = True,
                shell: bool = True, env: Optional[Dict[str, str]] = None,
                cwd: Optional[str] = None, input_data: Optional[str] = None) -> ExecutionResult:
        """
        Execute a command with comprehensive error handling and logging.
        
        Args:
            command: Command string to execute
            timeout: Timeout in seconds (uses default if None)
            capture_output: Whether to capture stdout and stderr
            text: Whether to treat output as text
            shell: Whether to use shell execution
            env: Environment variables
            cwd: Working directory
            input_data: Data to send to stdin
            
        Returns:
            ExecutionResult with command output and metadata
        """
        if timeout is None:
            timeout = self.default_timeout
        
        if cwd is None:
            cwd = self.working_directory
        
        # Prepare environment
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)
        
        start_time = time.time()
        process = None
        
        try:
            self.logger.debug(f"Executing command: {command}")
            if cwd:
                self.logger.debug(f"Working directory: {cwd}")
            
            # Start the process
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                stdin=subprocess.PIPE if input_data else None,
                text=text,
                shell=shell,
                env=exec_env,
                cwd=cwd,
                preexec_fn=os.setsid if os.name != 'nt' else None  # For process group killing
            )
            
            # Track the process
            with self.process_lock:
                self.active_processes[process.pid] = process
            
            try:
                # Wait for completion with timeout
                stdout, stderr = process.communicate(input=input_data, timeout=timeout)
                execution_time = time.time() - start_time
                
                result = ExecutionResult(
                    command=command,
                    exit_code=process.returncode,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    execution_time=execution_time,
                    timed_out=False
                )
                
                # Log the result
                if process.returncode == 0:
                    self.logger.debug(f"Command completed successfully in {execution_time:.2f}s")
                else:
                    self.logger.warning(f"Command failed with exit code {process.returncode}")
                    if stderr:
                        self.logger.debug(f"Error output: {stderr[:500]}...")
                
                return result
                
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Command timed out after {timeout} seconds")
                
                # Kill the process group
                try:
                    if os.name != 'nt':
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    else:
                        process.terminate()
                    
                    # Give it a moment to terminate gracefully
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        # Force kill if still running
                        if os.name != 'nt':
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait()
                        
                except (OSError, ProcessLookupError):
                    # Process already terminated
                    pass
                
                execution_time = time.time() - start_time
                
                # Try to get any output that was captured before timeout
                try:
                    stdout, stderr = process.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    stdout, stderr = "", ""
                
                return ExecutionResult(
                    command=command,
                    exit_code=-1,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    execution_time=execution_time,
                    timed_out=True,
                    error="Command timed out"
                )
                
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Failed to execute command: {str(e)}"
            self.logger.error(error_msg)
            
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr="",
                execution_time=execution_time,
                timed_out=False,
                error=error_msg
            )
            
        finally:
            # Clean up process tracking
            if process:
                with self.process_lock:
                    self.active_processes.pop(process.pid, None)
    
    def execute_with_live_output(self, command: str, timeout: Optional[int] = None,
                                cwd: Optional[str] = None) -> ExecutionResult:
        """
        Execute a command with live output streaming to the logger.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            cwd: Working directory
            
        Returns:
            ExecutionResult with captured output
        """
        if timeout is None:
            timeout = self.default_timeout
        
        if cwd is None:
            cwd = self.working_directory
        
        start_time = time.time()
        stdout_lines = []
        stderr_lines = []
        
        try:
            self.logger.info(f"Executing with live output: {command}")
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                cwd=cwd,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            with self.process_lock:
                self.active_processes[process.pid] = process
            
            # Read output in real-time
            def read_output(pipe, lines_list, prefix):
                try:
                    for line in iter(pipe.readline, ''):
                        if line:
                            line = line.rstrip()
                            lines_list.append(line)
                            self.logger.info(f"{prefix}: {line}")
                except Exception as e:
                    self.logger.error(f"Error reading {prefix}: {e}")
                finally:
                    pipe.close()
            
            # Start output reading threads
            stdout_thread = threading.Thread(
                target=read_output, 
                args=(process.stdout, stdout_lines, "STDOUT")
            )
            stderr_thread = threading.Thread(
                target=read_output, 
                args=(process.stderr, stderr_lines, "STDERR")
            )
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()
            
            # Wait for process completion
            exit_code = process.wait(timeout=timeout)
            execution_time = time.time() - start_time
            
            # Wait for output threads to finish
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            
            return ExecutionResult(
                command=command,
                exit_code=exit_code,
                stdout='\n'.join(stdout_lines),
                stderr='\n'.join(stderr_lines),
                execution_time=execution_time,
                timed_out=False
            )
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command with live output timed out after {timeout} seconds")
            
            try:
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.terminate()
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError, ProcessLookupError):
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout='\n'.join(stdout_lines),
                stderr='\n'.join(stderr_lines),
                execution_time=execution_time,
                timed_out=True,
                error="Command timed out"
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Failed to execute command with live output: {str(e)}"
            self.logger.error(error_msg)
            
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout='\n'.join(stdout_lines),
                stderr='\n'.join(stderr_lines),
                execution_time=execution_time,
                timed_out=False,
                error=error_msg
            )
        finally:
            if process:
                with self.process_lock:
                    self.active_processes.pop(process.pid, None)
    
    def execute_background(self, command: str, log_file: Optional[str] = None,
                          cwd: Optional[str] = None) -> subprocess.Popen:
        """
        Execute a command in the background and return the process handle.
        
        Args:
            command: Command to execute
            log_file: Optional file to redirect output to
            cwd: Working directory
            
        Returns:
            Process handle for background process
        """
        if cwd is None:
            cwd = self.working_directory
        
        try:
            self.logger.info(f"Starting background process: {command}")
            
            # Setup output redirection
            if log_file:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                stdout = open(log_file, 'w')
                stderr = subprocess.STDOUT
            else:
                stdout = subprocess.DEVNULL
                stderr = subprocess.DEVNULL
            
            process = subprocess.Popen(
                command,
                stdout=stdout,
                stderr=stderr,
                text=True,
                shell=True,
                cwd=cwd,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            with self.process_lock:
                self.active_processes[process.pid] = process
            
            self.logger.info(f"Background process started with PID: {process.pid}")
            return process
            
        except Exception as e:
            self.logger.error(f"Failed to start background process: {e}")
            raise
    
    def terminate_process(self, process: subprocess.Popen, force: bool = False) -> bool:
        """
        Terminate a background process gracefully or forcefully.
        
        Args:
            process: Process to terminate
            force: Whether to force kill immediately
            
        Returns:
            True if successfully terminated
        """
        try:
            if process.poll() is not None:
                # Process already terminated
                return True
            
            self.logger.info(f"Terminating process PID: {process.pid}")
            
            if force:
                # Force kill immediately
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            else:
                # Graceful termination
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.terminate()
                
                # Wait for graceful shutdown
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown failed
                    self.logger.warning(f"Graceful shutdown failed for PID {process.pid}, force killing")
                    if os.name != 'nt':
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait()
            
            with self.process_lock:
                self.active_processes.pop(process.pid, None)
            
            self.logger.info(f"Process PID {process.pid} terminated successfully")
            return True
            
        except (OSError, ProcessLookupError):
            # Process already dead
            with self.process_lock:
                self.active_processes.pop(process.pid, None)
            return True
        except Exception as e:
            self.logger.error(f"Failed to terminate process PID {process.pid}: {e}")
            return False
    
    def terminate_all_processes(self) -> None:
        """Terminate all active background processes."""
        with self.process_lock:
            processes = list(self.active_processes.values())
        
        for process in processes:
            self.terminate_process(process, force=True)
    
    def get_active_processes(self) -> List[int]:
        """Get a list of active process PIDs."""
        with self.process_lock:
            return list(self.active_processes.keys())
    
    def save_output_to_file(self, result: ExecutionResult, filepath: str,
                           include_metadata: bool = True) -> bool:
        """
        Save command execution results to a file.
        
        Args:
            result: ExecutionResult to save
            filepath: File path to save to
            include_metadata: Whether to include execution metadata
            
        Returns:
            True if successful
        """
        try:
            output_path = Path(filepath)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'w') as f:
                if include_metadata:
                    f.write(f"Command: {result.command}\n")
                    f.write(f"Exit Code: {result.exit_code}\n")
                    f.write(f"Execution Time: {result.execution_time:.2f}s\n")
                    f.write(f"Timed Out: {result.timed_out}\n")
                    if result.error:
                        f.write(f"Error: {result.error}\n")
                    f.write("-" * 80 + "\n")
                    f.write("STDOUT:\n")
                    f.write("-" * 40 + "\n")
                
                f.write(result.stdout)
                
                if include_metadata and result.stderr:
                    f.write("\n" + "-" * 40 + "\n")
                    f.write("STDERR:\n")
                    f.write("-" * 40 + "\n")
                    f.write(result.stderr)
            
            self.logger.debug(f"Saved command output to: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save output to {filepath}: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup all processes."""
        self.terminate_all_processes()

# Convenience functions for quick command execution
def run_command(command: str, timeout: int = 300, capture_output: bool = True) -> ExecutionResult:
    """
    Quick command execution with default settings.
    
    Args:
        command: Command to execute
        timeout: Timeout in seconds
        capture_output: Whether to capture output
        
    Returns:
        ExecutionResult
    """
    executor = CommandExecutor(default_timeout=timeout)
    return executor.execute(command, capture_output=capture_output)

def run_command_with_output(command: str, timeout: int = 300) -> Tuple[int, str, str]:
    """
    Run command and return exit code, stdout, stderr tuple.
    
    Args:
        command: Command to execute
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    result = run_command(command, timeout=timeout)
    return result.exit_code, result.stdout, result.stderr

def check_tool_availability(tool_name: str) -> bool:
    """
    Check if a tool is available in the system PATH.
    
    Args:
        tool_name: Name of the tool to check
        
    Returns:
        True if tool is available
    """
    import shutil
    return shutil.which(tool_name) is not None 