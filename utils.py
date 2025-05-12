import subprocess
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import logging
from pathlib import Path

console = Console()
logger = logging.getLogger("DomainSight")

def run_with_progress(tool, cmd, output_file, timeout):
    """
    Run a shell command with Rich progress bar and save stdout to output_file.
    """
    console.log(f"[blue]Starting {tool}...[/blue]")

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    estimated_total = None

    with open(output_file, 'w') as f, Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(f"[green]Running {tool}...", total=estimated_total)

        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            line_count = 0
            start_time = time.time()

            for line in proc.stdout:
                line = line.strip()
                if line:
                    f.write(line + "\n")
                    f.flush()

                    line_count += 1

                    if estimated_total:
                        progress.update(task, completed=line_count)
                    elif line_count % 10 == 0:
                        progress.update(task, completed=line_count)

            proc.wait()
            elapsed = time.time() - start_time

            if estimated_total:
                progress.update(task, completed=estimated_total)
            else:
                progress.update(task, completed=line_count)

            progress.stop()

            console.log(f"[green]{tool} completed in {elapsed:.1f} seconds with {line_count} lines found[/green]")

        except subprocess.TimeoutExpired:
            logger.warning(f"[yellow]{tool} command timed out after {timeout} seconds.[/yellow]")
            proc.kill()
        except Exception as e:
            logger.warning(f"[yellow]Error running {tool}: {e}[/yellow]")

    return proc.returncode if 'proc' in locals() else -1

def read_lines(filepath):
    """
    Read a file and return list of stripped non-empty lines.
    """
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.warning(f"[yellow]Error reading file {filepath}: {e}[/yellow]")
        return []

def save_lines(filepath, lines):
    """
    Save a list of lines into a file, each on a new line.
    """
    try:
        with open(filepath, 'w') as f:
            for line in lines:
                f.write(line.strip() + "\n")
    except Exception as e:
        logger.warning(f"[yellow]Error writing to file {filepath}: {e}[/yellow]")

def safe_mkdir(path):
    """
    Create directory if it does not exist.
    """
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.warning(f"[yellow]Failed to create directory {path}: {e}[/yellow]")
