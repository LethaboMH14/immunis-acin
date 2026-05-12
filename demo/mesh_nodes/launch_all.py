"""
Launch all 3 mesh node simulators simultaneously.

Usage:
    python demo/mesh_nodes/launch_all.py

    # With custom backend:
    python demo/mesh_nodes/launch_all.py --url ws://localhost:8000/ws

This starts Tshwane, Johannesburg, and Cape Town nodes in parallel.
All connect to the same backend WebSocket and report as separate nodes.

For the demo:
1. Start backend: uvicorn backend.main:app --reload --port 8000
2. Start frontend: cd frontend && npm run dev
3. Start nodes: python demo/mesh_nodes/launch_all.py
4. Run demo: python demo/scenario_full.py
"""

import asyncio
import importlib
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LAUNCHER] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("launcher")

MESH_DIR = Path(__file__).parent
NODES = [
    {"script": "node_tshwane.py", "name": "Tshwane", "color": "\033[92m"},    # Green
    {"script": "node_joburg.py", "name": "Johannesburg", "color": "\033[94m"},  # Blue
    {"script": "node_capetown.py", "name": "Cape Town", "color": "\033[95m"},   # Magenta
]
RESET = "\033[0m"


def launch_nodes():
    """Launch all mesh nodes as subprocesses."""
    
    # Pass through any CLI args
    extra_args = sys.argv[1:]
    
    print(f"\n{'='*60}")
    print(f"  IMMUNIS ACIN — Mesh Node Launcher")
    print(f"  Launching {len(NODES)} simulated nodes...")
    print(f"{'='*60}\n")

    processes = []

    for node in NODES:
        script_path = MESH_DIR / node["script"]
        
        if not script_path.exists():
            logger.error("Script not found: %s", script_path)
            continue

        cmd = [sys.executable, str(script_path)] + extra_args
        
        logger.info(
            "%sStarting %s...%s",
            node["color"], node["name"], RESET,
        )

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True,
        )
        processes.append({
            "process": proc,
            "name": node["name"],
            "color": node["color"],
        })

        # Small delay between launches to stagger connections
        time.sleep(1)

    if not processes:
        logger.error("No nodes launched!")
        return

    logger.info("All %d nodes launched. Press Ctrl+C to stop all.", len(processes))
    print()

    # Stream output from all processes with colored prefixes
    try:
        while True:
            all_dead = True
            for node_proc in processes:
                proc = node_proc["process"]
                if proc.poll() is None:
                    all_dead = False
                    # Non-blocking readline
                    try:
                        line = proc.stdout.readline()
                        if line:
                            prefix = f"{node_proc['color']}[{node_proc['name'][:8]:>8}]{RESET}"
                            print(f"{prefix} {line.rstrip()}")
                    except Exception:
                        pass

            if all_dead:
                logger.warning("All nodes have exited")
                break

            time.sleep(0.05)

    except KeyboardInterrupt:
        print(f"\n{'='*60}")
        print(f"  Shutting down all nodes...")
        print(f"{'='*60}\n")

        for node_proc in processes:
            proc = node_proc["process"]
            if proc.poll() is None:
                logger.info("Stopping %s (PID %d)...", node_proc["name"], proc.pid)
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        logger.info("All nodes stopped.")


if __name__ == "__main__":
    launch_nodes()
