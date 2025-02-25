import subprocess
from typing import Dict
from loguru import logger

class NmapTool:
    def run(self, target: str, ports: str = None, **kwargs) -> Dict:
        try:
            cmd = ["nmap", "-sV"]
            if ports:
                cmd.extend(["-p", ports])
            cmd.append(target)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            return {
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            raise