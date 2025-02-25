import subprocess
from typing import Dict, Any, Optional
from pathlib import Path
from loguru import logger

class GobusterTool:
    def __init__(self):
        self.default_wordlist = "/usr/share/wordlists/dirb/common.txt"

    def run(self,
            target: str,
            wordlist: Optional[str] = None,
            mode: str = "dir",
            threads: int = 10,
            status_codes: str = "200,204,301,302,307,401,403",
            **kwargs) -> Dict[str, Any]:
        """
        Run gobuster with specified parameters
        
        Args:
            target: Target URL
            wordlist: Path to wordlist file
            mode: Gobuster mode (dir, dns, vhost)
            threads: Number of concurrent threads
            status_codes: Status codes to look for
        """
        try:
            wordlist = wordlist or self.default_wordlist
            if not Path(wordlist).exists():
                raise FileNotFoundError(f"Wordlist not found: {wordlist}")

            cmd = [
                "gobuster",
                mode,
                "-u", target,
                "-w", wordlist,
                "-t", str(threads),
                "-s", status_codes,
                "-o", "gobuster_output.txt"
            ]

            # Add any additional parameters
            for key, value in kwargs.items():
                if isinstance(value, bool):
                    if value:
                        cmd.extend([f"-{key}"])
                else:
                    cmd.extend([f"-{key}", str(value)])

            logger.info(f"Running gobuster command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )

            # Read the output file
            with open("gobuster_output.txt", "r") as f:
                output_data = f.read()

            # Clean up the output file
            Path("gobuster_output.txt").unlink()

            return {
                "command": " ".join(cmd),
                "raw_output": output_data,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "parsed_results": self.parse_results(output_data)
            }

        except subprocess.CalledProcessError as e:
            logger.error(f"Gobuster execution failed: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during gobuster execution: {str(e)}")
            raise

    def parse_results(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output into structured format"""
        try:
            parsed_results = {
                "discovered_items": [],
                "summary": {
                    "total_discoveries": 0,
                    "response_codes": {}
                }
            }

            for line in output.split("\n"):
                if line.startswith("Found: ") or line.startswith("/"):
                    item = self._parse_line(line)
                    if item:
                        parsed_results["discovered_items"].append(item)
                        
                        # Update summary
                        parsed_results["summary"]["total_discoveries"] += 1
                        status = item.get("status_code")
                        if status:
                            parsed_results["summary"]["response_codes"][status] = \
                                parsed_results["summary"]["response_codes"].get(status, 0) + 1

            return parsed_results

        except Exception as e:
            logger.error(f"Failed to parse gobuster results: {str(e)}")
            raise

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single line of gobuster output"""
        try:
            # Remove "Found: " prefix if present
            line = line.replace("Found: ", "").strip()
            
            # Split the line into parts
            parts = line.split()
            if not parts:
                return None

            result = {
                "path": parts[0]
            }

            # Parse status code if present
            for part in parts:
                if part.startswith("Status:"):
                    result["status_code"] = int(part.split(":")[1])
                elif part.startswith("Size:"):
                    result["size"] = int(part.split(":")[1])

            return result

        except Exception:
            return None