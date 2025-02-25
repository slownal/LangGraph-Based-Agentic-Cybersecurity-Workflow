import subprocess
import json
from typing import Dict, Any, Optional
from pathlib import Path
from loguru import logger

class FfufTool:
    def __init__(self):
        self.default_wordlist = "/usr/share/wordlists/dirb/common.txt"

    def run(self, 
            target: str, 
            wordlist: Optional[str] = None,
            extensions: str = "php,html,txt",
            threads: int = 40,
            **kwargs) -> Dict[str, Any]:
        """
        Run ffuf web fuzzer with specified parameters
        
        Args:
            target: Target URL (e.g., http://example.com/FUZZ)
            wordlist: Path to wordlist file
            extensions: File extensions to test
            threads: Number of concurrent threads
        """
        try:
            wordlist = wordlist or self.default_wordlist
            if not Path(wordlist).exists():
                raise FileNotFoundError(f"Wordlist not found: {wordlist}")

            cmd = [
                "ffuf",
                "-u", target,
                "-w", wordlist,
                "-e", extensions,
                "-t", str(threads),
                "-o", "ffuf_output.json",
                "-of", "json"
            ]

            # Add any additional parameters
            for key, value in kwargs.items():
                if isinstance(value, bool):
                    if value:
                        cmd.extend([f"-{key}"])
                else:
                    cmd.extend([f"-{key}", str(value)])

            logger.info(f"Running ffuf command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )

            # Read the JSON output file
            with open("ffuf_output.json", "r") as f:
                output_data = json.load(f)

            # Clean up the output file
            Path("ffuf_output.json").unlink()

            return {
                "command": " ".join(cmd),
                "results": output_data,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }

        except subprocess.CalledProcessError as e:
            logger.error(f"Ffuf execution failed: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse ffuf output: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during ffuf execution: {str(e)}")
            raise

    def parse_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and structure ffuf results"""
        try:
            parsed_results = {
                "discovered_paths": [],
                "response_codes": {},
                "content_types": {},
                "summary": {}
            }

            for result in results.get("results", []):
                parsed_results["discovered_paths"].append({
                    "url": result.get("url"),
                    "status": result.get("status"),
                    "content_type": result.get("content-type"),
                    "length": result.get("length")
                })

                # Count response codes
                status = result.get("status")
                parsed_results["response_codes"][status] = \
                    parsed_results["response_codes"].get(status, 0) + 1

                # Count content types
                content_type = result.get("content-type")
                parsed_results["content_types"][content_type] = \
                    parsed_results["content_types"].get(content_type, 0) + 1

            # Generate summary
            parsed_results["summary"] = {
                "total_discoveries": len(parsed_results["discovered_paths"]),
                "unique_response_codes": len(parsed_results["response_codes"]),
                "unique_content_types": len(parsed_results["content_types"])
            }

            return parsed_results

        except Exception as e:
            logger.error(f"Failed to parse ffuf results: {str(e)}")
            raise