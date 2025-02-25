from typing import Dict, Any, List
from langchain.chat_models import ChatOllama
from langchain.prompts import ChatPromptTemplate
from langchain.schema import SystemMessage, HumanMessage
from loguru import logger
from ..core.scope import ScopeDefinition
from ..tools.nmap_tool import NmapTool
from ..tools.gobuster_tool import GobusterTool
from ..tools.ffuf_tool import FfufTool

class ToolAgent:
    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self.llm = ChatOllama(model="mistral")
        self.tools = {
            "nmap": NmapTool(),
            "gobuster": GobusterTool(),
            "ffuf": FfufTool()
        }

    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific security tool with given parameters"""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")

        target = parameters.get("target")
        if not target or not self.scope.is_in_scope(target):
            raise ValueError(f"Target {target} is not in scope")

        logger.info(f"Executing {tool_name} with parameters: {parameters}")
        tool = self.tools[tool_name]
        
        try:
            result = tool.run(**parameters)
            logger.info(f"{tool_name} execution completed successfully")
            return result
        except Exception as e:
            logger.error(f"{tool_name} execution failed: {str(e)}")
            raise

    def analyze_output(self, tool_name: str, output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze tool output and suggest next steps"""
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=f"You are a security expert analyzing {tool_name} output. "
                                "Suggest next steps based on the findings."),
            HumanMessage(content=str(output))
        ])

        response = self.llm.invoke(prompt)
        
        # Parse the response into a list of suggested next steps
        suggestions = self._parse_suggestions(response.content)
        
        # Filter suggestions to ensure they're in scope
        valid_suggestions = [
            suggestion for suggestion in suggestions
            if self.scope.is_in_scope(suggestion.get("target", ""))
        ]

        return valid_suggestions

    def _parse_suggestions(self, llm_response: str) -> List[Dict[str, Any]]:
        """Parse LLM response into structured suggestions"""
        try:
            # This is a simple implementation - you might want to make it more robust
            suggestions = []
            lines = llm_response.split("\n")
            
            current_suggestion = {}
            for line in lines:
                if line.startswith("Tool:"):
                    if current_suggestion:
                        suggestions.append(current_suggestion)
                    current_suggestion = {"tool": line.split(":")[1].strip()}
                elif line.startswith("Target:"):
                    current_suggestion["target"] = line.split(":")[1].strip()
                elif line.startswith("Parameters:"):
                    params_str = line.split(":")[1].strip()
                    current_suggestion["parameters"] = eval(params_str)  # Be careful with eval!

            if current_suggestion:
                suggestions.append(current_suggestion)

            return suggestions
        except Exception as e:
            logger.error(f"Failed to parse suggestions: {str(e)}")
            return []

    def validate_tool_parameters(self, tool_name: str, parameters: Dict[str, Any]) -> bool:
        """Validate that the parameters for a tool are correct and safe"""
        required_params = {
            "nmap": ["target"],
            "gobuster": ["target", "wordlist"],
            "ffuf": ["target", "wordlist"]
        }

        if tool_name not in required_params:
            return False

        return all(param in parameters for param in required_params[tool_name])