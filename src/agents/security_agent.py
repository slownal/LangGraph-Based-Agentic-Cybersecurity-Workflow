from typing import Dict, Any, List, Optional
from langchain.chat_models import ChatOllama
from langchain.prompts import ChatPromptTemplate
from langchain.schema import SystemMessage, HumanMessage
from loguru import logger
from src.core.scope import ScopeDefinition
from src.core.task_manager import TaskManager, TaskStatus, Task
from src.tools.nmap_tool import NmapTool
from src.tools.gobuster_tool import GobusterTool
from src.tools.ffuf_tool import FfufTool

class SecurityAgent:
    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self.task_manager = TaskManager()
        self.llm = ChatOllama(model="mistral")
        self.tools = {
            "nmap": NmapTool(),
            "gobuster": GobusterTool(),
            "ffuf": FfufTool()
        }

    def _plan_tasks(self, instruction: str) -> List[Dict]:
        """Plan security tasks based on instruction"""
        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content=(
                    "You are a cybersecurity expert. Break down the security task into "
                    "specific steps using available tools: nmap, gobuster, ffuf"
                )),
                HumanMessage(content=instruction)
            ])
            
            response = self.llm.invoke(prompt)
            tasks = self._parse_tasks(response.content)
            
            planned_tasks = []
            for task in tasks:
                if self.scope.is_in_scope(task["parameters"]["target"]):
                    planned_task = self.task_manager.add_task(**task)
                    planned_tasks.append(planned_task)
                else:
                    logger.warning(f"Task for target {task['parameters']['target']} is out of scope")
            
            return planned_tasks
        except Exception as e:
            logger.error(f"Error in planning tasks: {str(e)}")
            raise

    def _execute_task(self, task: Task) -> Optional[Dict]:
        """Execute a single task"""
        try:
            if task.tool not in self.tools:
                raise ValueError(f"Unknown tool: {task.tool}")

            tool = self.tools[task.tool]
            result = tool.run(**task.parameters)
            
            self.task_manager.update_task_status(
                task.id, 
                TaskStatus.COMPLETED, 
                result=result
            )

            return result
        except Exception as e:
            logger.error(f"Task execution failed: {str(e)}")
            if task.retries < task.max_retries:
                task.retries += 1
                self.task_manager.update_task_status(task.id, TaskStatus.PENDING)
            else:
                self.task_manager.update_task_status(task.id, TaskStatus.FAILED)
            return None

    def _analyze_results(self, results: List[Dict]) -> List[Dict]:
        """Analyze results and determine next steps"""
        try:
            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="Analyze the security scan results and suggest next steps."),
                HumanMessage(content=str(results))
            ])
            
            response = self.llm.invoke(prompt)
            new_tasks = self._parse_tasks(response.content)
            
            planned_tasks = []
            for task in new_tasks:
                if self.scope.is_in_scope(task["parameters"]["target"]):
                    planned_task = self.task_manager.add_task(**task)
                    planned_tasks.append(planned_task)
            
            return planned_tasks
        except Exception as e:
            logger.error(f"Error in analyzing results: {str(e)}")
            return []

    def run(self, instruction: str) -> Dict[str, Any]:
        """Run the security assessment workflow"""
        try:
            logger.info(f"Starting security assessment: {instruction}")
            
            # Initial task planning
            tasks = self._plan_tasks(instruction)
            results = []
            
            # Execute tasks and analyze results in a loop
            while tasks:
                for task in tasks:
                    logger.info(f"Executing task: {task.description}")
                    result = self._execute_task(task)
                    if result:
                        results.append(result)
                
                # Analyze results and get new tasks
                tasks = self._analyze_results(results)
            
            # Generate final report
            return self._generate_report()
            
        except Exception as e:
            logger.error(f"Error running security assessment: {str(e)}")
            raise

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final report"""
        completed_tasks = [t for t in self.task_manager.tasks if t.status == TaskStatus.COMPLETED]
        failed_tasks = [t for t in self.task_manager.tasks if t.status == TaskStatus.FAILED]

        findings = []
        for task in completed_tasks:
            if task.result:
                findings.extend(self._parse_findings(task))

        return {
            "findings": findings,
            "summary": {
                "total_tasks": len(self.task_manager.tasks),
                "completed_tasks": len(completed_tasks),
                "failed_tasks": len(failed_tasks),
                "total_findings": len(findings)
            }
        }

    def _parse_tasks(self, llm_response: str) -> List[Dict]:
        """Parse LLM response into structured tasks"""
        tasks = []
        try:
            lines = llm_response.split("\n")
            current_task = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith("Tool:"):
                    if current_task:
                        tasks.append(current_task)
                    current_task = {"tool": line.split(":")[1].strip()}
                elif line.startswith("Target:"):
                    current_task["parameters"] = {"target": line.split(":")[1].strip()}
                elif line.startswith("Parameters:"):
                    # Update existing parameters
                    current_task["parameters"].update(eval(line.split(":", 1)[1].strip()))
                elif line.startswith("Description:"):
                    current_task["description"] = line.split(":", 1)[1].strip()

            if current_task:
                tasks.append(current_task)

            return tasks
        except Exception as e:
            logger.error(f"Error parsing tasks: {str(e)}")
            return []

    def _parse_findings(self, task: Task) -> List[str]:
        """Parse task results into findings"""
        findings = []
        try:
            if task.tool == "nmap":
                # Parse nmap results
                if "open_ports" in task.result:
                    for port in task.result["open_ports"]:
                        findings.append(f"Port {port} is open on {task.parameters['target']}")
            elif task.tool in ["gobuster", "ffuf"]:
                # Parse directory discovery results
                if "discovered_paths" in task.result:
                    for path in task.result["discovered_paths"]:
                        findings.append(f"Directory {path} found on {task.parameters['target']}")
        except Exception as e:
            logger.error(f"Error parsing findings: {str(e)}")
        
        return findings