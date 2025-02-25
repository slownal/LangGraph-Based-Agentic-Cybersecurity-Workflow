import pytest
from src.agents.security_agent import SecurityAgent
from src.core.scope import ScopeDefinition
from src.core.task_manager import Task, TaskStatus

@pytest.fixture
def scope():
    return ScopeDefinition(
        domains=["example.com"],
        ip_ranges=["192.168.1.0/24"],
        wildcards=["*.example.com"]
    )

@pytest.fixture
def security_agent(scope):
    return SecurityAgent(scope)

def test_scope_validation(scope):
    assert scope.is_in_scope("example.com") == True
    assert scope.is_in_scope("test.example.com") == True
    assert scope.is_in_scope("malicious.com") == False
    assert scope.is_in_scope("192.168.1.100") == True
    assert scope.is_in_scope("10.0.0.1") == False

def test_task_creation(security_agent):
    instruction = "Scan example.com for open ports"
    state = security_agent._plan_tasks({"instruction": instruction})
    
    assert len(security_agent.task_manager.tasks) > 0
    assert all(isinstance(task, Task) for task in security_agent.task_manager.tasks)

def test_task_execution(security_agent):
    # Create a test task
    task = security_agent.task_manager.add_task(
        description="Test port scan",
        tool="nmap",
        parameters={"target": "example.com", "ports": "80,443"}
    )
    
    state = security_agent._execute_task({"current_task": task})
    executed_task = security_agent.task_manager.tasks[0]
    
    assert executed_task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]

def test_out_of_scope_handling(security_agent):
    instruction = "Scan malicious.com for vulnerabilities"
    state = security_agent._plan_tasks({"instruction": instruction})
    
    # Check that no tasks were created for out-of-scope targets
    assert all(
        task.parameters["target"] != "malicious.com" 
        for task in security_agent.task_manager.tasks
    )

def test_retry_mechanism(security_agent):
    # Create a task that will fail
    task = security_agent.task_manager.add_task(
        description="Test retry",
        tool="nmap",
        parameters={"target": "nonexistent.example.com"}
    )
    
    state = security_agent._execute_task({"current_task": task})
    failed_task = security_agent.task_manager.tasks[0]
    
    assert failed_task.retries > 0 or failed_task.status == TaskStatus.FAILED

def test_result_analysis(security_agent):
    # Create a completed task with results
    task = security_agent.task_manager.add_task(
        description="Test analysis",
        tool="nmap",
        parameters={"target": "example.com"}
    )
    security_agent.task_manager.update_task_status(
        task.id,
        TaskStatus.COMPLETED,
        result={"open_ports": [80, 443]}
    )
    
    state = security_agent._analyze_results({})
    
    # Check if new tasks were created based on the analysis
    assert len(security_agent.task_manager.tasks) > 1

def test_report_generation(security_agent):
    # Add some completed tasks
    task1 = security_agent.task_manager.add_task(
        description="Port scan",
        tool="nmap",
        parameters={"target": "example.com"}
    )
    security_agent.task_manager.update_task_status(
        task1.id,
        TaskStatus.COMPLETED,
        result={"open_ports": [80, 443]}
    )
    
    report = security_agent._generate_report({})
    
    assert isinstance(report, dict)
    assert "findings" in report
    assert "summary" in report