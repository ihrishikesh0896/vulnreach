#!/usr/bin/env python3
"""
Base Agent Framework for VulnReach

Provides the foundation for specialized agents that use ast-grep and LLM
to analyze vulnerabilities, determine reachability, and propose remediations.
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Agent execution status"""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"


class ToolType(Enum):
    """Available tool types for agents"""
    AST_GREP = "ast_grep"
    LLM = "llm"
    SEMGREP = "semgrep"
    TEST_RUNNER = "test_runner"
    GIT_OPS = "git_ops"


@dataclass
class AgentTask:
    """Represents a task for an agent to execute"""
    task_id: str
    task_type: str
    input_data: Dict[str, Any]
    priority: int = 5  # 1-10, higher is more urgent
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 300  # seconds
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Result from agent execution"""
    task_id: str
    agent_name: str
    status: AgentStatus
    output_data: Dict[str, Any]
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    llm_interactions: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class AgentMemory:
    """Persistent memory for agent learning"""
    agent_name: str
    successful_patterns: List[str] = field(default_factory=list)
    failed_patterns: List[str] = field(default_factory=list)
    learned_fixes: Dict[str, Any] = field(default_factory=dict)
    call_graphs: Dict[str, Any] = field(default_factory=dict)
    validation_history: List[Dict[str, Any]] = field(default_factory=list)


class BaseTool(ABC):
    """Abstract base class for agent tools"""
    
    def __init__(self, name: str):
        self.name = name
        self.call_count = 0
        self.total_time = 0.0
    
    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """Execute the tool with given parameters"""
        pass
    
    def __call__(self, **kwargs) -> Any:
        """Make tool callable"""
        self.call_count += 1
        start_time = datetime.now()
        result = self.execute(**kwargs)
        elapsed = (datetime.now() - start_time).total_seconds()
        self.total_time += elapsed
        return result


class BaseAgent(ABC):
    """
    Abstract base class for all agents.
    
    Each agent specializes in a specific task (scanning, reachability, remediation, etc.)
    and uses tools (ast-grep, LLM) to accomplish its goals.
    """
    
    def __init__(
        self,
        name: str,
        project_root: str,
        tools: Optional[Dict[str, BaseTool]] = None
    ):
        self.name = name
        self.project_root = project_root
        self.status = AgentStatus.IDLE
        self.memory = AgentMemory(agent_name=name)
        
        # Initialize tools
        self.tools = tools or {}
        
        # Execution tracking
        self.task_history: List[AgentResult] = []
        self.current_task: Optional[AgentTask] = None
    
    @abstractmethod
    def execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute a specific task.
        
        This method must be implemented by each specialized agent.
        """
        pass
    
    def run(self, task: AgentTask) -> AgentResult:
        """
        Main execution loop with error handling and retries.
        
        Args:
            task: Task to execute
            
        Returns:
            AgentResult with execution details
        """
        self.current_task = task
        self.status = AgentStatus.RUNNING
        start_time = datetime.now()
        
        try:
            logger.info(f"Agent {self.name} starting task {task.task_id}")
            result = self.execute_task(task)
            result.execution_time = (datetime.now() - start_time).total_seconds()
            
            if result.status == AgentStatus.FAILED and task.retry_count < task.max_retries:
                logger.warning(f"Task {task.task_id} failed, retrying ({task.retry_count + 1}/{task.max_retries})")
                task.retry_count += 1
                return self.run(task)
            
            self.status = AgentStatus.COMPLETED
            self.task_history.append(result)
            logger.info(f"Agent {self.name} completed task {task.task_id} in {result.execution_time:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Agent {self.name} encountered error: {e}", exc_info=True)
            self.status = AgentStatus.FAILED
            
            error_result = AgentResult(
                task_id=task.task_id,
                agent_name=self.name,
                status=AgentStatus.FAILED,
                output_data={},
                error_message=str(e),
                execution_time=(datetime.now() - start_time).total_seconds()
            )
            self.task_history.append(error_result)
            return error_result
    
    def use_tool(self, tool_name: str, **kwargs) -> Any:
        """
        Use a specific tool and log the interaction.
        
        Args:
            tool_name: Name of tool to use
            **kwargs: Tool-specific parameters
            
        Returns:
            Tool execution result
        """
        if tool_name not in self.tools:
            logger.error(f"Tool {tool_name} not available for agent {self.name}")
            return None
        
        tool = self.tools[tool_name]
        result = tool(**kwargs)
        
        return result
    
    def remember(self, key: str, value: Any):
        """Store information in agent memory"""
        if not hasattr(self.memory, key):
            setattr(self.memory, key, value)
        else:
            existing = getattr(self.memory, key)
            if isinstance(existing, list):
                existing.append(value)
            elif isinstance(existing, dict):
                existing.update(value)
            else:
                setattr(self.memory, key, value)
    
    def recall(self, key: str) -> Any:
        """Retrieve information from agent memory"""
        return getattr(self.memory, key, None)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get agent performance statistics"""
        total_tasks = len(self.task_history)
        successful_tasks = sum(1 for r in self.task_history if r.status == AgentStatus.COMPLETED)
        failed_tasks = sum(1 for r in self.task_history if r.status == AgentStatus.FAILED)
        avg_time = sum(r.execution_time for r in self.task_history) / max(total_tasks, 1)
        
        tool_stats = {}
        for tool_name, tool in self.tools.items():
            tool_stats[tool_name] = {
                "call_count": tool.call_count,
                "total_time": tool.total_time,
                "avg_time": tool.total_time / max(tool.call_count, 1)
            }
        
        return {
            "agent_name": self.name,
            "total_tasks": total_tasks,
            "successful_tasks": successful_tasks,
            "failed_tasks": failed_tasks,
            "success_rate": successful_tasks / max(total_tasks, 1),
            "average_execution_time": avg_time,
            "tool_statistics": tool_stats
        }


class ScannerAgent(BaseAgent):
    """
    Scanner Agent: Finds usage of vulnerable packages in codebase.
    
    Uses ast-grep to locate imports, function calls, and instantiations.
    """
    
    def __init__(self, project_root: str, tools: Optional[Dict[str, BaseTool]] = None):
        super().__init__(name="Scanner", project_root=project_root, tools=tools)
    
    def execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute scanning task.
        
        Expected input_data:
            - package_name: str
            - language: str
            - pattern_type: str (import, call, instantiation)
        """
        package_name = task.input_data.get("package_name")
        language = task.input_data.get("language", "python")
        pattern_type = task.input_data.get("pattern_type", "import")
        
        return AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            output_data={
                "package_name": package_name,
                "message": "Scanner agent placeholder - ast-grep integration pending"
            }
        )
