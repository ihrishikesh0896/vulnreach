#!/usr/bin/env python3
"""
Configuration management for VulnReach CLI

Handles loading and parsing of configuration from ~/.vulnreach/config/creds.yaml
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field
import logging


logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    """Configuration for a specific AI provider"""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    endpoint: Optional[str] = None
    org: Optional[str] = None
    api_version: Optional[str] = None
    models: Dict[str, str] = field(default_factory=dict)
    deployments: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    region: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    default_route: Optional[str] = None


@dataclass
class TaskRoute:
    """Configuration for task routing"""
    provider: str
    model: str


@dataclass
class Defaults:
    """Default configuration values"""
    timeout_s: int = 60
    max_retries: int = 3
    temperature: float = 0.2
    top_p: float = 1.0
    max_tokens: int = 2048


@dataclass
class Policy:
    """Configuration policy for task execution"""
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None


@dataclass
class VulnReachConfig:
    """Main configuration class for VulnReach"""
    version: int = 1
    defaults: Defaults = field(default_factory=Defaults)
    default_provider: str = "openai"
    default_task_routes: Dict[str, TaskRoute] = field(default_factory=dict)
    providers: Dict[str, ProviderConfig] = field(default_factory=dict)
    policies: Dict[str, Policy] = field(default_factory=dict)


class ConfigLoader:
    """Loads and manages VulnReach configuration"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration loader
        
        Args:
            config_path: Optional path to config file. Defaults to ~/.vulnreach/config/creds.yaml
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = Path.home() / ".vulnreach" / "config" / "creds.yaml"
        
        self._config: Optional[VulnReachConfig] = None
    
    def load_config(self) -> VulnReachConfig:
        """
        Load configuration from file with environment variable substitution
        
        Returns:
            VulnReachConfig: Loaded configuration object
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file has invalid YAML
            ValueError: If config has invalid structure
        """
        if not self.config_path.exists():
            logger.warning(f"Config file not found: {self.config_path}")
            return VulnReachConfig()
        
        try:
            with open(self.config_path, 'r') as f:
                raw_config = yaml.safe_load(f)
            
            if not raw_config:
                logger.warning("Config file is empty")
                return VulnReachConfig()
            
            # Substitute environment variables
            processed_config = self._substitute_env_vars(raw_config)
            
            # Parse and validate configuration
            config = self._parse_config(processed_config)
            
            self._config = config
            logger.info(f"Loaded configuration from {self.config_path}")
            
            return config
            
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Invalid YAML in config file {self.config_path}: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load config from {self.config_path}: {e}")
    
    def get_config(self) -> VulnReachConfig:
        """
        Get current configuration, loading if not already loaded
        
        Returns:
            VulnReachConfig: Current configuration
        """
        if self._config is None:
            self._config = self.load_config()
        return self._config
    
    def _substitute_env_vars(self, obj: Any) -> Any:
        """
        Recursively substitute environment variables in configuration
        
        Supports formats:
        - ${VAR_NAME} - required variable
        - ${VAR_NAME:-default} - variable with default value
        - ${VAR_NAME:-""} - variable with empty string default
        
        Args:
            obj: Configuration object (dict, list, or string)
            
        Returns:
            Configuration object with environment variables substituted
        """
        if isinstance(obj, dict):
            return {key: self._substitute_env_vars(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]
        elif isinstance(obj, str):
            return self._substitute_env_var_in_string(obj)
        else:
            return obj
    
    def _substitute_env_var_in_string(self, text: str) -> str:
        """
        Substitute environment variables in a string
        
        Args:
            text: String that may contain environment variable references
            
        Returns:
            String with environment variables substituted
        """
        import re
        
        # Pattern to match ${VAR_NAME} or ${VAR_NAME:-default}
        pattern = r'\$\{([^}]+)\}'
        
        def replace_var(match):
            var_expr = match.group(1)
            
            # Handle default values: VAR_NAME:-default
            if ':-' in var_expr:
                var_name, default_value = var_expr.split(':-', 1)
                # Remove quotes from default value if present
                if default_value.startswith('"') and default_value.endswith('"'):
                    default_value = default_value[1:-1]
                return os.getenv(var_name, default_value)
            else:
                # Required variable
                value = os.getenv(var_expr)
                if value is None:
                    logger.warning(f"Environment variable {var_expr} not set")
                    return f"${{{var_expr}}}"  # Keep original if not found
                return value
        
        return re.sub(pattern, replace_var, text)
    
    def _parse_config(self, config_data: Dict[str, Any]) -> VulnReachConfig:
        """
        Parse raw configuration data into structured config object
        
        Args:
            config_data: Raw configuration dictionary
            
        Returns:
            VulnReachConfig: Parsed configuration object
        """
        # Parse defaults
        defaults_data = config_data.get('defaults', {})
        defaults = Defaults(
            timeout_s=defaults_data.get('timeout_s', 60),
            max_retries=defaults_data.get('max_retries', 3),
            temperature=defaults_data.get('temperature', 0.2),
            top_p=defaults_data.get('top_p', 1.0),
            max_tokens=defaults_data.get('max_tokens', 2048)
        )
        
        # Parse default task routes
        default_task_routes = {}
        task_routes_data = config_data.get('default_task_routes', {})
        for task, route_data in task_routes_data.items():
            default_task_routes[task] = TaskRoute(
                provider=route_data['provider'],
                model=route_data['model']
            )
        
        # Parse providers
        providers = {}
        providers_data = config_data.get('providers', {})
        for provider_name, provider_data in providers_data.items():
            providers[provider_name] = ProviderConfig(
                api_key=provider_data.get('api_key'),
                base_url=provider_data.get('base_url'),
                endpoint=provider_data.get('endpoint'),
                org=provider_data.get('org'),
                api_version=provider_data.get('api_version'),
                models=provider_data.get('models', {}),
                deployments=provider_data.get('deployments', {}),
                headers=provider_data.get('headers', {}),
                region=provider_data.get('region'),
                access_key_id=provider_data.get('access_key_id'),
                secret_access_key=provider_data.get('secret_access_key'),
                session_token=provider_data.get('session_token'),
                default_route=provider_data.get('default_route')
            )
        
        # Parse policies
        policies = {}
        policies_data = config_data.get('policies', {})
        for policy_name, policy_data in policies_data.items():
            policies[policy_name] = Policy(
                temperature=policy_data.get('temperature'),
                max_tokens=policy_data.get('max_tokens'),
                top_p=policy_data.get('top_p')
            )
        
        return VulnReachConfig(
            version=config_data.get('version', 1),
            defaults=defaults,
            default_provider=config_data.get('default_provider', 'openai'),
            default_task_routes=default_task_routes,
            providers=providers,
            policies=policies
        )
    
    def create_default_config(self) -> None:
        """
        Create a default configuration file at the expected location
        """
        # Create directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        default_config = """# VulnReach Configuration
version: 1

defaults:
  timeout_s: 60
  max_retries: 3
  temperature: 0.2
  top_p: 1
  max_tokens: 2048

# Pick which provider/model to use by default
default_provider: openai
default_task_routes:
  summarize: { provider: openai,   model: gpt-4o-mini }
  codegen:   { provider: groq,     model: llama3-70b-8192 }
  embed:     { provider: openai,   model: text-embedding-3-large }

providers:
  openai:
    api_key: ${OPENAI_API_KEY}           # or: "sk-..."; env-var is recommended
    base_url: https://api.openai.com/v1
    org: ${OPENAI_ORG_ID:-""}
    models:
      chat: gpt-4o-mini
      reasoning: o4-mini
      embedding: text-embedding-3-large

  azure_openai:
    api_key: ${AZURE_OPENAI_API_KEY}
    endpoint: https://<your-resource>.openai.azure.com/
    api_version: 2024-08-01-preview      # example; set to what your deployment needs
    deployments:
      chat: gpt-4o                        # Azure uses deployment names
      embedding: text-embedding-3-large

  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    base_url: https://api.anthropic.com
    models:
      chat: claude-3-5-sonnet-20240620
      light: claude-3-5-haiku-20241022

  google_gemini:
    api_key: ${GOOGLE_API_KEY}
    endpoint: https://generativelanguage.googleapis.com
    models:
      chat: gemini-1.5-pro
      flash: gemini-1.5-flash

  cohere:
    api_key: ${COHERE_API_KEY}
    endpoint: https://api.cohere.ai
    models:
      chat: command-r-plus
      light: command-r

  mistral:
    api_key: ${MISTRAL_API_KEY}
    endpoint: https://api.mistral.ai
    models:
      chat: mistral-large-latest

  groq:
    api_key: ${GROQ_API_KEY}
    endpoint: https://api.groq.com/openai/v1
    models:
      chat: llama3-70b-8192
      light: llama3-8b-8192

  together:
    api_key: ${TOGETHER_API_KEY}
    endpoint: https://api.together.xyz/v1
    models:
      chat: meta-llama/Meta-Llama-3-70B-Instruct-Turbo

  openrouter:
    api_key: ${OPENROUTER_API_KEY}
    endpoint: https://openrouter.ai/api/v1
    default_route: anthropic/claude-3.5-sonnet
    headers:
      HTTP-Referer: https://yourapp.example
      X-Title: Your App

  deepseek:
    api_key: ${DEEPSEEK_API_KEY}
    endpoint: https://api.deepseek.com
    models:
      chat: deepseek-chat

  perplexity:
    api_key: ${PERPLEXITY_API_KEY}
    endpoint: https://api.perplexity.ai
    models:
      chat: pplx-70b-online

  aws_bedrock:
    # Prefer IAM roles where possible; keys shown for local/dev only
    region: ap-south-1
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    session_token: ${AWS_SESSION_TOKEN:-""}
    endpoint: https://bedrock-runtime.ap-south-1.amazonaws.com
    models:
      chat: "anthropic.claude-3-5-sonnet-20240620-v1:0"  # example ARN suffix

# Optional per-task overrides (e.g., throttling, safety, logit bias)
policies:
  safe_default:
    temperature: 0.1
    max_tokens: 1024
  creative:
    temperature: 0.8
    top_p: 0.95
"""
        
        with open(self.config_path, 'w') as f:
            f.write(default_config)
        
        print(f"Created default configuration file: {self.config_path}")
    
    def get_provider_config(self, provider_name: str) -> Optional[ProviderConfig]:
        """
        Get configuration for a specific provider
        
        Args:
            provider_name: Name of the provider
            
        Returns:
            ProviderConfig: Provider configuration or None if not found
        """
        config = self.get_config()
        return config.providers.get(provider_name)
    
    def get_task_route(self, task_name: str) -> Optional[TaskRoute]:
        """
        Get task routing configuration for a specific task
        
        Args:
            task_name: Name of the task
            
        Returns:
            TaskRoute: Task route configuration or None if not found
        """
        config = self.get_config()
        return config.default_task_routes.get(task_name)
    
    def get_policy(self, policy_name: str) -> Optional[Policy]:
        """
        Get policy configuration
        
        Args:
            policy_name: Name of the policy
            
        Returns:
            Policy: Policy configuration or None if not found
        """
        config = self.get_config()
        return config.policies.get(policy_name)
    
    def has_valid_api_keys(self) -> Tuple[bool, List[str]]:
        """
        Check if any valid API keys are configured
        
        Returns:
            Tuple of (has_keys, list_of_configured_providers)
        """
        config = self.get_config()
        valid_providers = []
        
        for provider_name, provider_config in config.providers.items():
            # Check if provider has any valid credentials
            has_creds = False
            
            # Check standard API key
            if provider_config.api_key and provider_config.api_key.strip():
                # Skip if it's still a placeholder like ${ENV_VAR}
                if not provider_config.api_key.startswith('${'):
                    has_creds = True
            
            # Check AWS-specific credentials for bedrock
            if provider_name == 'aws_bedrock':
                if (provider_config.access_key_id and provider_config.access_key_id.strip() and
                    not provider_config.access_key_id.startswith('${')):
                    has_creds = True
            
            if has_creds:
                valid_providers.append(provider_name)
        
        return len(valid_providers) > 0, valid_providers


# Global config loader instance
_config_loader = None


def get_config_loader(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Get global config loader instance
    
    Args:
        config_path: Optional path to config file
        
    Returns:
        ConfigLoader: Global config loader instance
    """
    global _config_loader
    if _config_loader is None or config_path:
        _config_loader = ConfigLoader(config_path)
    return _config_loader


def load_config(config_path: Optional[str] = None) -> VulnReachConfig:
    """
    Load configuration from file
    
    Args:
        config_path: Optional path to config file
        
    Returns:
        VulnReachConfig: Loaded configuration
    """
    loader = get_config_loader(config_path)
    return loader.load_config()


def get_config() -> VulnReachConfig:
    """
    Get current configuration
    
    Returns:
        VulnReachConfig: Current configuration
    """
    loader = get_config_loader()
    return loader.get_config()