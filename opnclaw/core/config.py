"""Configuration loading with environment variable substitution."""
import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class TelegramConfig:
    bot_token: str
    chat_id: str
    parse_mode: str = "Markdown"
    notify_on: list = field(default_factory=list)
    compact_mode: bool = True
    max_message_length: int = 4000


@dataclass
class ScopeConfig:
    in_scope: Dict[str, list] = field(default_factory=dict)
    out_of_scope: Dict[str, list] = field(default_factory=dict)
    credentials: list = field(default_factory=list)
    rules_of_engagement: list = field(default_factory=list)


@dataclass
class RulesConfig:
    testing_window: str = "24/7"
    max_scan_rate: int = 100
    stealth_mode: bool = False
    auto_exploit: bool = False
    token_efficiency: bool = False
    allowed_techniques: list = field(default_factory=list)
    technique_config: Dict = field(default_factory=dict)
    reporting: Dict = field(default_factory=dict)


@dataclass
class AgentConfig:
    max_concurrent_agents: int = 7
    timeout_per_task: int = 3600
    retry_on_failure: bool = True
    max_retries: int = 3
    mcp_config_path: str = "config/mcp_servers.yaml"
    calibration: Dict = field(default_factory=dict)


@dataclass
class EngagementConfig:
    name: str = "Security Assessment"
    client: str = "Target Client"
    type: str = "blackbox"
    start_date: str = ""
    end_date: str = ""
    operator: str = "@SecurityLead"
    aegis_version: str = "1.0.0"
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    credentials: list = field(default_factory=list)
    rules: RulesConfig = field(default_factory=RulesConfig)
    telegram: Optional[TelegramConfig] = None
    agent: AgentConfig = field(default_factory=AgentConfig)
    aegis: Dict = field(default_factory=dict)


def substitute_env_vars(value: Any) -> Any:
    """Recursively substitute ${VAR_NAME} or ${VAR_NAME:default} with environment variables."""
    if isinstance(value, str):
        import re
        def replace(match):
            var_expr = match.group(1)
            if ':' in var_expr:
                var_name, default = var_expr.split(':', 1)
                return os.getenv(var_name, default)
            return os.getenv(var_expr, match.group(0))
        return re.sub(r'\$\{([^}]+)\}', replace, value)
    elif isinstance(value, dict):
        return {k: substitute_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [substitute_env_vars(v) for v in value]
    return value


def load_config(config_path: str) -> EngagementConfig:
    """Load engagement configuration from YAML with env var substitution."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    
    with open(path) as f:
        raw = yaml.safe_load(f)
    
    raw = substitute_env_vars(raw)
    engagement_data = raw.get('engagement', raw)
    
    # Parse nested configs
    scope_data = engagement_data.get('scope', {})
    scope = ScopeConfig(
        in_scope=scope_data.get('in_scope', {}),
        out_of_scope=scope_data.get('out_of_scope', {}),
        credentials=scope_data.get('credentials', []),
        rules_of_engagement=scope_data.get('notes', [])
    )
    
    rules_data = engagement_data.get('rules', {})
    rules = RulesConfig(
        testing_window=rules_data.get('testing_window', '24/7'),
        max_scan_rate=rules_data.get('max_scan_rate', 100),
        stealth_mode=rules_data.get('stealth_mode', False),
        auto_exploit=rules_data.get('auto_exploit', False),
        token_efficiency=rules_data.get('token_efficiency', False),
        allowed_techniques=rules_data.get('allowed_techniques', []),
        technique_config=rules_data.get('technique_config', {}),
        reporting=rules_data.get('reporting', {})
    )
    
    telegram_data = engagement_data.get('telegram', {})
    telegram = TelegramConfig(
        bot_token=telegram_data.get('bot_token', ''),
        chat_id=telegram_data.get('chat_id', ''),
        parse_mode=telegram_data.get('parse_mode', 'Markdown'),
        notify_on=telegram_data.get('notify_on', []),
        compact_mode=telegram_data.get('compact_mode', True),
        max_message_length=telegram_data.get('max_message_length', 4000)
    )
    
    agent_data = engagement_data.get('agent', {})
    agent = AgentConfig(
        max_concurrent_agents=agent_data.get('max_concurrent_agents', 7),
        timeout_per_task=agent_data.get('timeout_per_task', 3600),
        retry_on_failure=agent_data.get('retry_on_failure', True),
        max_retries=agent_data.get('max_retries', 3),
        mcp_config_path=agent_data.get('mcp_config_path', 'config/mcp_servers.yaml'),
        calibration=agent_data.get('calibration', {})
    )
    
    return EngagementConfig(
        name=engagement_data.get('name', 'Security Assessment'),
        client=engagement_data.get('client', 'Target Client'),
        type=engagement_data.get('type', 'blackbox'),
        start_date=engagement_data.get('start_date', ''),
        end_date=engagement_data.get('end_date', ''),
        operator=engagement_data.get('operator', '@SecurityLead'),
        aegis_version=engagement_data.get('aegis_version', '1.0.0'),
        scope=scope,
        credentials=engagement_data.get('credentials', []),
        rules=rules,
        telegram=telegram,
        agent=agent,
        aegis=engagement_data.get('aegis', {})
    )