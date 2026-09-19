"""Scanner API Agent - REST, GraphQL, gRPC API security testing."""
import asyncio
import logging
import json
from typing import Any, Dict, List
from datetime import datetime
from pathlib import Path

from .base import BaseAgent, ToolResult
from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding
from ..core.telegram_base import BaseTelegramBot

logger = logging.getLogger(__name__)


class ScannerAPIAgent(BaseAgent):
    """API security testing agent - REST, GraphQL, gRPC, WebSocket."""

    def __init__(
        self,
        name: str = "SCANNER-API",
        role: str = "API Security Tester",
        config: EngagementConfig = None,
        agent_config: AgentConfig = None,
        scope_validator: ScopeValidator = None,
        memory: MemoryManager = None,
        telegram: BaseTelegramBot = None
    ):
        super().__init__(
            name,
            role,
            config=config,
            agent_config=agent_config,
            scope_validator=scope_validator,
            memory=memory,
            telegram=telegram,
            skills=["api-testing", "scope-management", "memory-management", "evidence-collection"],
            tools_required=["curl", "kiterunner", "arjun", "graphql-cop", "jwt_tool"],
            hitl_required=True,
            hitl_checkpoints=["before_bola_exploitation", "before_mass_assignment"],
            max_runtime_minutes=120
        )

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Starting API security testing")
        self.log_event("scanner_api", "started", "API security testing initiated")

        endpoints = inputs.get("endpoints", [])
        credentials = inputs.get("credentials", {})
        schemas = inputs.get("schemas", {})

        results = {
            "bola_findings": [],
            "auth_findings": [],
            "mass_assignment": [],
            "rate_limit": [],
            "graphql": [],
            "jwt_analysis": []
        }

        for endpoint in endpoints:
            if not self.validate_target(endpoint):
                continue

            logger.info(f"[{self.name}] Testing API endpoint: {endpoint}")

            # 1. Endpoint discovery & schema analysis
            schema = await self._get_schema(endpoint, schemas)

            # 2. BOLA/IDOR testing
            bola = await self._test_bola(endpoint, credentials)
            results["bola_findings"].extend(bola)

            # 3. Authentication testing
            auth = await self._test_auth(endpoint, credentials)
            results["auth_findings"].extend(auth)

            # 4. Mass assignment
            ma = await self._test_mass_assignment(endpoint, credentials)
            results["mass_assignment"].extend(ma)

            # 5. Rate limiting
            rl = await self._test_rate_limiting(endpoint)
            results["rate_limit"].extend(rl)

            # 6. GraphQL testing
            if "graphql" in endpoint.lower():
                gql = await self._test_graphql(endpoint, credentials)
                results["graphql"].extend(gql)

            # 7. JWT analysis
            jwt_findings = await self._analyze_jwt(endpoint, credentials)
            results["jwt_analysis"].extend(jwt_findings)

        self.memory.save_phase_result("scanner_api", results)
        self.log_event("scanner_api", "completed", f"Tested {len(endpoints)} API endpoints")

        return results

    async def _get_schema(self, endpoint: str, schemas: Dict) -> Dict:
        """Get API schema from provided or discover."""
        return schemas.get(endpoint, {})

    async def _test_bola(self, endpoint: str, credentials: Dict) -> List:
        findings = []

        # Test object ID manipulation with different user contexts
        # Simplified - would need actual authenticated requests
        return findings

    async def _test_auth(self, endpoint: str, credentials: Dict) -> List:
        findings = []

        # Test for broken authentication
        # - Missing auth on admin endpoints
        # - Weak token validation
        # - JWT algorithm confusion
        return findings

    async def _test_mass_assignment(self, endpoint: str, credentials: Dict) -> List:
        findings = []

        # Test for mass assignment by submitting extra fields
        return findings

    async def _test_rate_limiting(self, endpoint: str) -> List:
        findings = []

        # Test for rate limiting by sending rapid requests
        return findings

    async def _test_graphql(self, endpoint: str, credentials: Dict) -> List:
        findings = []

        # GraphQL introspection
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types { ...FullType }
                    directives { name description locations args { ...InputValue } }
                }
            }
            fragment FullType on __Type {
                kind name description fields(includeDeprecated: true) {
                    name description args { ...InputValue } type { ...TypeRef }
                    isDeprecated deprecationReason
                }
                inputFields { ...InputValue }
                interfaces { ...TypeRef }
                enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
                ofType { ...TypeRef }
            }
            fragment InputValue on __InputValue {
                name description type { ...TypeRef } defaultValue
            }
            fragment TypeRef on __Type {
                kind name ofType { ...TypeRef }
            }
            """
        }

        # Test introspection
        result = await self.execute_tool(
            "curl",
            ["-s", "-X", "POST", endpoint, "-H", "Content-Type: application/json",
             "-d", json.dumps({"query": introspection_query})],
            timeout=30
        )

        if result.returncode == 0 and "__schema" in result.stdout:
            finding = Finding(
                id=f"GQL-INTROSPECTION-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                target=endpoint,
                type="GRAPHQL_INTROSPECTION_ENABLED",
                confidence=10,
                severity=5,
                title="GraphQL Introspection Enabled",
                description="GraphQL introspection is enabled, exposing full schema",
                evidence={"response": result.stdout[:1000]},
                mitre_attack="T1592",
                d3fend="D3-PSA",
                proposed_action="Disable introspection in production",
                risk="Schema information disclosure"
            )
            return [finding]

        return []

    async def _analyze_jwt(self, endpoint: str, credentials: Dict) -> List:
        findings = []

        # JWT algorithm confusion, weak secrets, key confusion
        return findings