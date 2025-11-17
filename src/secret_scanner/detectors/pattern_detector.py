"""Pattern-based secret detection."""

from typing import List, Dict, Any
import hashlib
from datetime import datetime, timezone

from ..core.models import Finding, SourceLocation, Severity, Confidence
from ..core.config import SECRET_PATTERNS
from ..utils.text_utils import get_line_col_from_index


class PatternDetector:
    """Detects secrets using predefined regex patterns."""
    
    def __init__(self):
        self.patterns = SECRET_PATTERNS
        self._severity_map = self._build_severity_map()
        self._description_map = self._build_description_map()
        self._remediation_map = self._build_remediation_map()
    
    def detect(self, text: str, source_info: Dict[str, Any]) -> List[Finding]:
        """Detect secrets in text using patterns."""
        findings = []
        
        if not text:
            return findings
        
        for pattern_name, regex in self.patterns.items():
            for match in regex.finditer(text):
                finding = self._create_finding(
                    pattern_name, match, text, source_info
                )
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _create_finding(self, pattern_name: str, match, text: str, source_info: Dict[str, Any]) -> Finding:
        """Create a Finding object from a regex match."""
        matched_text = self._extract_match(match)
        start_pos = match.start()
        line, col = get_line_col_from_index(text, start_pos)
        context = self._extract_context(text, start_pos, match.end())
        
        # Generate unique ID
        finding_id = self._generate_finding_id(pattern_name, matched_text, start_pos)
        
        # Create source location
        source = SourceLocation(
            type=source_info.get("type", "unknown"),
            url=source_info.get("url", ""),
            line=line,
            col=col,
            tag=source_info.get("tag"),
            attr=source_info.get("attr"),
            storage=source_info.get("storage"),
            key=source_info.get("key")
        )
        
        return Finding(
            id=finding_id,
            type=pattern_name,
            severity=self._get_severity(pattern_name),
            description=self._get_description(pattern_name),
            match=self._truncate_match(matched_text),
            match_length=len(matched_text),
            context=context,
            snippet=context[:200],
            remediation=self._get_remediation(pattern_name),
            confidence=Confidence.HIGH,
            source=source,
            timestamp=datetime.now(timezone.utc)
        )
    
    def _extract_match(self, match) -> str:
        """Extract the matched text, preferring capture groups."""
        groups = match.groups()
        if groups:
            return next((g for g in groups if g), match.group(0))
        return match.group(0)
    
    def _extract_context(self, text: str, start: int, end: int) -> str:
        """Extract context around the match."""
        context_start = max(0, start - 80)
        context_end = min(len(text), end + 80)
        return text[context_start:context_end].replace("\n", " ")
    
    def _truncate_match(self, match: str) -> str:
        """Truncate long matches for security."""
        if len(match) > 50:
            return match[:50] + "..."
        return match
    
    def _generate_finding_id(self, pattern_name: str, match: str, position: int) -> str:
        """Generate unique ID for finding."""
        content = f"{pattern_name}_{match}_{position}"
        hash_obj = hashlib.md5(content.encode())
        return f"{pattern_name}_{hash_obj.hexdigest()[:8]}"
    
    def _get_severity(self, pattern_name: str) -> Severity:
        """Get severity level for pattern."""
        return self._severity_map.get(pattern_name, Severity.INFO)
    
    def _get_description(self, pattern_name: str) -> str:
        """Get description for pattern."""
        return self._description_map.get(pattern_name, "Unknown secret type detected")
    
    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation advice for pattern."""
        return self._remediation_map.get(pattern_name, "Review and rotate this credential if sensitive.")
    
    def _build_severity_map(self) -> Dict[str, Severity]:
        """Build mapping of patterns to severity levels."""
        return {
            # High severity
            "aws_access_key": Severity.HIGH,
            "aws_secret_key_like": Severity.HIGH,
            "private_key": Severity.HIGH,
            "ssh_private_key": Severity.HIGH,
            
            # Medium severity
            "jwt_like": Severity.MEDIUM,
            "github_token": Severity.MEDIUM,
            "github_classic_token": Severity.MEDIUM,
            "stripe_secret": Severity.MEDIUM,
            "stripe_publishable": Severity.MEDIUM,
            "google_api_key": Severity.MEDIUM,
            "google_oauth_key": Severity.MEDIUM,
            "slack_token": Severity.MEDIUM,
            "discord_token": Severity.MEDIUM,
            "telegram_bot_token": Severity.MEDIUM,
            "gitlab_token": Severity.MEDIUM,
            "azure_client_secret": Severity.MEDIUM,
            "paypal_client_id": Severity.MEDIUM,
            "mongodb_uri": Severity.MEDIUM,
            "postgres_uri": Severity.MEDIUM,
            "mysql_uri": Severity.MEDIUM,
            
            # Low severity
            "bearer_token_header": Severity.LOW,
            "basic_auth_inline": Severity.LOW,
            "generic_key": Severity.LOW,
            "password_param": Severity.LOW,
            "bearer_in_url": Severity.LOW,
            "aws_session_token": Severity.LOW,
        }
    
    def _build_description_map(self) -> Dict[str, str]:
        """Build mapping of patterns to descriptions."""
        return {
            "jwt_like": "JSON Web Token - May contain sensitive user data or authentication info",
            "aws_access_key": "AWS Access Key - Provides access to AWS services and resources",
            "aws_secret_key_like": "AWS Secret Key - Critical credential for AWS authentication",
            "github_token": "GitHub Personal Access Token - Grants access to GitHub repositories",
            "github_classic_token": "GitHub Classic Token - Grants access to GitHub repositories",
            "stripe_secret": "Stripe Secret Key - Allows processing payments and accessing customer data",
            "stripe_publishable": "Stripe Publishable Key - Client-side payment processing key",
            "google_api_key": "Google API Key - Provides access to Google Cloud services",
            "google_oauth_key": "Google OAuth Key - Authentication credential for Google services",
            "private_key": "Private Key - Critical cryptographic key for authentication/encryption",
            "ssh_private_key": "SSH Private Key - Allows server access and authentication",
            "bearer_token_header": "Bearer Token - Authentication token found in headers",
            "basic_auth_inline": "Basic Authentication - Username/password in URL",
            "generic_key": "Generic API Key/Secret - Potentially sensitive credential",
            "slack_token": "Slack Token - Provides access to Slack workspace",
            "discord_token": "Discord Token - Bot or user authentication token",
            "telegram_bot_token": "Telegram Bot Token - Bot authentication credential",
            "gitlab_token": "GitLab Token - Personal access token for GitLab",
            "azure_client_secret": "Azure Client Secret - Authentication credential for Azure",
            "paypal_client_id": "PayPal Client ID - Payment processing credential",
            "mongodb_uri": "MongoDB Connection URI - Database connection string with credentials",
            "postgres_uri": "PostgreSQL Connection URI - Database connection string with credentials",
            "mysql_uri": "MySQL Connection URI - Database connection string with credentials",
            "password_param": "Password Parameter - Password found in URL parameters",
            "bearer_in_url": "Bearer Token in URL - Authentication token in URL parameters",
            "aws_session_token": "AWS Session Token - Temporary AWS authentication token",
        }
    
    def _build_remediation_map(self) -> Dict[str, str]:
        """Build mapping of patterns to remediation advice."""
        return {
            "jwt_like": "Revoke and regenerate JWT tokens. Implement proper token expiration.",
            "aws_access_key": "URGENT: Rotate AWS keys immediately. Review CloudTrail logs for unauthorized access.",
            "aws_secret_key_like": "URGENT: Rotate AWS credentials immediately. Check for unauthorized resource usage.",
            "github_token": "Revoke token in GitHub settings. Generate new token with minimal required permissions.",
            "github_classic_token": "Revoke token in GitHub settings. Generate new token with minimal required permissions.",
            "stripe_secret": "Rotate Stripe keys immediately. Review transaction logs for unauthorized activity.",
            "stripe_publishable": "Rotate Stripe keys immediately. Review transaction logs for unauthorized activity.",
            "google_api_key": "Regenerate API key. Restrict key usage to specific IPs/domains if possible.",
            "google_oauth_key": "Regenerate OAuth credentials. Review application permissions.",
            "private_key": "Replace private key immediately. Update all systems using this key.",
            "ssh_private_key": "Replace SSH key pair. Remove old public key from all authorized_keys files.",
            "bearer_token_header": "Invalidate current tokens. Implement proper token rotation.",
            "basic_auth_inline": "Remove credentials from URLs. Use proper authentication headers.",
            "generic_key": "Rotate the credential. Review access logs for unauthorized usage.",
            "slack_token": "Revoke token in Slack settings. Generate new token with minimal permissions.",
            "discord_token": "Regenerate Discord token. Review bot permissions.",
            "telegram_bot_token": "Regenerate bot token through BotFather. Update bot configuration.",
            "gitlab_token": "Revoke token in GitLab settings. Generate new token with minimal permissions.",
            "azure_client_secret": "Rotate Azure client secret. Update application configuration.",
            "paypal_client_id": "Rotate PayPal credentials. Review transaction history.",
            "mongodb_uri": "Change database credentials. Update connection strings.",
            "postgres_uri": "Change database credentials. Update connection strings.",
            "mysql_uri": "Change database credentials. Update connection strings.",
            "password_param": "Remove password from URL. Use proper authentication methods.",
            "bearer_in_url": "Remove token from URL. Use proper authentication headers.",
            "aws_session_token": "Session tokens are temporary but should not be exposed. Review IAM policies.",
        }