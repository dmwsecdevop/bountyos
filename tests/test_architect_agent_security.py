"""
Tests for ArchitectAgent error sanitization security fix.

Verifies that the _sanitize_error method properly masks sensitive information
in exception messages before exposing them to API clients.
"""

import pytest
from api.agents.architect_agent import ArchitectAgent


class TestErrorSanitization:
    """Test suite for error message sanitization."""
    
    def test_sanitize_password(self):
        """Test password masking in error messages."""
        exc = Exception("Failed to connect with password=secretPass123")
        result = ArchitectAgent._sanitize_error(exc)
        assert "password" not in result or "***" in result
        assert "secretPass123" not in result
    
    def test_sanitize_api_key(self):
        """Test API key masking."""
        exc = Exception("Authentication failed: api_key=sk_live_abc123xyz789")
        result = ArchitectAgent._sanitize_error(exc)
        assert "api_key" not in result or "***" in result
        assert "sk_live_abc123xyz789" not in result
    
    def test_sanitize_token(self):
        """Test token masking."""
        exc = Exception("Request denied: token=eyJhbGciOiJIUzI1NiIs...")
        result = ArchitectAgent._sanitize_error(exc)
        assert "token" not in result or "***" in result
        assert "eyJhbGciOiJIUzI1NiIs" not in result
    
    def test_sanitize_bearer_token(self):
        """Test bearer token masking."""
        exc = Exception("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        result = ArchitectAgent._sanitize_error(exc)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
    
    def test_sanitize_file_paths(self):
        """Test file path masking."""
        exc = Exception("Error in /opt/app/secrets/database.py line 42")
        result = ArchitectAgent._sanitize_error(exc)
        # File paths should be masked or message should be generic
        assert "/opt/app/secrets" not in result or "***" in result
    
    def test_sanitize_database_url(self):
        """Test database connection string masking."""
        exc = Exception("Connection failed: postgres://user:password@db.internal:5432/bountyos")
        result = ArchitectAgent._sanitize_error(exc)
        assert "password" not in result or "***" in result
        assert "db.internal" not in result or "***" in result
    
    def test_sanitize_authorization_header(self):
        """Test authorization header masking."""
        exc = Exception("Invalid authorization: authorization=Bearer secret_token_123")
        result = ArchitectAgent._sanitize_error(exc)
        assert "secret_token_123" not in result
        assert "***" in result or "Internal processing error" in result
    
    def test_sanitize_secret_key(self):
        """Test secret key masking."""
        exc = Exception("Configuration error: secret=my_super_secret_key_xyz")
        result = ArchitectAgent._sanitize_error(exc)
        assert "my_super_secret_key_xyz" not in result
    
    def test_sanitize_traceback_fallback(self):
        """Test that stack traces trigger fallback to generic message."""
        exc = Exception(
            "Traceback (most recent call last):\n"
            "  File '/opt/app/api/agents/architect_agent.py', line 518, in handle\n"
            "    result = await self.act(...)\n"
            "Module initialization failed at import stage"
        )
        result = ArchitectAgent._sanitize_error(exc)
        # Should fallback to generic message when traceback keywords detected
        assert "Traceback" not in result
        assert "Internal processing error" in result
    
    def test_sanitize_long_message_fallback(self):
        """Test that very long messages trigger fallback to generic message."""
        # Create a message longer than 200 chars
        long_msg = "x" * 250
        exc = Exception(long_msg)
        result = ArchitectAgent._sanitize_error(exc)
        assert result == "Internal processing error."
    
    def test_preserve_safe_messages(self):
        """Test that safe, short error messages are preserved."""
        exc = Exception("Target not found")
        result = ArchitectAgent._sanitize_error(exc)
        assert "Target not found" in result
    
    def test_preserve_generic_user_messages(self):
        """Test that user-facing error messages are preserved."""
        exc = Exception("Scan could not be completed due to network timeout")
        result = ArchitectAgent._sanitize_error(exc)
        assert "Scan could not be completed" in result or "Scan" in result
    
    def test_multiple_sensitive_patterns(self):
        """Test sanitization with multiple sensitive patterns."""
        exc = Exception(
            "Failed to connect: password=pass123 at /etc/config.py "
            "using api_key=key_xyz and token=abc123"
        )
        result = ArchitectAgent._sanitize_error(exc)
        assert "pass123" not in result
        assert "key_xyz" not in result
        assert "abc123" not in result
    
    def test_empty_exception(self):
        """Test handling of empty exception."""
        exc = Exception("")
        result = ArchitectAgent._sanitize_error(exc)
        assert result == "Internal processing error."
    
    def test_exception_with_none_str(self):
        """Test exception conversion to string."""
        exc = Exception("Database connection failed")
        result = ArchitectAgent._sanitize_error(exc)
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_case_insensitive_masking(self):
        """Test that pattern matching is case-insensitive."""
        exc = Exception("PASSWORD=secret123 and Password=another_secret API_KEY=key123")
        result = ArchitectAgent._sanitize_error(exc)
        assert "secret123" not in result
        assert "another_secret" not in result
        assert "key123" not in result


class TestErrorSanitizationIntegration:
    """Integration tests for error sanitization in context."""
    
    def test_sanitization_preserves_error_intent(self):
        """Test that sanitization preserves enough info for debugging."""
        exc = Exception("Failed to authenticate user")
        result = ArchitectAgent._sanitize_error(exc)
        # Should be recognizable as auth error
        assert "Failed" in result or "authenticate" in result or "Internal" in result
    
    def test_multiple_calls_consistent(self):
        """Test that multiple calls produce consistent results."""
        exc = Exception("error_msg=value123 token=abc")
        result1 = ArchitectAgent._sanitize_error(exc)
        result2 = ArchitectAgent._sanitize_error(exc)
        assert result1 == result2
    
    def test_sanitization_no_side_effects(self):
        """Test that sanitization doesn't modify original exception."""
        exc = Exception("password=secret123")
        original_msg = str(exc)
        ArchitectAgent._sanitize_error(exc)
        assert str(exc) == original_msg


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
