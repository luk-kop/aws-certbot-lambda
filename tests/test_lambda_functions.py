"""Unit tests for standalone functions and lambda_handler."""

import json
from unittest.mock import Mock, patch

import pytest

pytestmark = pytest.mark.usefixtures("aws_credentials", "env_vars")


class TestRetryWithBackoff:
    """Test retry_with_backoff decorator."""

    @patch("lambda_function.time.sleep")
    def test_retry_success_first_attempt(self, mock_sleep):
        """Test function succeeds on first attempt."""
        from lambda_function import retry_with_backoff

        @retry_with_backoff(max_attempts=3, base_delay=1, exceptions=(ValueError,))
        def success_func():
            return "success"

        result = success_func()

        assert result == "success"
        mock_sleep.assert_not_called()

    @patch("lambda_function.time.sleep")
    def test_retry_success_after_failures(self, mock_sleep):
        """Test function succeeds after retries."""
        from lambda_function import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_attempts=3, base_delay=1, exceptions=(ValueError,))
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"

        result = flaky_func()

        assert result == "success"
        assert call_count == 3
        assert mock_sleep.call_count == 2

    @patch("lambda_function.time.sleep")
    def test_retry_exponential_backoff(self, mock_sleep):
        """Test exponential backoff delays."""
        from lambda_function import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_attempts=4, base_delay=5, exceptions=(ValueError,))
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 4:
                raise ValueError("Temporary failure")
            return "success"

        flaky_func()

        # Verify exponential backoff: 5, 10, 20
        delays = [call[0][0] for call in mock_sleep.call_args_list]
        assert delays == [5, 10, 20]

    @patch("lambda_function.time.sleep")
    def test_retry_max_attempts_exceeded(self, mock_sleep):
        """Test exception raised after max attempts."""
        from lambda_function import retry_with_backoff

        @retry_with_backoff(max_attempts=3, base_delay=1, exceptions=(ValueError,))
        def always_fails():
            raise ValueError("Always fails")

        with pytest.raises(ValueError, match="Always fails"):
            always_fails()

        assert mock_sleep.call_count == 2

    @patch("lambda_function.time.sleep")
    def test_retry_non_matching_exception(self, mock_sleep):
        """Test non-matching exceptions are not retried."""
        from lambda_function import retry_with_backoff

        @retry_with_backoff(max_attempts=3, base_delay=1, exceptions=(ValueError,))
        def raises_type_error():
            raise TypeError("Not retried")

        with pytest.raises(TypeError, match="Not retried"):
            raises_type_error()

        mock_sleep.assert_not_called()

    @patch("lambda_function.time.sleep")
    def test_retry_preserves_function_name(self, mock_sleep):
        """Test decorator preserves function metadata."""
        from lambda_function import retry_with_backoff

        @retry_with_backoff()
        def my_function():
            """My docstring."""
            pass

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."


class TestValidateConfig:
    """Test _validate_config function."""

    def test_validate_config_success(self):
        """Test validation passes with valid config."""
        import lambda_function
        from lambda_function import _validate_config

        # env_vars fixture sets valid values, verify they're applied
        assert lambda_function.DOMAINS == ["example.com", "*.example.com"]
        assert lambda_function.HOSTED_ZONE_ID == "Z1234567890"
        assert lambda_function.SECRET_NAME_PREFIX == "test-certbot"

        # Should not raise
        _validate_config()

    def test_validate_config_empty_domains(self):
        """Test validation fails with empty domains."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.DOMAINS
        try:
            lambda_function.DOMAINS = []
            with pytest.raises(
                ValueError, match="DOMAINS environment variable must not be empty"
            ):
                _validate_config()
        finally:
            lambda_function.DOMAINS = original

    def test_validate_config_empty_domain_string(self):
        """Test validation fails with empty domain string."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.DOMAINS
        try:
            lambda_function.DOMAINS = [""]
            with pytest.raises(
                ValueError, match="DOMAINS environment variable must not be empty"
            ):
                _validate_config()
        finally:
            lambda_function.DOMAINS = original

    def test_validate_config_missing_hosted_zone_id(self):
        """Test validation fails without hosted zone ID."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.HOSTED_ZONE_ID
        try:
            lambda_function.HOSTED_ZONE_ID = ""
            with pytest.raises(
                ValueError, match="HOSTED_ZONE_ID environment variable is required"
            ):
                _validate_config()
        finally:
            lambda_function.HOSTED_ZONE_ID = original

    def test_validate_config_missing_secret_name_prefix(self):
        """Test validation fails without secret name prefix."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.SECRET_NAME_PREFIX
        try:
            lambda_function.SECRET_NAME_PREFIX = ""
            with pytest.raises(
                ValueError, match="SECRET_NAME_PREFIX environment variable is required"
            ):
                _validate_config()
        finally:
            lambda_function.SECRET_NAME_PREFIX = original

    def test_validate_config_invalid_renewal_days_zero(self):
        """Test validation fails with zero renewal days."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.RENEWAL_DAYS_BEFORE_EXPIRY
        try:
            lambda_function.RENEWAL_DAYS_BEFORE_EXPIRY = 0
            with pytest.raises(
                ValueError, match="RENEWAL_DAYS_BEFORE_EXPIRY must be positive"
            ):
                _validate_config()
        finally:
            lambda_function.RENEWAL_DAYS_BEFORE_EXPIRY = original

    def test_validate_config_invalid_renewal_days_negative(self):
        """Test validation fails with negative renewal days."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.RENEWAL_DAYS_BEFORE_EXPIRY
        try:
            lambda_function.RENEWAL_DAYS_BEFORE_EXPIRY = -5
            with pytest.raises(
                ValueError, match="RENEWAL_DAYS_BEFORE_EXPIRY must be positive"
            ):
                _validate_config()
        finally:
            lambda_function.RENEWAL_DAYS_BEFORE_EXPIRY = original

    def test_validate_config_invalid_hosted_zone_format(self):
        """Test validation fails with invalid hosted zone format."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.HOSTED_ZONE_ID
        try:
            lambda_function.HOSTED_ZONE_ID = "invalid-zone-id"
            with pytest.raises(ValueError, match="Invalid HOSTED_ZONE_ID format"):
                _validate_config()
        finally:
            lambda_function.HOSTED_ZONE_ID = original

    def test_validate_config_hostedzone_path_format(self):
        """Test validation passes with /hostedzone/ format."""
        import lambda_function
        from lambda_function import _validate_config

        original = lambda_function.HOSTED_ZONE_ID
        try:
            lambda_function.HOSTED_ZONE_ID = "/hostedzone/Z1234567890"
            # Should not raise
            _validate_config()
        finally:
            lambda_function.HOSTED_ZONE_ID = original


class TestSendNotification:
    """Test send_notification function."""

    @patch("lambda_function.boto3.client")
    def test_send_notification_success(self, mock_boto_client):
        """Test successful SNS notification."""
        from lambda_function import send_notification

        mock_sns = Mock()
        mock_boto_client.return_value = mock_sns

        send_notification(
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            subject="Test Subject",
            message="Test message body",
        )

        mock_boto_client.assert_called_with("sns")
        mock_sns.publish.assert_called_once_with(
            TopicArn="arn:aws:sns:us-east-1:123456789012:test-topic",
            Subject="Test Subject",
            Message="Test message body",
        )

    @patch("lambda_function.boto3.client")
    def test_send_notification_failure(self, mock_boto_client):
        """Test SNS notification failure is handled gracefully."""
        from lambda_function import send_notification

        mock_sns = Mock()
        mock_sns.publish.side_effect = IOError("Network error")
        mock_boto_client.return_value = mock_sns

        # Should not raise
        send_notification(
            topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
            subject="Test Subject",
            message="Test message",
        )


class TestPublishEvent:
    """Test publish_event function."""

    @patch("lambda_function.boto3.client")
    def test_publish_event_success(self, mock_boto_client):
        """Test successful EventBridge event publishing."""
        from lambda_function import publish_event

        mock_events = Mock()
        mock_boto_client.return_value = mock_events

        publish_event(
            bus_name="test-bus",
            source="test-source",
            detail_type="TestEvent",
            detail={"key": "value"},
        )

        mock_boto_client.assert_called_with("events")
        mock_events.put_events.assert_called_once()

        call_args = mock_events.put_events.call_args
        entry = call_args[1]["Entries"][0]
        assert entry["Source"] == "test-source"
        assert entry["DetailType"] == "TestEvent"
        assert entry["EventBusName"] == "test-bus"
        assert json.loads(entry["Detail"]) == {"key": "value"}

    @patch("lambda_function.boto3.client")
    def test_publish_event_failure(self, mock_boto_client):
        """Test EventBridge failure is handled gracefully."""
        from lambda_function import publish_event

        mock_events = Mock()
        mock_events.put_events.side_effect = IOError("Network error")
        mock_boto_client.return_value = mock_events

        # Should not raise
        publish_event(
            bus_name="test-bus",
            source="test-source",
            detail_type="TestEvent",
            detail={"key": "value"},
        )
