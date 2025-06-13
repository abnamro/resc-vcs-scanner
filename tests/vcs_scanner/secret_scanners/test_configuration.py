# Third Party
import pytest
from _pytest.monkeypatch import MonkeyPatch

# First Party
from vcs_scanner.helpers.environment_wrapper import validate_environment
from vcs_scanner.secret_scanners.configuration import REQUIRED_ENV_VARS


def test_required_env_vars_empty():
    mp = MonkeyPatch()
    mp.delenv("GITLEAKS_PATH", False)
    mp.delenv("RESC_RABBITMQ_SERVICE_HOST", False)
    mp.delenv("RABBITMQ_DEFAULT_VHOST", False)
    mp.delenv("RESC_API_NO_AUTH_SERVICE_HOST", False)
    mp.delenv("RABBITMQ_USERNAME", False)
    mp.delenv("RABBITMQ_PASSWORD", False)
    mp.delenv("RABBITMQ_QUEUE", False)
    with pytest.raises(OSError) as pytest_wrapped_e:
        env_variables = validate_environment(REQUIRED_ENV_VARS)
        assert env_variables is None
        assert pytest_wrapped_e.value.code == -1
