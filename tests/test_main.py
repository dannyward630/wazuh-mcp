from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp import __main__ as cli
from wazuh_mcp.config import Settings


@pytest.mark.parametrize("port", [0, 65536])
def test_settings_from_validates_cli_port(monkeypatch, port: int) -> None:
    monkeypatch.setattr(cli, "load_settings", lambda: Settings(_env_file=None))

    with pytest.raises(ValidationError) as exc_info:
        cli.settings_from(cli.parse_args(["--port", str(port)]))

    assert exc_info.value.errors()[0]["loc"] == ("bind_port",)


def test_settings_from_normalizes_cli_path_and_preserves_loaded_values(monkeypatch) -> None:
    settings = Settings(_env_file=None, api_url="https://manager.example.test")
    monkeypatch.setattr(cli, "load_settings", lambda: settings)

    result = cli.settings_from(cli.parse_args(["--path", "mcp/"]))

    assert result.http_path == "/mcp"
    assert result.api_url == "https://manager.example.test"


def test_main_returns_configuration_error_for_invalid_cli_port(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "load_settings", lambda: Settings(_env_file=None))

    result = cli.main(["--transport", "http", "--port", "70000"])

    assert result == 2
    assert "bind_port" in capsys.readouterr().err
