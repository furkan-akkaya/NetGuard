from dataclasses import fields

import pytest

from netguard.config import Config, ConfigError, load_config


def _write(tmp_path, text):
    path = tmp_path / "netguard.toml"
    path.write_text(text)
    return path


def test_defaults_without_file():
    cfg = load_config(None)
    assert cfg.portscan.min_distinct_ports == 15
    assert cfg.is_allowlisted("10.0.0.1") is False


def test_valid_file(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            """
allowlist = ["10.0.0.5", "192.168.50.0/24"]
[portscan]
min_distinct_ports = 30
window_seconds = 120
[arpspoof]
critical_ips = ["10.0.0.1"]
""",
        )
    )
    assert cfg.portscan.min_distinct_ports == 30
    assert cfg.portscan.window_seconds == 120.0
    assert cfg.arpspoof.critical_ips == ["10.0.0.1"]
    assert cfg.is_allowlisted("192.168.50.77")
    assert not cfg.is_allowlisted("192.168.51.1")


def test_example_config_in_repo_is_valid():
    load_config("netguard.example.toml")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[portscan]\nmin_distinct_port = 3", "unknown keys: min_distinct_port"),
        ("[portscn]\n", "unknown sections"),
        ("[portscan]\nmin_distinct_ports = 'ten'", "expected int"),
        ("[portscan]\nmin_distinct_ports = 0", "must be > 0"),
        ("[portscan]\nenabled = 1", "expected bool"),
        ("allowlist = ['not-an-ip']", "allowlist"),
        ("allowlist = 'x'", "allowlist must be a list"),
        ("[portscan", "netguard.toml"),
    ],
)
def test_invalid_files(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load_config(_write(tmp_path, text))


def test_ratios_and_probabilities_are_bounded(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text("[synflood]\nmax_completion_ratio = 1.5\n")
    with pytest.raises(ConfigError, match="<= 1"):
        load_config(cfg)


def test_trw_probabilities_must_be_ordered(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text("[trw]\nscanner_success_probability = 0.9\n")
    with pytest.raises(ConfigError, match="trw"):
        load_config(cfg)


def test_example_config_matches_the_code_defaults():
    """The documented example must never drift from the real defaults."""
    example = load_config("netguard.example.toml")
    defaults = Config()
    for f in fields(Config):
        if f.name != "allowlist":
            assert getattr(example, f.name) == getattr(defaults, f.name), f.name
