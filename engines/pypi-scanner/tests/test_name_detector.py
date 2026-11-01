
import sys
from pathlib import Path

# Add the Python scanner directory to the import path.
SCANNER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCANNER_DIR))

from scanner.name_detector import (
    analyze_package_name,
    levenshtein_distance,
    normalize_package_name,
)
from scanner.name_detector import (
    detect_unicode_confusable,
    detect_keyboard_adjacent_substitution,
    damerau_levenshtein_distance,
)

def test_levenshtein_distance():
    assert levenshtein_distance("requests", "reqeusts") == 2
    assert levenshtein_distance("numpy", "numpy") == 0


def test_pypi_name_normalization():
    assert normalize_package_name("My_Package", "pypi") == (
        normalize_package_name("my-package", "pypi")
    )


def test_detect_typo_in_popular_package():
    result = analyze_package_name("reqeusts", "pypi")

    assert result["suspicious_name"] is True
    assert any(
        match["reference_package"] == "requests"
        for match in result["matches"]
    )


def test_normal_package_name():
    result = analyze_package_name("my-unique-project", "pypi")

    assert result["suspicious_name"] is False


def test_detect_npm_lookalike():
    result = analyze_package_name("reactt", "npm")

    assert result["suspicious_name"] is True
    assert any(
        match["reference_package"] == "react"
        for match in result["matches"]
    )


def test_detect_unicode_confusable():
    # The first character is Cyrillic 'а', not Latin 'a'.
    assert detect_unicode_confusable("аxios", "axios") is True


def test_detect_keyboard_adjacent_substitution():
    assert detect_keyboard_adjacent_substitution(
        "reacts",
        "reacta",
    ) is True


def test_detect_adjacent_transposition():
    assert damerau_levenshtein_distance(
        "reqeusts",
        "requests",
    ) == 1


def test_detect_repeated_character_lookalike():
    result = analyze_package_name("reactt", "npm")

    assert result["suspicious_name"] is True
    assert any(
        match["repeated_character"]
        for match in result["matches"]
    )


def test_normal_package_does_not_match_itself():
    result = analyze_package_name("requests", "pypi")

    assert result["suspicious_name"] is False


def test_invalid_ecosystem_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        analyze_package_name("example", "unknown")

