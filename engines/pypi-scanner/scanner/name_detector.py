
import json
import re
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path
from typing import Sequence


# =========================================================
# CONFIGURATION
# =========================================================

DEFAULT_THRESHOLD = 75

PROJECT_ROOT = Path(__file__).resolve().parents[3]

POPULAR_PACKAGES_FILE = (
    PROJECT_ROOT / "shared" / "rules" / "popular-packages.json"
)


# =========================================================
# VISUAL CONFUSABLES
# =========================================================

# Focused Greek and Cyrillic mappings.
# This is a heuristic mapping, not a complete Unicode table.

CONFUSABLES = {
    "а": "a", "ɑ": "a", "α": "a",
    "е": "e", "ε": "e",
    "о": "o", "ο": "o",
    "р": "p", "ρ": "p",
    "с": "c", "ϲ": "c",
    "х": "x", "χ": "x",
    "у": "y", "γ": "y",
    "і": "i", "ι": "i",
    "ј": "j",
    "к": "k", "κ": "k",
    "м": "m", "μ": "m",
    "т": "t", "τ": "t",
    "в": "b", "β": "b",
    "н": "h", "η": "h",
    "ѕ": "s",
    "ԁ": "d",
    "ӏ": "l",
}

DIGIT_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "8": "b",
}


# QWERTY rows, used for approximate keyboard adjacency.
KEYBOARD_ROWS = (
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


# =========================================================
# PACKAGE REFERENCE DATABASE
# =========================================================

def load_popular_packages(ecosystem: str) -> list[str]:
    """
    Load popular package names for the requested ecosystem.

    Expected JSON:
    {
        "pypi": ["requests", "numpy"],
        "npm": ["react", "express"]
    }
    """

    if ecosystem not in {"pypi", "npm"}:
        raise ValueError("Ecosystem must be 'pypi' or 'npm'.")

    try:
        with POPULAR_PACKAGES_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            database = json.load(file)

        packages = database.get(ecosystem, [])

        if not isinstance(packages, list):
            return []

        # Remove invalid and duplicate entries.
        return list(
            dict.fromkeys(
                package.strip()
                for package in packages
                if isinstance(package, str) and package.strip()
            )
        )

    except FileNotFoundError:
        return []

    except (json.JSONDecodeError, OSError):
        return []


# =========================================================
# PACKAGE NAME NORMALIZATION
# =========================================================

def normalize_package_name(
    name: str,
    ecosystem: str = "pypi",
) -> str:
    """
    Normalize package names according to ecosystem rules.

    PyPI:
        Requests, requests, request_s
        PyPI treats '.', '_' and '-' as equivalent.

    npm:
        Comparison is case-insensitive.
        Hyphens and underscores remain distinct.
    """

    if not isinstance(name, str):
        raise TypeError("Package name must be a string.")

    if ecosystem not in {"pypi", "npm"}:
        raise ValueError("Ecosystem must be 'pypi' or 'npm'.")

    normalized = unicodedata.normalize(
        "NFKC",
        name,
    ).casefold().strip()

    if ecosystem == "pypi":
        normalized = re.sub(r"[-_.]+", "-", normalized)

    return normalized


# =========================================================
# CONFUSABLE SKELETONS
# =========================================================

def unicode_confusable_skeleton(name: str) -> str:
    """
    Map selected Unicode characters to Latin equivalents.
    """

    normalized = unicodedata.normalize(
        "NFKC",
        name,
    ).casefold()

    return "".join(
        CONFUSABLES.get(character, character)
        for character in normalized
    )


def confusable_skeleton(name: str) -> str:
    """
    Convert selected Unicode characters and digits
    into ASCII-like equivalents.
    """

    normalized = unicode_confusable_skeleton(name)

    return normalized.translate(
        str.maketrans(DIGIT_SUBSTITUTIONS)
    )


# =========================================================
# EDIT DISTANCE ALGORITHMS
# =========================================================

def levenshtein_distance(
    first: str,
    second: str,
) -> int:
    """
    Calculate minimum insertion, deletion and substitution distance.
    """

    if len(first) < len(second):
        first, second = second, first

    previous_row = list(range(len(second) + 1))

    for i, char_a in enumerate(first, start=1):

        current_row = [i]

        for j, char_b in enumerate(second, start=1):

            insertions = current_row[j - 1] + 1
            deletions = previous_row[j] + 1

            substitutions = previous_row[j - 1] + (
                char_a != char_b
            )

            current_row.append(
                min(
                    insertions,
                    deletions,
                    substitutions,
                )
            )

        previous_row = current_row

    return previous_row[-1]


def damerau_levenshtein_distance(
    first: str,
    second: str,
) -> int:
    """
    Calculate edit distance including adjacent transpositions.

    Example:
        requsets -> requests

    This implementation uses the optimal-string-alignment
    variant of Damerau-Levenshtein distance.
    """

    rows = len(first) + 1
    columns = len(second) + 1

    matrix = [
        [0] * columns
        for _ in range(rows)
    ]

    for i in range(rows):
        matrix[i][0] = i

    for j in range(columns):
        matrix[0][j] = j

    for i in range(1, rows):

        for j in range(1, columns):

            cost = (
                0
                if first[i - 1] == second[j - 1]
                else 1
            )

            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )

            # Adjacent character transposition.
            if (
                i > 1
                and j > 1
                and first[i - 1] == second[j - 2]
                and first[i - 2] == second[j - 1]
            ):
                matrix[i][j] = min(
                    matrix[i][j],
                    matrix[i - 2][j - 2] + 1,
                )

    return matrix[-1][-1]


# =========================================================
# SIMILARITY
# =========================================================

def similarity_score(
    first: str,
    second: str,
) -> float:
    """Return a similarity score between 0 and 100."""

    return round(
        SequenceMatcher(
            None,
            first,
            second,
        ).ratio() * 100,
        2,
    )


# =========================================================
# DIGIT SUBSTITUTION DETECTOR
# =========================================================

def detect_character_substitution(
    name: str,
    reference: str,
) -> bool:
    """
    Detect digit-for-letter substitutions.

    Examples:
        g00gle -> google
        p4ypal -> paypal
    """

    translated = name.translate(
        str.maketrans(DIGIT_SUBSTITUTIONS)
    )

    return (
        translated == reference
        and name.casefold() != reference.casefold()
    )


# =========================================================
# UNICODE CONFUSABLE DETECTOR
# =========================================================

def detect_unicode_confusable(
    name: str,
    reference: str,
) -> bool:
    """
    Detect Unicode characters that visually resemble
    Latin characters.
    """

    if name == reference:
        return False

    skeleton_name = unicode_confusable_skeleton(name)
    skeleton_reference = unicode_confusable_skeleton(reference)

    if skeleton_name != skeleton_reference:
        return False

    has_non_ascii = any(
        ord(character) > 127
        for character in name
    )

    return has_non_ascii


# =========================================================
# KEYBOARD-ADJACENT SUBSTITUTION
# =========================================================

def get_keyboard_neighbours(
    character: str,
) -> set[str]:
    """
    Return approximate neighbouring QWERTY keys.

    Includes horizontal and diagonal neighbours.
    """

    character = character.casefold()

    for row_index, row in enumerate(KEYBOARD_ROWS):

        if character not in row:
            continue

        position = row.index(character)
        neighbours = set()

        for other_row_index in range(
            max(0, row_index - 1),
            min(len(KEYBOARD_ROWS), row_index + 2),
        ):

            other_row = KEYBOARD_ROWS[other_row_index]

            # Adjacent rows have slightly different offsets.
            offset = 0

            if row_index == 1 and other_row_index == 2:
                offset = 0.5
            elif row_index == 2 and other_row_index == 1:
                offset = -0.5

            for other_position, other_character in enumerate(
                other_row
            ):

                if (
                    abs(
                        (other_position + offset) - position
                    ) <= 1
                    and other_character != character
                ):
                    neighbours.add(other_character)

        return neighbours

    return set()


def detect_keyboard_adjacent_substitution(
    name: str,
    reference: str,
) -> bool:
    """
    Detect exactly one keyboard-adjacent substitution.
    """

    if len(name) != len(reference):
        return False

    differences = [
        (actual, expected)
        for actual, expected in zip(name, reference)
        if actual != expected
    ]

    if len(differences) != 1:
        return False

    actual, expected = differences[0]

    return expected in get_keyboard_neighbours(actual)


# =========================================================
# REPEATED CHARACTER DETECTOR
# =========================================================

def detect_repeated_character(
    name: str,
    reference: str,
) -> bool:
    """
    Detect one extra adjacent repeated character.

    Example:
        requuests -> requests
    """

    if name == reference:
        return False

    if abs(len(name) - len(reference)) != 1:
        return False

    shorter, longer = sorted(
        [name, reference],
        key=len,
    )

    for index in range(len(longer) - 1):

        candidate = (
            longer[:index]
            + longer[index + 1:]
        )

        if candidate == shorter:
            return (
                longer[index] == longer[index + 1]
            )

    return False


# =========================================================
# MAIN PACKAGE NAME ANALYSIS
# =========================================================

def analyze_package_name(
    package_name: str,
    ecosystem: str = "pypi",
    threshold: float = DEFAULT_THRESHOLD,
    reference_packages: Sequence[str] | None = None,
) -> dict:
    """
    Analyse a package name for possible typosquatting.

    The result is heuristic evidence, not proof of malicious intent.

    Args:
        package_name: Package name to analyse.
        ecosystem: pypi or npm.
        threshold: Similarity threshold from 0 to 100.
        reference_packages: Optional custom reference list.

    Returns:
        Structured dictionary containing possible matches.
    """

    # -----------------------------------------------------
    # INPUT VALIDATION
    # -----------------------------------------------------

    if not isinstance(package_name, str):
        raise TypeError("Package name must be a string.")

    if not package_name.strip():
        raise ValueError("Package name cannot be empty.")

    if ecosystem not in {"pypi", "npm"}:
        raise ValueError("Ecosystem must be 'pypi' or 'npm'.")

    if not isinstance(threshold, (int, float)):
        raise TypeError("Threshold must be numeric.")

    if not 0 <= threshold <= 100:
        raise ValueError(
            "Threshold must be between 0 and 100."
        )

    normalized_name = normalize_package_name(
        package_name,
        ecosystem,
    )

    if not normalized_name:
        raise ValueError("Package name is invalid.")

    # -----------------------------------------------------
    # LOAD REFERENCE PACKAGES
    # -----------------------------------------------------

    references = (
        list(reference_packages)
        if reference_packages is not None
        else load_popular_packages(ecosystem)
    )

    matches = []

    # -----------------------------------------------------
    # COMPARE AGAINST EACH REFERENCE
    # -----------------------------------------------------

    for reference in references:

        if (
            not isinstance(reference, str)
            or not reference.strip()
        ):
            continue

        normalized_reference = normalize_package_name(
            reference,
            ecosystem,
        )

        # Exact normalized identity is not suspicious.
        if normalized_name == normalized_reference:
            continue

        # -------------------------------------------------
        # DISTANCE AND SIMILARITY
        # -------------------------------------------------

        distance = levenshtein_distance(
            normalized_name,
            normalized_reference,
        )

        damerau_distance = damerau_levenshtein_distance(
            normalized_name,
            normalized_reference,
        )

        score = similarity_score(
            normalized_name,
            normalized_reference,
        )

        # -------------------------------------------------
        # SHORT NAME THRESHOLD
        # -------------------------------------------------

        effective_threshold = threshold

        if len(normalized_name) <= 4:
            effective_threshold = max(
                threshold,
                85,
            )

        elif len(normalized_name) <= 6:
            effective_threshold = max(
                threshold,
                80,
            )

        # -------------------------------------------------
        # SPECIALIZED DETECTION
        # -------------------------------------------------

        digit_match = detect_character_substitution(
            normalized_name,
            normalized_reference,
        )

        unicode_match = detect_unicode_confusable(
            normalized_name,
            normalized_reference,
        )

        keyboard_match = detect_keyboard_adjacent_substitution(
            normalized_name,
            normalized_reference,
        )

        repeated_match = detect_repeated_character(
            normalized_name,
            normalized_reference,
        )

        # -------------------------------------------------
        # MATCH CLASSIFICATION
        # -------------------------------------------------

        visual_match = (
            digit_match
            or unicode_match
            or keyboard_match
        )

        edit_match = (
            damerau_distance <= 1
            or repeated_match
        )

        # Similarity alone is not sufficient.
        # This reduces false positives from legitimate
        # package extensions such as requests-html.

        max_allowed_distance = max(
            1,
            min(
                len(normalized_name),
                len(normalized_reference),
            ) // 5,
        )

        similarity_match = (
            score >= effective_threshold
            and distance <= max_allowed_distance
        )

        if not (
            visual_match
            or edit_match
            or similarity_match
        ):
            continue

        # -------------------------------------------------
        # EXPLANATION
        # -------------------------------------------------

        reasons = []

        if digit_match:
            reasons.append(
                "digit-for-letter substitution"
            )

        if unicode_match:
            reasons.append(
                "Unicode confusable characters"
            )

        if keyboard_match:
            reasons.append(
                "keyboard-adjacent substitution"
            )

        if repeated_match:
            reasons.append(
                "repeated-character lookalike"
            )

        if damerau_distance == 1 and not repeated_match:
            reasons.append(
                "one-edit or adjacent-transposition match"
            )

        if similarity_match:
            reasons.append(
                "high name similarity"
            )

        # -------------------------------------------------
        # STORE MATCH
        # -------------------------------------------------

        matches.append({

            # Main detector fields.
            "reference_package": reference,
            "normalized_reference": normalized_reference,
            "similarity": score,
            "levenshtein_distance": distance,
            "damerau_levenshtein_distance": damerau_distance,

            "digit_substitution": digit_match,
            "unicode_confusable": unicode_match,
            "keyboard_adjacent_substitution": keyboard_match,
            "repeated_character": repeated_match,
            "similarity_match": similarity_match,

            "reasons": reasons,

            # Backward-compatible fields expected by run_scan.py.
            "reason": "; ".join(reasons),
            "edit_distance": distance,
            "damerau_distance": damerau_distance,
            "character_substitution": digit_match,
        })

    # -----------------------------------------------------
    # SORT RESULTS
    # -----------------------------------------------------

    matches.sort(
        key=lambda item: (
            item["unicode_confusable"],
            item["digit_substitution"],
            item["keyboard_adjacent_substitution"],
            item["similarity"],
            -item["levenshtein_distance"],
        ),
        reverse=True,
    )

    # -----------------------------------------------------
    # FINAL RESULT
    # -----------------------------------------------------

    return {
        "package_name": package_name,
        "normalized_name": normalized_name,
        "ecosystem": ecosystem,
        "suspicious_name": bool(matches),
        "match_count": len(matches),
        "matches": matches,

        "analysis_note": (
            "Name similarity is a heuristic indicator. "
            "It does not establish malicious behaviour. "
            "Verify package ownership, publisher identity, "
            "repository and package history."
        ),
    }
