from typing import Required, TypedDict


# Move me to Backend later
# https://github.com/gitleaks/gitleaks?tab=readme-ov-file#configuration
class Allowlist(TypedDict, total=False):
    description: Required[str]
    paths: list[str]
    regexes: list[str]


class RulesAllowlist(TypedDict, total=False):
    description: Required[str]
    regexTarget: str
    regexes: list[str]
    paths: list[str]
    stopwords: list[str]


class RuleToml(TypedDict, total=False):
    # from GitLeeks
    id: Required[str]
    description: Required[str]
    regex: Required[str]
    keywords: list[str]
    entropy: float
    path: str
    secretGroup: int
    allowlist: RulesAllowlist
    tags: Required[list[str]]
    # from RESC
    comment: str


class GitLeaksConfigToml(TypedDict):  # Implicit total = True
    title: str
    version: str
    allowlist: Allowlist
    rules: list[RuleToml]
