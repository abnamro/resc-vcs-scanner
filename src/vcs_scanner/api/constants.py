BITBUCKET = "BITBUCKET"
AZURE_DEVOPS = "AZURE_DEVOPS"
GITHUB_PUBLIC = "GITHUB_PUBLIC"

# Rule tags with special behaviour
RULE_TAG_SCAN_AS_DIR = "ScanAsDir"

RWS_VERSION_PREFIX = "/resc/v1"
RWS_ROUTE_REPOSITORIES = "/repositories"
RWS_ROUTE_SCANS = "/scans"
RWS_ROUTE_LAST_SCAN = "/last-scan"
RWS_ROUTE_FINDINGS = "/findings"
RWS_ROUTE_RULE_PACKS = "/rule-packs"
RWS_ROUTE_VCS = "/vcs-instances"

DEFAULT_RECORDS_PER_PAGE_LIMIT = 100
MAX_RECORDS_PER_PAGE_LIMIT = 1000

BASE_SCAN = "BASE"
INCREMENTAL_SCAN = "INCREMENTAL"

# # Cache

TEMP_RULE_FILE = "/tmp/temp_resc_rule.toml"
TEMP_RULE_REPO_FILE = "/tmp/temp_resc_repo_rule.toml"
TEMP_RULE_DIR_FILE = "/tmp/temp_resc_dir_rule.toml"
