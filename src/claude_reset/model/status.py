"""Final statuses of operations. The values are the strings reports and the command line have always carried,
so a status is written to JSON unchanged and compares equal to its old string."""
from enum import StrEnum

__all__ = ['Backend', 'BlockerKind', 'Browsers', 'Check', 'Collected', 'DesktopKeys', 'Diagnosis', 'Elevation',
           'Export', 'Fix', 'Identifier', 'Location', 'Measurement', 'Network', 'NextAction', 'Package', 'Progress',
           'Protection', 'ProtectionLevel', 'ProtectionState', 'Proxy', 'ProxyKind', 'Readiness', 'Reset', 'Step',
           'Uninstall']


class Protection(StrEnum):
    """How an L1 protection install, restart or removal ended."""
    INSTALLED = 'installed'
    INSTALLED_NEEDS_ATTENTION = 'installed_needs_attention'
    RESTARTED = 'restarted'
    REMOVED = 'removed'
    REMOVED_WITH_LEFTOVERS = 'removed_with_leftovers'
    NOT_INSTALLED = 'not_installed'
    BLOCKED = 'blocked'
    NEEDS_BACKEND = 'needs_backend'
    NEEDS_CONNECTION_PROFILE = 'needs_connection_profile'
    NEEDS_CONSENT = 'needs_consent'
    PROXY_CONFIRMATION_REQUIRED = 'proxy_confirmation_required'
    EXTENSION_CHOICE_REQUIRED = 'extension_choice_required'
    PENDING_ELEVATION = 'pending_elevation'
    RECONCILE_REQUIRED = 'reconcile_required'
    CONTROLLER_NOT_STOPPED = 'controller_not_stopped'
    PACKAGE_FAILED = 'package_failed'
    AUTOSTART_FAILED = 'autostart_failed'
    START_FAILED = 'start_failed'
    RELAY_NOT_OPEN = 'relay_not_open'
    EXTENSION_PROXY_FAILED = 'extension_proxy_failed'
    EXTENSION_EXCLUSION_FAILED = 'extension_exclusion_failed'
    AUTOSTART_NOT_REMOVED = 'autostart_not_removed'
    FILTERS_NOT_REMOVED = 'filters_not_removed'
    BACKEND_NOT_REMOVED = 'backend_not_removed'
    PACKAGE_NOT_REMOVED = 'package_not_removed'
    CONNECTION_PROFILE_NOT_REMOVED = 'connection_profile_not_removed'
    FAILED = 'failed'   # an unexpected error; its type and message are in the report


class Step(StrEnum):
    """How one step of a multi-step operation ended."""
    OK = 'ok'
    STOPPED = 'stopped'


class NextAction(StrEnum):
    """What the person should do after an operation stopped. The window and the command line word it themselves."""
    START_CONTROLLER_THEN_CHECK = 'start_controller_then_check'
    START_CONTROLLER_THEN_INSTALL = 'start_controller_then_install'
    INSTALL_BACKEND = 'install_backend'
    SAVE_CONNECTION_PROFILE = 'save_connection_profile'
    CHECK_CONTROLLER_STATUS = 'check_controller_status'
    CONFIRM_LIMITS = 'confirm_limits'
    REINSTALL_CONTROLLER_TO_REPLACE = 'reinstall_controller_to_replace'
    SET_EXTENSION_PROXY = 'set_extension_proxy'


class Backend(StrEnum):
    """Installing or removing the local engine task or a remote proxy profile, and the imported engine profiles."""
    FAILED = 'failed'
    IMPORTED_INACTIVE = 'imported_inactive'
    INACTIVE_INVENTORY = 'inactive_inventory'
    INSTALLED = 'installed'
    INSTALLED_NEEDS_ATTENTION = 'installed_needs_attention'
    NOT_INSTALLED = 'not_installed'
    NOT_STARTED = 'not_started'
    REMOVED = 'removed'
    REMOVED_WITH_LEFTOVERS = 'removed_with_leftovers'
    UNREADABLE_OR_INVALID = 'unreadable_or_invalid'


class Check(StrEnum):
    """One readiness check row: ok, info and warn pass; missing is created by an install step; blocked cannot be fixed by one."""
    BLOCKED = 'blocked'
    INFO = 'info'
    MISSING = 'missing'
    OK = 'ok'
    UNKNOWN = 'unknown'
    WARN = 'warn'


class Diagnosis(StrEnum):
    """Read-only diagnostics: time zone and language advice, operation history, network observation, install preflight."""
    CANDIDATE_PREFLIGHT_BLOCKED = 'candidate_preflight_blocked'
    CANDIDATE_PREFLIGHT_FAILED = 'candidate_preflight_failed'
    COMPARED = 'compared'
    OBSERVED = 'observed'
    UNAVAILABLE = 'unavailable'
    UNAVAILABLE_OR_ERROR = 'unavailable_or_error'
    UNSUPPORTED = 'unsupported'


class Elevation(StrEnum):
    """A request carried out by the elevated helper, as the requesting side sees it."""
    COMPLETED = 'completed'
    INCOMPLETE = 'incomplete'
    INSPECTION_FINISHED = 'inspection_finished'
    OBSERVED_READY = 'observed_ready'
    PENDING_ELEVATION = 'pending_elevation'
    RECONCILE_REQUIRED = 'reconcile_required'
    UNKNOWN = 'unknown'


class Export(StrEnum):
    """Encrypted exports made before a reset, and their recovery."""
    COWORK_EXPORT_RECOVERED = 'cowork_export_recovered'
    COWORK_EXPORT_VERIFIED = 'cowork_export_verified'
    CUSTOMIZATION_SOURCE_EXPORTED = 'customization_source_exported'
    ENCRYPTED_EXPORT_VERIFIED = 'encrypted_export_verified'
    ENCRYPTED_SOURCE_EXPORT_VERIFIED = 'encrypted_source_export_verified'
    FAILED_OR_PARTIAL = 'failed_or_partial'
    INCOMPLETE = 'incomplete'
    INVENTORY_COMPLETE = 'inventory_complete'
    MEMORY_EXPORTED = 'memory_exported'


class Network(StrEnum):
    """Checks and probes of the network protection, its controller, and the owner's acceptance of its limits."""
    BLOCKED_INCOMPLETE_BROKER_ISOLATION = 'blocked_incomplete_broker_isolation'
    BLOCKED_INSTALLED_ACCEPTANCE_REQUIRED = 'blocked_installed_acceptance_required'
    BROKERED_DNS_NOT_CONTAINED = 'brokered_dns_not_contained'
    CONTROLLER_NOT_STOPPED = 'controller_not_stopped'
    DIRECT_EGRESS_DENIED_PROXY_WORKING = 'direct_egress_denied_proxy_working'
    DNS_PROBE_CONTAINED = 'dns_probe_contained'
    GUARD_PREFLIGHT_FAILED = 'guard_preflight_failed'
    GUARD_PROBE_FAILED = 'guard_probe_failed'
    INSPECTION_FAILED = 'inspection_failed'
    ISOLATION_AUDIT_COMPLETED = 'isolation_audit_completed'
    L1_ACCEPTANCE_ABSENT = 'l1_acceptance_absent'
    L1_ACCEPTANCE_NOT_RECORDED = 'l1_acceptance_not_recorded'
    L1_ACCEPTANCE_PRESENT = 'l1_acceptance_present'
    L1_ACCEPTANCE_RECORDED = 'l1_acceptance_recorded'
    L1_ACCEPTANCE_REMAINS = 'l1_acceptance_remains'
    L1_ACCEPTANCE_REVOKED = 'l1_acceptance_revoked'
    LOCAL_DNS_PROBE_UNAVAILABLE = 'local_dns_probe_unavailable'
    NOT_APPLICABLE_PROGRAM_RUNS_IN_PACKAGE = 'not_applicable_program_runs_in_package'
    NOT_INSTALLED = 'not_installed'
    NOT_REQUESTED_ONLY_SCOPED_PROBES = 'not_requested_only_scoped_probes'
    PROTECTION_DEGRADED = 'protection_degraded'
    STATIC_CHECKS_PASSED = 'static_checks_passed'
    STATIC_CHECKS_PASSED_REVIEW_NEEDED = 'static_checks_passed_review_needed'
    STRICT_CLOSE_REQUESTED = 'strict_close_requested'
    STRICT_CONTROLLER_LAST_REPORT = 'strict_controller_last_report'
    STRICT_NOT_INSTALLED = 'strict_not_installed'
    STRICT_PLAN_PREPARED = 'strict_plan_prepared'
    STRICT_SCOPED_PROBE_FAILED = 'strict_scoped_probe_failed'
    STRICT_SCOPED_PROBE_PASSED = 'strict_scoped_probe_passed'
    SUPPORTED_STATIC_CONFIGURATION = 'supported_static_configuration'


class Location(StrEnum):
    """Whether a fixed file location still holds data."""
    ABSENT = 'absent'
    PRESENT = 'present'
    UNAVAILABLE = 'unavailable'


class Measurement(StrEnum):
    """Reaching a proxy, measuring the exit address and comparing it with the saved connection."""
    CANDIDATE_EXIT_VERIFIED = 'candidate_exit_verified'
    CONNECTION_PROFILE_SAVED = 'connection_profile_saved'
    EXIT_MATCHES = 'exit_matches'
    EXIT_MISMATCH = 'exit_mismatch'
    HTTP_REFUSED = 'http_refused'
    MEASURED = 'measured'
    MEASUREMENT_FAILED = 'measurement_failed'
    NOT_CONFIGURED = 'not_configured'
    NOT_REQUESTED = 'not_requested'
    NO_VERIFIED_CANDIDATE = 'no_verified_candidate'
    REACHABLE = 'reachable'
    UNREACHABLE = 'unreachable'


class Package(StrEnum):
    """Registering or removing the isolation package."""
    ALREADY_REGISTERED = 'already_registered'
    FAILED = 'failed'
    REGISTERED = 'registered'
    REMOVED = 'removed'


class Proxy(StrEnum):
    """The window's proxy and engine steps: check, save, import, install and remove."""
    BACKEND_REMOVED = 'backend_removed'
    BACKEND_REMOVE_REFUSED = 'backend_remove_refused'
    ENGINE_INSTALLED = 'engine_installed'
    ENGINE_INSTALL_FAILED = 'engine_install_failed'
    ENGINE_NEEDS_ATTENTION = 'engine_needs_attention'
    ENGINE_NOT_STARTED = 'engine_not_started'
    ENGINE_REMOTE_PROFILE_SAVED = 'engine_remote_profile_saved'
    PROXY_CHECKED = 'proxy_checked'
    PROXY_CHECK_FAILED = 'proxy_check_failed'
    PROXY_CONFIRMATION_REQUIRED = 'proxy_confirmation_required'
    PROXY_EXIT_UNAVAILABLE = 'proxy_exit_unavailable'
    PROXY_LOGIN_OR_CONNECT_REFUSED = 'proxy_login_or_connect_refused'
    PROXY_SAVED = 'proxy_saved'
    PROXY_UNREACHABLE = 'proxy_unreachable'
    VLESS_IMPORTED = 'vless_imported'
    VLESS_IMPORT_REFUSED = 'vless_import_refused'


class Reset(StrEnum):
    """A reset or wipe: its plan and coverage, journal, steps and audit, Desktop keys and browser site data."""
    BLOCKING = 'blocking'
    COMPLETED = 'completed'
    DONE = 'done'
    FAILED = 'failed'
    FAILED_OR_PARTIAL = 'failed_or_partial'
    FIXED_LOCATIONS_WIPED = 'fixed_locations_wiped'
    MANUAL_ACTION_REQUIRED = 'manual_action_required'
    NOT_COVERED = 'not_covered'
    NOT_INSPECTED = 'not_inspected'
    NOT_VERIFIED = 'not_verified'
    PARTIAL = 'partial'
    PARTIAL_COVERAGE = 'local_operations_completed_partial_coverage'
    PLANNED = 'planned'
    PREVIEW = 'preview'
    STARTED = 'started'
    SUPPORTED_DATA_REMOVED = 'supported_data_removed'
    VERIFIED = 'verified'


class Uninstall(StrEnum):
    """Removing the installed program."""
    NOT_INSTALLED = 'not_installed'
    PROTECTION_NOT_REMOVED = 'protection_not_removed'
    REMOVED = 'removed'


class Identifier(StrEnum):
    """A known local identifier compared before and after a reset."""
    CHANGED = 'changed'
    NEW_VALUE_OBSERVED_NO_OLD_BASELINE = 'new_value_observed_no_old_baseline'
    NOT_OBSERVED = 'not_observed'
    OLD_VALUE_REMOVED_NEW_VALUE_NOT_OBSERVED = 'old_value_removed_new_value_not_observed'
    UNCHANGED = 'unchanged'


class ProtectionLevel(StrEnum):
    """How much of the protection a readiness check found installed."""
    INSTALLED = 'installed'
    NOT_INSTALLED = 'not_installed'
    PARTIAL = 'partial'
    UNKNOWN = 'unknown'


class ProtectionState(StrEnum):
    """The protection as the main window shows it."""
    OFF = 'off'
    ON = 'on'
    PARTIAL = 'partial'
    PAUSED = 'paused'
    PROBLEM = 'problem'
    UNKNOWN = 'unknown'


class Readiness(StrEnum):
    """The overall answer of a readiness check."""
    BLOCKED = 'blocked'
    INSTALLED = 'installed'
    PARTIAL = 'partial'
    READY_TO_INSTALL = 'ready_to_install'
    UNKNOWN = 'unknown'


class Fix(StrEnum):
    """The one fix the main window suggests for the protection."""
    ACCEPT_EXIT = 'accept_exit'
    INSTALL = 'install'
    REENTER = 'reenter'
    RESTART = 'restart'
    RESUME = 'resume'
    RETRY = 'retry'


class ProxyKind(StrEnum):
    """The kind of proxy the protection goes through, as the window names it."""
    HTTP = 'HTTP'
    SOCKS5 = 'SOCKS5'
    VLESS = 'VLESS'


class Progress(StrEnum):
    """One step of the wizard: done, still to do, waiting for the steps before it, or unreadable."""
    DONE = 'done'
    TODO = 'todo'
    UNKNOWN = 'unknown'
    WAITING = 'waiting'


class Collected(StrEnum):
    """How much a read-only diagnostics read collected: all of it, a part, or nothing it could trust."""
    COMPLETE = 'complete'
    PARTIAL = 'partial'
    UNAVAILABLE = 'unavailable'


class BlockerKind(StrEnum):
    """Who resolves a reset blocker: the program itself, the person, or the person by a choice."""
    ASK = 'ask'
    AUTO = 'auto'
    USER = 'user'


class DesktopKeys(StrEnum):
    """What the reset did with the device keys of Claude Desktop."""
    FAILED = 'failed'
    NOT_PRESENT = 'not_present'
    NOT_SUPPORTED = 'not_supported'
    NO_KEYS = 'no_keys'
    RESET = 'reset'


class Browsers(StrEnum):
    """Signing out of claude.ai in the browsers after a reset."""
    BROWSERS_OPEN = 'browsers_open'
    CLEARED = 'cleared'
    FAILED = 'failed'
    NOT_REQUESTED = 'not_requested'
