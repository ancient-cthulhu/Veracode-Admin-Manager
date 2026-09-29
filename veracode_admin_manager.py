#!/usr/bin/env python3
"""Veracode Admin Manager - Manage teams, users, roles and business units via the Identity API."""

from __future__ import annotations

import argparse
import csv
import fnmatch
import logging
import os
import random
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


# Constants
REQUEST_TIMEOUT = 60
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 1.0
MAX_BACKOFF_SECONDS = 60
DEFAULT_RETRY_AFTER_SECONDS = 60
RETRYABLE_STATUS = {500, 502, 503, 504}

# Veracode REST API documented limit: 500 calls/minute per IP address.
# The Identity API is a REST API, so we throttle below that ceiling.
VERACODE_REST_LIMIT_PER_MINUTE = 500
VERACODE_REST_SAFETY_MARGIN = 0.90
VERACODE_REST_EFFECTIVE_LIMIT_PER_MINUTE = int(
    VERACODE_REST_LIMIT_PER_MINUTE * VERACODE_REST_SAFETY_MARGIN
)

API_PAGE_SIZE = 100          # Items requested per API page
PAGE_SIZE = 10               # Items shown per page in the interactive browser
PREVIEW_LIMIT = 20           # Items listed in confirmation previews
DEFAULT_OUTPUT_DIR = "admin_output"

SCAN_ROLES = {
    "extsubmitanyscan", "extsubmitstaticscan", "extsubmitdynamicanalysis",
    "extsubmitmanualscan", "extsubmitdynamicscan", "extsubmitdynamicmpscan",
}

# User actions that could lock the caller out if applied to itself.
SELF_PROTECTED_ACTIONS = {"delete", "deactivate", "remove-role", "remove-team"}

USER_ACTIONS = [
    "list", "add-team", "remove-team", "add-role", "remove-role",
    "activate", "deactivate", "delete",
]
TEAM_ACTIONS = ["list", "create", "delete"]
BU_ACTIONS = ["list", "create", "add", "remove", "move", "delete-empty"]
ROLE_ACTIONS = ["list"]


# Data model

@dataclass
class Result:
    """Outcome of a single administrative operation."""
    operation: str
    target: str
    status: str
    detail: str = ""


class ApiError(Exception):
    """Raised when a Veracode API call fails."""

    def __init__(self, status: Optional[int], message: str) -> None:
        super().__init__(f"HTTP {status}: {message}" if status else message)
        self.status = status


class TokenBucketRateLimiter:
    """Thread-safe token bucket rate limiter.

    Keeps the client below the REST API limit of 500 requests/minute per IP.
    The default configuration uses 450 requests/minute (10% safety margin).
    """

    def __init__(self, capacity: int, refill_rate_per_second: float) -> None:
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_rate_per_second = float(refill_rate_per_second)
        self.updated_at = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        """Block until one request token is available."""
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated_at
                self.updated_at = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_second)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                sleep_for = (1.0 - self.tokens) / self.refill_rate_per_second
            time.sleep(max(sleep_for, 0.01))


def parse_retry_after(value: Optional[str]) -> float:
    """Parse a Retry-After header given as seconds or as an HTTP-date."""
    if not value:
        return float(DEFAULT_RETRY_AFTER_SECONDS)
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        retry_dt = parsedate_to_datetime(value)
        if retry_dt.tzinfo is None:
            retry_dt = retry_dt.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_dt - datetime.now(timezone.utc)).total_seconds())
    except Exception:
        return float(DEFAULT_RETRY_AFTER_SECONDS)


# API client

class VeracodeAdminClient:
    """Client for the Veracode Identity REST API."""

    REGIONS: Dict[str, str] = {
        "commercial": "https://api.veracode.com",
        "european": "https://api.veracode.eu",
        "federal": "https://api.veracode.us",
    }
    API_PATH = "/api/authn/v2"

    def __init__(
        self,
        region: str = "commercial",
        rate_limit_per_minute: int = VERACODE_REST_EFFECTIVE_LIMIT_PER_MINUTE,
        dry_run: bool = False,
    ) -> None:
        if rate_limit_per_minute <= 0:
            raise ValueError("rate_limit_per_minute must be greater than zero")

        self.region = region.lower() if region.lower() in self.REGIONS else "commercial"
        self.base_url = self.REGIONS[self.region]
        self.dry_run = dry_run

        self.session = requests.Session()
        self.session.auth = RequestsAuthPluginVeracodeHMAC()
        self.session.headers.update({
            "User-Agent": "Veracode-Admin-Manager/2.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        # Retries are handled in request() so they respect the rate limiter
        # and never replay non-idempotent calls.
        adapter = HTTPAdapter(max_retries=Retry(total=0))
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.rate_limit_per_minute = rate_limit_per_minute
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=rate_limit_per_minute,
            refill_rate_per_second=rate_limit_per_minute / 60.0,
        )
        self._cache: Dict[str, List[Dict]] = {}
        self._self_user: Optional[Dict] = None

    def __enter__(self) -> "VeracodeAdminClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False

    def close(self) -> None:
        self.session.close()

    # Low level

    @staticmethod
    def _backoff(attempt: int, reason: str) -> None:
        wait = min(RETRY_BACKOFF_FACTOR * (2 ** attempt), MAX_BACKOFF_SECONDS) + random.uniform(0.1, 1.0)
        logger.warning("%s, retrying in %.1fs... (%d/%d)", reason, wait, attempt + 1, MAX_RETRIES)
        time.sleep(wait)

    @staticmethod
    def _error_message(response: requests.Response) -> str:
        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                errors = body.get("_embedded", {}).get("errors", [])
                if errors:
                    detail = errors[0].get("detail") or errors[0].get("title", "")
                else:
                    detail = body.get("message") or body.get("error") or ""
        except ValueError:
            detail = response.text[:300].strip()

        if response.status_code == 401:
            return "Authentication failed. Check your API credentials."
        if response.status_code == 403:
            return detail or (
                "Access denied. The account needs the Administrator role (user) "
                "or the Admin API role (API service account)."
            )
        if response.status_code == 404:
            return detail or "Resource not found."
        return detail or response.reason or "Request failed."

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict] = None,
        payload: Optional[Dict] = None,
    ) -> Any:
        """Send an authenticated request with throttling and safe retries.

        GET, PUT and DELETE are retried on timeouts, connection errors and
        transient 5xx. POST is only retried on 429 so a create is never replayed.
        """
        method = method.upper()
        url = path if path.startswith("http") else f"{self.base_url}{self.API_PATH}{path}"

        if self.dry_run and method != "GET":
            logger.info("   [DRY RUN] %s %s%s", method, url, f" {params}" if params else "")
            return {"dry_run": True, "method": method, "url": url, "params": params, "payload": payload}

        idempotent = method in {"GET", "PUT", "DELETE"}
        last_exception: Optional[Exception] = None

        for attempt in range(MAX_RETRIES + 1):
            self.rate_limiter.acquire()
            try:
                response = self.session.request(
                    method, url, params=params, json=payload, timeout=REQUEST_TIMEOUT
                )
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                last_exception = e
                if idempotent and attempt < MAX_RETRIES:
                    self._backoff(attempt, "Timeout" if isinstance(e, requests.exceptions.Timeout) else "Connection error")
                    continue
                raise ApiError(None, f"Request failed: {e}") from e
            except requests.exceptions.RequestException as e:
                raise ApiError(None, f"Request failed: {e}") from e

            if response.status_code == 429 and attempt < MAX_RETRIES:
                wait = parse_retry_after(response.headers.get("Retry-After")) + random.uniform(0.1, 1.0)
                logger.warning(
                    "Rate limited by Veracode. Waiting %.1f seconds before retrying... (%d/%d)",
                    wait, attempt + 1, MAX_RETRIES,
                )
                time.sleep(wait)
                continue

            if response.status_code in RETRYABLE_STATUS and idempotent and attempt < MAX_RETRIES:
                self._backoff(attempt, f"Transient server error {response.status_code}")
                continue

            if not response.ok:
                raise ApiError(response.status_code, self._error_message(response))

            if not response.text.strip():
                return {}
            try:
                return response.json()
            except ValueError:
                raise ApiError(response.status_code, f"Invalid JSON response from {path}")

        raise ApiError(None, f"Request failed after {MAX_RETRIES} retries: {last_exception}")

    @staticmethod
    def items(data: Any, key: str) -> List[Dict]:
        """Extract a list of items from a HAL or plain response."""
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return []
        return data.get("_embedded", {}).get(key, data.get(key, data.get("content", []))) or []

    def get_all(self, path: str, key: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch every page of a collection endpoint."""
        out: List[Dict] = []
        page = 0
        while True:
            page_params = dict(params or {})
            page_params.update({"page": page, "size": API_PAGE_SIZE})
            data = self.request("GET", path, params=page_params)
            rows = self.items(data, key)
            out.extend(rows)

            info = data.get("page", {}) if isinstance(data, dict) else {}
            total = info.get("total_pages", data.get("totalPages") if isinstance(data, dict) else None)
            if total is not None:
                if page + 1 >= int(total):
                    break
            elif len(rows) < API_PAGE_SIZE:
                break
            if not rows:
                break
            page += 1
        return out

    # Cached collections

    def _cached(self, key: str, loader: Callable[[], List[Dict]], refresh: bool) -> List[Dict]:
        if refresh or key not in self._cache:
            self._cache[key] = loader()
        return self._cache[key]

    def invalidate(self, *keys: str) -> None:
        """Drop cached collections so the next read hits the API."""
        for key in keys or list(self._cache):
            self._cache.pop(key, None)

    def teams(self, refresh: bool = False) -> List[Dict]:
        return self._cached("teams", lambda: self.get_all("/teams", "teams", {"all_for_org": "true"}), refresh)

    def users(self, refresh: bool = False) -> List[Dict]:
        return self._cached("users", lambda: self.get_all("/users", "users"), refresh)

    def bus(self, refresh: bool = False) -> List[Dict]:
        return self._cached("bus", lambda: self.get_all("/business_units", "business_units"), refresh)

    def roles(self, refresh: bool = False) -> List[Dict]:
        return self._cached("roles", lambda: self.get_all("/roles", "roles"), refresh)

    def get_user(self, uid: str) -> Dict:
        return self.request("GET", f"/users/{uid}")

    def get_team(self, tid: str) -> Dict:
        return self.request("GET", f"/teams/{tid}")

    def get_bu(self, bid: str) -> Dict:
        return self.request("GET", f"/business_units/{bid}")

    def whoami(self) -> Dict:
        """Return the user or API account that owns the credentials."""
        if self._self_user is None:
            self._self_user = self.request("GET", "/users/self")
        return self._self_user

    def whoami_id(self) -> str:
        try:
            return str(val(self.whoami(), "user_id", "id"))
        except ApiError:
            return ""


# Data helpers

def val(obj: Any, *names: str, default: Any = "") -> Any:
    """Return the first non-null field found in obj."""
    if not isinstance(obj, dict):
        return default
    for name in names:
        if obj.get(name) is not None:
            return obj[name]
    return default


def row_id(row: Dict) -> str:
    return str(val(row, "team_id", "user_id", "bu_id", "role_id", "id"))


def row_name(row: Dict) -> str:
    return str(val(row, "team_name", "user_name", "bu_name", "role_name", "name", "email_address", default="Unknown"))


def join_names(items: Optional[Iterable[Dict]], *keys: str) -> str:
    return ", ".join(str(val(x, *keys)) for x in (items or []))


def is_wildcard(text: str) -> bool:
    return any(ch in text for ch in "*?[")


def read_lines(path_or_text: str) -> List[str]:
    """Read names or IDs from a file path, or from comma/newline separated text."""
    if not path_or_text:
        return []
    text = path_or_text
    try:
        p = Path(path_or_text).expanduser()
        if p.is_file():
            text = p.read_text(encoding="utf-8-sig")
    except (OSError, ValueError):
        pass
    seen: Set[str] = set()
    out: List[str] = []
    for raw in text.replace(",", "\n").splitlines():
        x = raw.strip()
        if x and not x.startswith("#") and x.casefold() not in seen:
            seen.add(x.casefold())
            out.append(x)
    return out


def row_keys(row: Dict) -> Set[str]:
    """All values a user could type to identify a row (ID, name, email)."""
    keys = {row_id(row).casefold(), row_name(row).casefold()}
    email = str(val(row, "email_address"))
    if email:
        keys.add(email.casefold())
    keys.discard("")
    return keys


def match_tokens(rows: List[Dict], tokens: Iterable[str]) -> Tuple[List[Dict], List[str]]:
    """Match exact IDs, names or emails. Returns (matched rows, tokens not found)."""
    index: Dict[str, List[Dict]] = {}
    for r in rows:
        for k in row_keys(r):
            index.setdefault(k, []).append(r)
    matched: List[Dict] = []
    seen: Set[int] = set()
    missing: List[str] = []
    for token in tokens:
        hits = index.get(token.casefold(), [])
        if not hits:
            missing.append(token)
        for h in hits:
            if id(h) not in seen:
                seen.add(id(h))
                matched.append(h)
    return matched, missing


def wildcard_match(row: Dict, pattern: str) -> bool:
    pattern = pattern.casefold()
    return any(fnmatch.fnmatch(k, pattern) for k in (row_name(row).casefold(), str(val(row, "email_address")).casefold()) if k)


def select(
    rows: List[Dict],
    *,
    ids: Iterable[str] = (),
    pasted: Iterable[str] = (),
    wildcard: str = "",
    role: str = "",
    team: str = "",
    active: Optional[bool] = None,
) -> List[Dict]:
    """Filter rows by IDs, pasted names/emails, wildcard, role, team and active state."""
    tokens = [*ids, *pasted]
    if tokens or wildcard:
        matched, _ = match_tokens(rows, tokens)
        matched_ids = {id(r) for r in matched}
        rows = [r for r in rows if id(r) in matched_ids or (wildcard and wildcard_match(r, wildcard))]
    out = []
    for r in rows:
        if role and role.casefold() not in {str(val(x, "role_name", "name")).casefold() for x in r.get("roles", []) or []}:
            continue
        if team and team.casefold() not in {
            str(v).casefold() for x in r.get("teams", []) or [] for v in (val(x, "team_name"), val(x, "team_id"))
        }:
            continue
        if active is not None and bool(r.get("active")) != active:
            continue
        out.append(r)
    return out


def resolve_one(rows: List[Dict], token: str, label: str) -> Dict:
    """Resolve a single row by exact ID or case-insensitive name."""
    matched, _ = match_tokens(rows, [token])
    if not matched:
        raise ValueError(f"{label} '{token}' not found.")
    if len(matched) > 1:
        raise ValueError(f"{label} '{token}' is ambiguous ({len(matched)} matches). Use the UUID instead.")
    return matched[0]


def resolve_many(rows: List[Dict], tokens: List[str], label: str) -> List[Dict]:
    matched, missing = match_tokens(rows, tokens)
    if missing:
        raise ValueError(f"{label}(s) not found: {', '.join(missing)}")
    return matched


def validate_roles(roles: Iterable[str]) -> List[str]:
    """Check key Veracode role dependencies."""
    roles = set(roles)
    errors = []
    if ("extseclead" in roles or "extcreator" in roles) and not roles & SCAN_ROLES:
        errors.append("extseclead/extcreator requires at least one scan submission role")
    if "deletescans" in roles and not roles & {"extseclead", "extcreator"}:
        errors.append("deletescans requires extseclead or extcreator")
    return errors


def ok_status(c: VeracodeAdminClient) -> str:
    return "dry-run" if c.dry_run else "success"


def progress(i: int, total: int, text: str) -> None:
    if total > 1:
        logger.info("   [%d/%d] %s", i, total, text)


# Operations

def teams_create(c: VeracodeAdminClient, names: List[str]) -> List[Result]:
    existing = {row_name(x).casefold() for x in c.teams()}
    results = []
    for i, name in enumerate(names, 1):
        progress(i, len(names), name)
        if name.casefold() in existing:
            results.append(Result("team-create", name, "skipped", "already exists"))
            continue
        try:
            c.request("POST", "/teams", payload={"team_name": name})
            results.append(Result("team-create", name, ok_status(c)))
            existing.add(name.casefold())
        except Exception as e:
            results.append(Result("team-create", name, "failed", str(e)))
    c.invalidate("teams")
    return results


def teams_delete(c: VeracodeAdminClient, rows: List[Dict]) -> List[Result]:
    results = []
    for i, r in enumerate(rows, 1):
        name, tid = row_name(r), row_id(r)
        progress(i, len(rows), name)
        try:
            c.request("DELETE", f"/teams/{tid}")
            results.append(Result("team-delete", name, ok_status(c)))
        except Exception as e:
            results.append(Result("team-delete", name, "failed", str(e)))
    c.invalidate("teams", "bus", "users")
    return results


def users_modify(
    c: VeracodeAdminClient,
    rows: List[Dict],
    action: str,
    value: Optional[str] = None,
    value_label: str = "",
) -> List[Result]:
    """Apply one action to many users.

    Teams and roles are sent as the complete resulting list with partial=true.
    """
    me = c.whoami_id() if action in SELF_PROTECTED_ACTIONS else ""
    op = f"user-{action}"
    label = value_label or value or ""
    results = []

    for i, summary in enumerate(rows, 1):
        uid = str(val(summary, "user_id", "id"))
        name = str(val(summary, "user_name", "email_address", default=uid))
        progress(i, len(rows), name)
        try:
            if me and uid == me:
                results.append(Result(op, name, "skipped", "refusing to modify the account running this tool"))
                continue

            if action == "delete":
                c.request("DELETE", f"/users/{uid}")
                results.append(Result(op, name, ok_status(c)))
                continue

            user = c.get_user(uid)
            payload: Dict[str, Any] = {}

            if action in {"activate", "deactivate"}:
                want = action == "activate"
                if bool(user.get("active")) == want:
                    results.append(Result(op, name, "skipped", f"already {'active' if want else 'inactive'}"))
                    continue
                payload["active"] = want

            elif action in {"add-team", "remove-team"}:
                teams = {str(val(x, "team_id")): {"team_id": val(x, "team_id")} for x in user.get("teams", []) or []}
                if action == "add-team":
                    if value in teams:
                        results.append(Result(op, name, "skipped", f"already a member of {label}"))
                        continue
                    teams[value] = {"team_id": value}
                else:
                    if value not in teams:
                        results.append(Result(op, name, "skipped", f"not a member of {label}"))
                        continue
                    teams.pop(value)
                payload["teams"] = list(teams.values())

            elif action in {"add-role", "remove-role"}:
                roles = {str(val(x, "role_name")): {"role_name": val(x, "role_name")} for x in user.get("roles", []) or []}
                if action == "add-role":
                    if value in roles:
                        results.append(Result(op, name, "skipped", f"already has {value}"))
                        continue
                    roles[value] = {"role_name": value}
                else:
                    if value not in roles:
                        results.append(Result(op, name, "skipped", f"does not have {value}"))
                        continue
                    roles.pop(value)
                errors = validate_roles(roles)
                if errors:
                    raise ValueError("; ".join(errors))
                payload["roles"] = list(roles.values())

            else:
                raise ValueError(f"Unknown user action: {action}")

            c.request("PUT", f"/users/{uid}", params={"partial": "true"}, payload=payload)
            results.append(Result(op, name, ok_status(c), label))
        except Exception as e:
            results.append(Result(op, name, "failed", str(e)))

    c.invalidate("users", "teams")
    return results


def bu_create(c: VeracodeAdminClient, names: List[str]) -> List[Result]:
    existing = {row_name(x).casefold() for x in c.bus()}
    results = []
    for i, name in enumerate(names, 1):
        progress(i, len(names), name)
        if name.casefold() in existing:
            results.append(Result("bu-create", name, "skipped", "already exists"))
            continue
        try:
            c.request("POST", "/business_units", payload={"bu_name": name})
            results.append(Result("bu-create", name, ok_status(c)))
            existing.add(name.casefold())
        except Exception as e:
            results.append(Result("bu-create", name, "failed", str(e)))
    c.invalidate("bus")
    return results


def bu_assign(
    c: VeracodeAdminClient,
    bu_id: str,
    team_ids: List[str],
    remove: bool = False,
    bu_label: str = "",
) -> List[Result]:
    """Add or remove teams on a business unit."""
    op = "bu-remove-teams" if remove else "bu-add-teams"
    label = bu_label or bu_id
    try:
        bu = c.get_bu(bu_id)
        current = {str(val(x, "team_id")): {"team_id": val(x, "team_id")} for x in bu.get("teams", []) or []}
        changed, unchanged = [], []
        for tid in team_ids:
            if remove:
                (changed if current.pop(tid, None) is not None else unchanged).append(tid)
            elif tid in current:
                unchanged.append(tid)
            else:
                current[tid] = {"team_id": tid}
                changed.append(tid)
        if not changed:
            return [Result(op, label, "skipped", "no changes needed")]
        c.request("PUT", f"/business_units/{bu_id}", params={"partial": "true"}, payload={"teams": list(current.values())})
        detail = f"{len(changed)} team(s)"
        if unchanged:
            detail += f", {len(unchanged)} already {'absent' if remove else 'present'}"
        return [Result(op, label, ok_status(c), detail)]
    except Exception as e:
        return [Result(op, label, "failed", str(e))]
    finally:
        c.invalidate("bus", "teams")


def bu_move(
    c: VeracodeAdminClient,
    source: str,
    target: str,
    team_ids: List[str],
    source_label: str = "",
    target_label: str = "",
) -> List[Result]:
    """Move teams from one business unit to another."""
    removed = bu_assign(c, source, team_ids, True, source_label)
    if removed[0].status == "failed":
        return removed + [Result("bu-add-teams", target_label or target, "skipped", "source removal failed")]
    added = bu_assign(c, target, team_ids, False, target_label)
    if added[0].status == "failed" and removed[0].status == "success":
        added[0].detail += " | teams were removed from source; re-add them or retry the move"
    return removed + added


def bu_delete_empty(c: VeracodeAdminClient, rows: List[Dict]) -> List[Result]:
    results = []
    for i, r in enumerate(rows, 1):
        bid, name = str(val(r, "bu_id", "id")), str(val(r, "bu_name", "name"))
        progress(i, len(rows), name)
        try:
            full = c.get_bu(bid)
            if full.get("teams"):
                results.append(Result("bu-delete", name, "skipped", f"not empty ({len(full['teams'])} team(s))"))
                continue
            c.request("DELETE", f"/business_units/{bid}")
            results.append(Result("bu-delete", name, ok_status(c)))
        except Exception as e:
            results.append(Result("bu-delete", name, "failed", str(e)))
    c.invalidate("bus")
    return results


# Output

def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def write_csv(path: Path, fieldnames: List[str], rows: Iterable[Dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    base, n = path, 1
    while path.exists():  # Never overwrite an earlier log from the same second
        path = base.with_name(f"{base.stem}_{n}{base.suffix}")
        n += 1
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: csv_safe(r.get(k, "")) for k in fieldnames})
    return path


def write_results_csv(results: List[Result], output_dir: str, prefix: str) -> Path:
    return write_csv(
        Path(output_dir) / f"{prefix}_{timestamp()}.csv",
        ["operation", "target", "status", "detail"],
        (asdict(r) for r in results),
    )


LIST_COLUMNS: Dict[str, List[Tuple[str, Callable[[Dict], Any]]]] = {
    "team": [
        ("team_name", lambda r: val(r, "team_name")),
        ("team_id", lambda r: val(r, "team_id")),
        ("business_unit", lambda r: val(r.get("business_unit") or {}, "bu_name")),
    ],
    "user": [
        ("user_name", lambda r: val(r, "user_name")),
        ("email_address", lambda r: val(r, "email_address")),
        ("first_name", lambda r: val(r, "first_name")),
        ("last_name", lambda r: val(r, "last_name")),
        ("active", lambda r: r.get("active", "")),
        ("roles", lambda r: join_names(r.get("roles"), "role_name", "name")),
        ("teams", lambda r: join_names(r.get("teams"), "team_name", "team_id")),
        ("user_id", lambda r: val(r, "user_id", "id")),
    ],
    "business unit": [
        ("bu_name", lambda r: val(r, "bu_name", "name")),
        ("bu_id", lambda r: val(r, "bu_id", "id")),
        ("teams", lambda r: join_names(r.get("teams"), "team_name", "team_id")),
    ],
    "role": [
        ("role_name", lambda r: val(r, "role_name")),
        ("role_description", lambda r: val(r, "role_description", "description")),
        ("scan_type", lambda r: "yes" if is_scan_role(r) else ""),
    ],
}


def export_list(kind: str, rows: List[Dict], output_dir: str) -> Path:
    cols = LIST_COLUMNS[kind]
    path = Path(output_dir) / f"{kind.replace(' ', '_')}s_{timestamp()}.csv"
    return write_csv(path, [c for c, _ in cols], ({c: fn(r) for c, fn in cols} for r in rows))


def truncate(text: Any, width: int) -> str:
    s = str(text)
    return s if len(s) <= width else s[: max(0, width - 3)] + "..."


def print_table(headers: List[str], rows: List[List[Any]], max_width: int = 40) -> None:
    widths = [len(h) for h in headers]
    cells = [[truncate(c, max_width) for c in row] for row in rows]
    for row in cells:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))
    line = "  ".join(h.upper().ljust(widths[i]) for i, h in enumerate(headers))
    print(f"  {line}")
    print("  " + "-" * len(line))
    for row in cells:
        print("  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(row)))


def show_list(kind: str, rows: List[Dict]) -> None:
    cols = LIST_COLUMNS[kind]
    print(f"\n{kind.upper()}S ({len(rows)} total)")
    print("-" * 60)
    if not rows:
        print("  No items to display.")
        return
    print_table([c for c, _ in cols], [[fn(r) for _, fn in cols] for r in rows])


def summarize(results: List[Result]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def print_results(results: List[Result]) -> None:
    print(f"\n{'=' * 60}")
    print("  RESULTS")
    print("=" * 60)
    if not results:
        print("  Nothing to do.")
        return
    print_table(["operation", "target", "status", "detail"],
                [[r.operation, r.target, r.status.upper(), r.detail] for r in results], max_width=60)
    counts = summarize(results)
    order = ["success", "dry-run", "skipped", "failed"]
    parts = [f"{counts[k]} {k}" for k in order if counts.get(k)]
    print(f"\n  Summary: {', '.join(parts)}")


def is_scan_role(role: Dict) -> bool:
    flag = role.get("is_scan_type")
    return bool(flag) if flag is not None else str(val(role, "role_name")) in SCAN_ROLES


def credentials_present() -> bool:
    return bool(os.environ.get("VERACODE_API_KEY_ID")) or os.path.exists(
        os.path.expanduser(os.path.join("~", ".veracode", "credentials"))
    )


# UI Helper Functions

def clear_screen() -> None:
    """Clear the terminal screen."""
    if os.name == "nt":
        os.system("")  # Enables ANSI escape handling on Windows 10+
    print("\033[2J\033[H", end="", flush=True)


def print_error(msg: str) -> None:
    print(f"\n{'!' * 60}")
    print(f"  ERROR: {msg}")
    print("!" * 60)


def print_warning(msg: str) -> None:
    print(f"\n{'*' * 60}")
    print(f"  WARNING: {msg}")
    print("*" * 60)


def print_success(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print("=" * 60)


def print_section(title: str) -> None:
    print(f"\n{title.upper()}")
    print("-" * 40)


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        print("\n\nInput closed. Exiting.")
        sys.exit(0)


def pause() -> None:
    ask("\nPress Enter to continue...")


def confirm(prompt: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = ask(f"{prompt} {suffix}: ").lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def confirm_typed(word: str) -> bool:
    return ask(f"Type {word} to continue: ") == word


# Interactive Browser

@dataclass
class BrowserState:
    """State for the interactive browser."""
    items: List[Dict]
    filtered_items: List[Dict] = field(default_factory=list)
    selected: List[Dict] = field(default_factory=list)
    selected_ids: Set[str] = field(default_factory=set)
    filter_str: str = ""
    page: int = 0

    def __post_init__(self) -> None:
        if not self.filtered_items:
            self.filtered_items = self.items.copy()


class ItemBrowser:
    """Interactive browser for selecting items with filtering and pagination.

    Modes:
      single  - pick one item
      multi   - build a selection (allow_multi=True)
      view    - browse and open item details (view_fn given)
    """

    def __init__(
        self,
        items: List[Dict],
        item_type: str,
        name_fn: Callable[[Dict], str] = row_name,
        id_fn: Callable[[Dict], str] = row_id,
        subtitle_fn: Optional[Callable[[Dict], str]] = None,
        allow_multi: bool = False,
        blocked_fn: Optional[Callable[[Dict], bool]] = None,
        blocked_label: str = "BLOCKED",
        blocked_reason: str = "",
        view_fn: Optional[Callable[[Dict], None]] = None,
    ) -> None:
        self.items = items
        self.item_type = item_type
        self.name_fn = name_fn
        self.id_fn = id_fn
        self.subtitle_fn = subtitle_fn or (lambda _: "")
        self.allow_multi = allow_multi
        self.blocked_fn = blocked_fn or (lambda _: False)
        self.blocked_label = blocked_label
        self.blocked_reason = blocked_reason
        self.view_fn = view_fn
        self.state = BrowserState(items=items)

    @property
    def total_pages(self) -> int:
        return max(1, (len(self.state.filtered_items) + PAGE_SIZE - 1) // PAGE_SIZE)

    @property
    def display_items(self) -> List[Dict]:
        start = self.state.page * PAGE_SIZE
        return self.state.filtered_items[start:start + PAGE_SIZE]

    @property
    def blocked_count(self) -> int:
        return sum(1 for item in self.state.filtered_items if self.blocked_fn(item))

    def display(self) -> None:
        s = self.state
        print(f"\n{self.item_type.upper()}S", end="")
        if s.filter_str:
            print(f" matching '{s.filter_str}'", end="")
        print(f" ({len(s.filtered_items)} total)")

        if self.blocked_count:
            print("-" * 55)
            print(f"  NOTE: {self.blocked_count} item(s) marked [{self.blocked_label}] cannot be selected.")
            if self.blocked_reason:
                print(f"  {self.blocked_reason}")

        if self.allow_multi and s.selected:
            print(f"Selected: {len(s.selected)} item(s)")
        print("-" * 55)

        if not self.display_items:
            print("  No items to display.")
        else:
            for i, item in enumerate(self.display_items, s.page * PAGE_SIZE + 1):
                subtitle = self.subtitle_fn(item)
                suffix = f"  ({subtitle})" if subtitle else ""
                if self.blocked_fn(item):
                    marker = f" [{self.blocked_label}]"
                else:
                    marker = " [*]" if self.id_fn(item) in s.selected_ids else ""
                print(f"  {i:3d}. {self.name_fn(item)}{suffix}{marker}")

        if self.total_pages > 1:
            nav = []
            if s.page > 0:
                nav.append("[P]rev")
            if s.page < self.total_pages - 1:
                nav.append("[N]ext")
            print(f"\n  Page {s.page + 1}/{self.total_pages}  {' / '.join(nav)}")

        print()
        if self.allow_multi:
            print("  [#] Add by number (1 or 1,3,5)   [R] Review selected")
            print("  [A] Add all matching             [D] Done - proceed")
            print("  [L] Load list (file or names)    [X] Clear selection")
            print("  [text] Filter (wildcards * ? ok)" + ("   [C] Clear filter" if s.filter_str else ""))
        else:
            verb = "View details" if self.view_fn else "Select"
            print(f"  [#] {verb} by number    [text] Filter (wildcards * ? ok)")
            if s.filter_str:
                print("  [C] Clear filter")
        print("  [0] " + ("Back" if self.view_fn else "Cancel"))

    def matches(self, item: Dict, text: str) -> bool:
        haystacks = [self.name_fn(item).casefold(), self.subtitle_fn(item).casefold(), self.id_fn(item).casefold()]
        if is_wildcard(text):
            return any(fnmatch.fnmatch(h, text) for h in haystacks if h)
        return any(text in h for h in haystacks)

    def apply_filter(self, text: str) -> None:
        needle = text.casefold()
        filtered = [item for item in self.items if self.matches(item, needle)]
        if not filtered:
            print(f"  No matches for '{text}'")
            return
        self.state.filter_str = text
        self.state.filtered_items = filtered
        self.state.page = 0

    def clear_filter(self) -> None:
        self.state.filter_str = ""
        self.state.filtered_items = self.items.copy()
        self.state.page = 0

    def _add(self, item: Dict, announce: bool = True) -> bool:
        if self.blocked_fn(item):
            if announce:
                print(f"  BLOCKED: '{self.name_fn(item)}' is marked [{self.blocked_label}].")
            return False
        item_id = self.id_fn(item)
        if item_id in self.state.selected_ids:
            if announce:
                print(f"  Already selected: {self.name_fn(item)}")
            return False
        self.state.selected.append(item)
        self.state.selected_ids.add(item_id)
        if announce:
            print(f"  + {self.name_fn(item)}")
        return True

    def add_items(self, indices: List[int]) -> None:
        for idx in indices:
            if 1 <= idx <= len(self.state.filtered_items):
                self._add(self.state.filtered_items[idx - 1])
            else:
                print(f"  Invalid: {idx}")
        if indices:
            print(f"  Total selected: {len(self.state.selected)}")

    def add_all_filtered(self) -> None:
        added = sum(1 for item in self.state.filtered_items if self._add(item, announce=False))
        blocked = self.blocked_count
        print(f"  Added {added} item(s). Total: {len(self.state.selected)}" if added else "  All eligible items already selected.")
        if blocked:
            print(f"  Skipped {blocked} [{self.blocked_label}] item(s).")

    def load_list(self) -> None:
        source = ask("  File path or comma-separated names/emails/IDs: ")
        tokens = read_lines(source)
        if not tokens:
            print("  Nothing to load.")
            return
        matched, missing = match_tokens(self.items, tokens)
        added = sum(1 for item in matched if self._add(item, announce=False))
        print(f"  Matched {len(matched)} of {len(tokens)}; added {added}. Total: {len(self.state.selected)}")
        if missing:
            print(f"  Not found ({len(missing)}): {', '.join(missing[:10])}{' ...' if len(missing) > 10 else ''}")

    def review_selected(self) -> None:
        if not self.state.selected:
            print("  No items selected.")
            return
        review_page = 0
        while self.state.selected:
            total_pages = max(1, (len(self.state.selected) + PAGE_SIZE - 1) // PAGE_SIZE)
            start = review_page * PAGE_SIZE
            end = min(start + PAGE_SIZE, len(self.state.selected))

            print(f"\n=== SELECTED {self.item_type.upper()}S ({len(self.state.selected)} total) ===")
            print("-" * 55)
            for i, item in enumerate(self.state.selected[start:end], start + 1):
                print(f"  {i:3d}. {self.name_fn(item)}")
            if total_pages > 1:
                nav = []
                if review_page > 0:
                    nav.append("[P]rev")
                if review_page < total_pages - 1:
                    nav.append("[N]ext")
                print(f"\n  Page {review_page + 1}/{total_pages}  {' / '.join(nav)}")

            print("\n  [#] Remove (1 or 1,3,5)  [Enter] Back to browse")
            choice = ask("\n> ")
            if choice == "":
                break
            if choice.upper() == "N" and review_page < total_pages - 1:
                review_page += 1
                continue
            if choice.upper() == "P" and review_page > 0:
                review_page -= 1
                continue
            to_remove = sorted(
                {int(x) - 1 for x in choice.replace(" ", ",").split(",") if x.strip().isdigit()},
                reverse=True,
            )
            if not to_remove:
                print("  Invalid input.")
                continue
            for idx in to_remove:
                if 0 <= idx < len(self.state.selected):
                    removed = self.state.selected.pop(idx)
                    self.state.selected_ids.discard(self.id_fn(removed))
                    print(f"  Removed: {self.name_fn(removed)}")
            if self.state.selected:
                print(f"  {len(self.state.selected)} item(s) remaining")
                review_page = min(review_page, (len(self.state.selected) - 1) // PAGE_SIZE)

    def run(self) -> Optional[List[Dict]]:
        if not self.items:
            print(f"No {self.item_type}s found.")
            return None

        while True:
            self.display()
            choice = ask("\n> ")
            if not choice:
                continue
            cmd = choice.upper()

            if choice == "0":
                if self.allow_multi and self.state.selected:
                    if not confirm(f"Discard {len(self.state.selected)} selected?"):
                        continue
                return None

            if cmd == "N" and self.state.page < self.total_pages - 1:
                self.state.page += 1
                continue
            if cmd == "P" and self.state.page > 0:
                self.state.page -= 1
                continue
            if cmd == "C" and self.state.filter_str:
                self.clear_filter()
                continue

            if self.allow_multi:
                if cmd == "X":
                    self.state.selected.clear()
                    self.state.selected_ids.clear()
                    print("  Selection cleared.")
                    continue
                if cmd == "D":
                    if self.state.selected:
                        return self.state.selected
                    print("  Nothing selected yet.")
                    continue
                if cmd == "A":
                    self.add_all_filtered()
                    continue
                if cmd == "R":
                    self.review_selected()
                    continue
                if cmd == "L":
                    self.load_list()
                    continue

            parts = [x for x in choice.replace(" ", ",").split(",") if x]
            if parts and all(x.isdigit() for x in parts):
                nums = [int(x) for x in parts]
                if self.allow_multi:
                    self.add_items(nums)
                    continue
                num = nums[0]
                if not 1 <= num <= len(self.state.filtered_items):
                    print("  Invalid selection.")
                    continue
                item = self.state.filtered_items[num - 1]
                if self.view_fn:
                    self.view_fn(item)
                    continue
                if self.blocked_fn(item):
                    print(f"\n  BLOCKED: '{self.name_fn(item)}' is marked [{self.blocked_label}].")
                    if self.blocked_reason:
                        print(f"  {self.blocked_reason}")
                    pause()
                    continue
                return [item]

            self.apply_filter(choice)


# Per-type browser settings

def user_subtitle(r: Dict) -> str:
    parts = [str(val(r, "email_address"))]
    if r.get("active") is False:
        parts.append("INACTIVE")
    return " | ".join(p for p in parts if p)


def team_subtitle(r: Dict) -> str:
    return str(val(r.get("business_unit") or {}, "bu_name"))


def bu_subtitle(r: Dict) -> str:
    return f"{len(r['teams'])} team(s)" if isinstance(r.get("teams"), list) else ""


def role_subtitle(r: Dict) -> str:
    desc = str(val(r, "role_description", "description"))
    return ("scan type | " if is_scan_role(r) else "") + desc


SUBTITLES = {"user": user_subtitle, "team": team_subtitle, "business unit": bu_subtitle, "role": role_subtitle}


def browse(items: List[Dict], kind: str, **kwargs: Any) -> Optional[List[Dict]]:
    return ItemBrowser(items, kind, subtitle_fn=SUBTITLES.get(kind), **kwargs).run()


# Detail views

def print_fields(pairs: List[Tuple[str, Any]]) -> None:
    width = max(len(k) for k, _ in pairs)
    for k, v in pairs:
        if v not in ("", None, []):
            print(f"  {k.ljust(width)} : {v}")


def view_user(c: VeracodeAdminClient, row: Dict) -> None:
    try:
        u = c.get_user(str(val(row, "user_id", "id")))
    except ApiError as e:
        print_error(str(e))
        return pause()
    print_section(f"User: {val(u, 'user_name')}")
    print_fields([
        ("User ID", val(u, "user_id")),
        ("Email", val(u, "email_address")),
        ("Name", f"{val(u, 'first_name')} {val(u, 'last_name')}".strip()),
        ("Active", u.get("active")),
        ("Login enabled", u.get("login_enabled")),
        ("SAML user", u.get("saml_user")),
        ("Roles", join_names(u.get("roles"), "role_name")),
        ("Teams", join_names(u.get("teams"), "team_name", "team_id")),
    ])
    pause()


def view_team(c: VeracodeAdminClient, row: Dict) -> None:
    try:
        t = c.get_team(row_id(row))
    except ApiError as e:
        print_error(str(e))
        return pause()
    members = t.get("users") or []
    print_section(f"Team: {val(t, 'team_name')}")
    print_fields([
        ("Team ID", val(t, "team_id")),
        ("Business unit", val(t.get("business_unit") or {}, "bu_name")),
        ("Members", len(members) if isinstance(members, list) else ""),
    ])
    for m in members[:PREVIEW_LIMIT]:
        print(f"    - {val(m, 'user_name', 'email_address')}")
    if len(members) > PREVIEW_LIMIT:
        print(f"    ... and {len(members) - PREVIEW_LIMIT} more")
    pause()


def view_bu(c: VeracodeAdminClient, row: Dict) -> None:
    try:
        b = c.get_bu(str(val(row, "bu_id", "id")))
    except ApiError as e:
        print_error(str(e))
        return pause()
    teams = b.get("teams") or []
    print_section(f"Business unit: {val(b, 'bu_name', 'name')}")
    print_fields([("BU ID", val(b, "bu_id", "id")), ("Teams", len(teams))])
    for t in teams:
        print(f"    - {val(t, 'team_name', 'team_id')}")
    pause()


def view_role(_: VeracodeAdminClient, row: Dict) -> None:
    print_section(f"Role: {val(row, 'role_name')}")
    print_fields([
        ("Description", val(row, "role_description", "description")),
        ("Role ID", val(row, "role_id")),
        ("Scan type", "yes" if is_scan_role(row) else "no"),
        ("API role", row.get("is_api")),
    ])
    pause()


# Interactive flows

class Session:
    """Interactive session state."""

    def __init__(self, client: VeracodeAdminClient, output_dir: str) -> None:
        self.c = client
        self.output_dir = output_dir
        self.identity = ""

    def fetch(self, label: str, loader: Callable[[], List[Dict]]) -> Optional[List[Dict]]:
        print(f"Fetching {label}...")
        try:
            return loader()
        except ApiError as e:
            print_error(str(e))
            pause()
            return None

    def finish(self, results: List[Result]) -> None:
        print_results(results)
        if results:
            path = write_results_csv(results, self.output_dir, "results")
            print(f"\n  Full results log: {path}")
            bad = [r for r in results if r.status in {"failed", "skipped"}]
            if bad and confirm("Export failures/skips to a separate CSV?", default=True):
                print(f"  Saved: {write_results_csv(bad, self.output_dir, 'failures')}")
        pause()

    def preview(self, items: List[Dict], title: str, name_fn: Callable[[Dict], str] = row_name) -> None:
        print(f"\n{title} ({len(items)} item(s))")
        print("-" * 55)
        for it in items[:PREVIEW_LIMIT]:
            print(f"  - {name_fn(it)}")
        if len(items) > PREVIEW_LIMIT:
            print(f"  ... and {len(items) - PREVIEW_LIMIT} more")
        print("-" * 55)
        if self.c.dry_run:
            print("  DRY RUN: no changes will be sent to Veracode.")

    def cancelled(self, msg: str = "Operation cancelled.") -> None:
        print(f"\n{msg}")
        pause()

    def export(self, kind: str, rows: List[Dict]) -> None:
        path = export_list(kind, rows, self.output_dir)
        print_success(f"Exported {len(rows)} {kind}(s): {path}")
        pause()


def print_header(s: Session) -> None:
    print("=" * 60)
    print("       VERACODE ADMIN MANAGER")
    print("=" * 60)
    print(f"  Region: {s.c.region}  ({s.c.base_url})")
    if s.identity:
        print(f"  Signed in as: {s.identity}")
    if s.c.dry_run:
        print("  MODE: DRY RUN (write requests are previewed, not sent)")
    print()


def print_menu(title: str, options: List[str], back_label: str = "Back") -> None:
    print(f"\n{title}")
    print("-" * 40)
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    print("-" * 40)
    print(f"  0. {back_label}")
    print()


def menu_choice(s: Session, title: str, options: List[str]) -> int:
    """Show a submenu and return the chosen option number (0 = back)."""
    while True:
        clear_screen()
        print_header(s)
        print_menu(title, options)
        choice = ask("Enter choice: ")
        if choice.isdigit() and 0 <= int(choice) <= len(options):
            return int(choice)
        print_error(f"Invalid choice. Please enter 0-{len(options)}.")
        pause()


# Teams

def teams_menu(s: Session) -> None:
    c = s.c
    options = ["List teams", "Create teams", "Delete teams", "Export teams to CSV"]
    while True:
        choice = menu_choice(s, "TEAMS", options)
        if choice == 0:
            return
        print_section(options[choice - 1])

        if choice == 1:
            teams = s.fetch("teams", c.teams)
            if teams is not None:
                browse(teams, "team", view_fn=lambda r: view_team(c, r))

        elif choice == 2:
            names = read_lines(ask("File path or comma-separated team names: "))
            if not names:
                s.cancelled("No team names provided.")
                continue
            if s.fetch("teams", c.teams) is None:
                continue
            s.preview([{"team_name": n} for n in names], "Teams to create")
            if not confirm("Create these teams?"):
                s.cancelled()
                continue
            s.finish(teams_create(c, names))

        elif choice == 3:
            teams = s.fetch("teams", c.teams)
            if teams is None:
                continue
            selected = browse(teams, "team", allow_multi=True)
            if not selected:
                s.cancelled("No teams selected.")
                continue
            s.preview(selected, "Teams to DELETE")
            if not confirm_typed("DELETE"):
                s.cancelled()
                continue
            s.finish(teams_delete(c, selected))

        elif choice == 4:
            teams = s.fetch("teams", c.teams)
            if teams is not None:
                s.export("team", teams)


# Users

USER_MENU = [
    ("List users", "list"),
    ("Add users to a team", "add-team"),
    ("Remove users from a team", "remove-team"),
    ("Add a role to users", "add-role"),
    ("Remove a role from users", "remove-role"),
    ("Activate users", "activate"),
    ("Deactivate users", "deactivate"),
    ("Delete users", "delete"),
    ("Export users to CSV", "export"),
]


def pick_team(s: Session, prompt: str) -> Optional[Dict]:
    teams = s.fetch("teams", s.c.teams)
    if not teams:
        return None
    print(f"\n{prompt}")
    picked = browse(teams, "team")
    return picked[0] if picked else None


def pick_role(s: Session, prompt: str) -> Optional[str]:
    print("Fetching roles...")
    try:
        roles = s.c.roles()
    except ApiError as e:
        print_warning(f"Could not load roles ({e}). Enter the role short name manually.")
        name = ask("Role short name (e.g. extcreator): ")
        return name or None
    print(f"\n{prompt}")
    picked = browse(roles, "role")
    return str(val(picked[0], "role_name")) if picked else None


def users_menu(s: Session) -> None:
    c = s.c
    labels = [label for label, _ in USER_MENU]
    while True:
        choice = menu_choice(s, "USERS", labels)
        if choice == 0:
            return
        label, action = USER_MENU[choice - 1]
        print_section(label)

        users = s.fetch("users", c.users)
        if users is None:
            continue

        if action == "list":
            browse(users, "user", view_fn=lambda r: view_user(c, r))
            continue
        if action == "export":
            s.export("user", users)
            continue

        value: Optional[str] = None
        value_label = ""
        candidates = users

        if action in {"add-team", "remove-team"}:
            team = pick_team(s, "Select the team:")
            if not team:
                s.cancelled("No team selected.")
                continue
            value, value_label = row_id(team), row_name(team)
            if action == "remove-team" and any("teams" in u for u in users):
                members = select(users, team=value) or select(users, team=value_label)
                if members:
                    candidates = members
        elif action in {"add-role", "remove-role"}:
            value = pick_role(s, "Select the role:")
            if not value:
                s.cancelled("No role selected.")
                continue
            value_label = value
            if action == "remove-role" and any("roles" in u for u in users):
                holders = select(users, role=value)
                if holders:
                    candidates = holders

        me = c.whoami_id() if action in SELF_PROTECTED_ACTIONS else ""
        selected = browse(
            candidates,
            "user",
            name_fn=lambda r: str(val(r, "user_name", "email_address")),
            allow_multi=True,
            blocked_fn=(lambda r: str(val(r, "user_id", "id")) == me) if me else None,
            blocked_label="YOU",
            blocked_reason="The account running this tool is protected from this action.",
        )
        if not selected:
            s.cancelled("No users selected.")
            continue

        target = f" -> {value_label}" if value_label else ""
        s.preview(selected, f"Users to {action.upper()}{target}", lambda r: f"{val(r, 'user_name')}  {val(r, 'email_address')}")

        if action == "delete":
            ok = confirm_typed("DELETE")
        elif action == "remove-role":
            ok = confirm_typed("REMOVE")
        else:
            ok = confirm("Apply these changes?")
        if not ok:
            s.cancelled()
            continue
        s.finish(users_modify(c, selected, action, value, value_label))


# Business units

def pick_bu(s: Session, prompt: str, exclude_id: str = "") -> Optional[Dict]:
    bus = s.fetch("business units", s.c.bus)
    if not bus:
        return None
    bus = [b for b in bus if str(val(b, "bu_id", "id")) != exclude_id]
    print(f"\n{prompt}")
    picked = browse(bus, "business unit", id_fn=lambda r: str(val(r, "bu_id", "id")))
    return picked[0] if picked else None


def bu_menu(s: Session) -> None:
    c = s.c
    options = [
        "List business units",
        "Create business units",
        "Add teams to a business unit",
        "Remove teams from a business unit",
        "Move teams between business units",
        "Delete empty business units",
        "Export business units to CSV",
    ]
    bu_id = lambda r: str(val(r, "bu_id", "id"))  # noqa: E731

    while True:
        choice = menu_choice(s, "BUSINESS UNITS", options)
        if choice == 0:
            return
        print_section(options[choice - 1])

        if choice == 1:
            bus = s.fetch("business units", c.bus)
            if bus is not None:
                browse(bus, "business unit", id_fn=bu_id, view_fn=lambda r: view_bu(c, r))

        elif choice == 2:
            names = read_lines(ask("File path or comma-separated business unit names: "))
            if not names:
                s.cancelled("No names provided.")
                continue
            if s.fetch("business units", c.bus) is None:
                continue
            s.preview([{"bu_name": n} for n in names], "Business units to create")
            if not confirm("Create these business units?"):
                s.cancelled()
                continue
            s.finish(bu_create(c, names))

        elif choice in (3, 4, 5):
            source = None
            if choice == 5:
                source = pick_bu(s, "Select the SOURCE business unit:")
                if not source:
                    s.cancelled("No source selected.")
                    continue
            target = pick_bu(
                s,
                "Select the TARGET business unit:" if choice != 4 else "Select the business unit:",
                exclude_id=bu_id(source) if source else "",
            )
            if not target:
                s.cancelled("No business unit selected.")
                continue

            teams = s.fetch("teams", c.teams)
            if teams is None:
                continue
            pool = teams
            anchor = source if choice == 5 else target if choice == 4 else None
            if anchor is not None:
                try:
                    in_bu = {str(val(t, "team_id")) for t in c.get_bu(bu_id(anchor)).get("teams", []) or []}
                    narrowed = [t for t in teams if row_id(t) in in_bu]
                    if narrowed:
                        pool = narrowed
                except ApiError:
                    pass
            selected = browse(pool, "team", allow_multi=True)
            if not selected:
                s.cancelled("No teams selected.")
                continue
            tids = [row_id(t) for t in selected]

            if choice == 5:
                title = f"Teams to MOVE: {row_name(source)} -> {row_name(target)}"
            elif choice == 4:
                title = f"Teams to REMOVE from {row_name(target)}"
            else:
                title = f"Teams to ADD to {row_name(target)}"
            s.preview(selected, title)
            if not confirm("Apply assignment changes?"):
                s.cancelled()
                continue

            if choice == 5:
                s.finish(bu_move(c, bu_id(source), bu_id(target), tids, row_name(source), row_name(target)))
            else:
                s.finish(bu_assign(c, bu_id(target), tids, remove=choice == 4, bu_label=row_name(target)))

        elif choice == 6:
            bus = s.fetch("business units", c.bus)
            if bus is None:
                continue
            selected = browse(
                bus, "business unit",
                id_fn=bu_id,
                allow_multi=True,
                blocked_fn=lambda r: bool(r.get("teams")),
                blocked_label="NOT EMPTY",
                blocked_reason="Only empty business units can be deleted. Move their teams first.",
            )
            if not selected:
                s.cancelled("No business units selected.")
                continue
            s.preview(selected, "Business units to DELETE (only if empty)")
            if not confirm_typed("DELETE EMPTY"):
                s.cancelled()
                continue
            s.finish(bu_delete_empty(c, selected))

        elif choice == 7:
            bus = s.fetch("business units", c.bus)
            if bus is not None:
                s.export("business unit", bus)


# Roles

def roles_menu(s: Session) -> None:
    roles = s.fetch("roles", s.c.roles)
    if roles is None:
        return
    choice = ask("[1] Browse roles  [2] Export roles to CSV  [0] Back: ")
    if choice == "1":
        browse(roles, "role", view_fn=lambda r: view_role(s.c, r))
    elif choice == "2":
        s.export("role", roles)


def interactive_mode(client: VeracodeAdminClient, output_dir: str) -> None:
    """Run the interactive menu mode."""
    s = Session(client, output_dir)
    print("Connecting to Veracode...")
    try:
        me = client.whoami()
        s.identity = str(val(me, "user_name", "email_address"))
    except ApiError as e:
        print_error(str(e))
        if e.status in (401, 403):
            sys.exit(1)

    menu = [
        ("Teams", teams_menu),
        ("Users", users_menu),
        ("Business Units", bu_menu),
        ("Roles", roles_menu),
    ]
    while True:
        clear_screen()
        print_header(s)
        options = [label for label, _ in menu]
        options.append(f"Toggle dry-run mode (currently {'ON' if client.dry_run else 'OFF'})")
        options.append("Refresh cached data")
        print_menu("MAIN MENU", options, back_label="Exit")
        choice = ask("Enter choice: ")

        try:
            if choice == "0":
                print("\nGoodbye!")
                return
            if choice.isdigit() and 1 <= int(choice) <= len(menu):
                menu[int(choice) - 1][1](s)
            elif choice == str(len(menu) + 1):
                client.dry_run = not client.dry_run
            elif choice == str(len(menu) + 2):
                client.invalidate()
                print_success("Cache cleared. Data will be reloaded on next use.")
                pause()
            else:
                print_error(f"Invalid choice. Please enter 0-{len(options)}.")
                pause()
        except KeyboardInterrupt:
            print("\n\nCancelled. Returning to main menu.")
            pause()
        except ApiError as e:
            print_error(str(e))
            pause()


# Command-line mode

def cli_confirm(args: argparse.Namespace, prompt: str, typed_word: Optional[str] = None) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty():
        logger.error("Confirmation required. Re-run with --yes for non-interactive use.")
        return False
    return confirm_typed(typed_word) if typed_word else confirm(prompt)


def cli_preview(rows: List[Dict], title: str, dry_run: bool) -> None:
    logger.info("\n%s (%d item(s))", title, len(rows))
    logger.info("-" * 55)
    for r in rows[:PREVIEW_LIMIT]:
        logger.info("  - %s", row_name(r))
    if len(rows) > PREVIEW_LIMIT:
        logger.info("  ... and %d more", len(rows) - PREVIEW_LIMIT)
    logger.info("-" * 55)
    if dry_run:
        logger.info("  DRY RUN: no changes will be sent to Veracode.")


def cli_select(rows: List[Dict], args: argparse.Namespace, require: bool) -> List[Dict]:
    """Select rows from --input and/or --filter, then apply attribute filters."""
    tokens = read_lines(args.input) if getattr(args, "input", None) else []
    pattern = getattr(args, "filter", None)
    role = getattr(args, "role", "") or ""
    team = getattr(args, "team", "") or ""
    active = getattr(args, "active", None)

    if require and not tokens and pattern is None and not (role or team or active is not None):
        raise ValueError("Specify targets with --filter and/or --input (use --filter '*' to target everything).")

    if tokens:
        _, missing = match_tokens(rows, tokens)
        if missing:
            logger.warning("Not found (%d): %s", len(missing), ", ".join(missing))
    return select(rows, pasted=tokens, wildcard=pattern or ("" if tokens else "*"), role=role, team=team, active=active)


def cli_teams(c: VeracodeAdminClient, args: argparse.Namespace) -> Optional[List[Result]]:
    if args.action == "list":
        rows = cli_select(c.teams(), args, require=False)
        show_list("team", rows)
        if args.csv:
            logger.info("\nSaved: %s", export_list("team", rows, args.output))
        return None
    if args.action == "create":
        names = read_lines(args.input or "")
        if not names:
            raise ValueError("teams create requires --input (file or comma-separated names).")
        return teams_create(c, names)
    rows = cli_select(c.teams(), args, require=True)
    cli_preview(rows, "Teams to DELETE", c.dry_run)
    if not rows:
        return []
    return teams_delete(c, rows) if cli_confirm(args, "", "DELETE") else []


def cli_users(c: VeracodeAdminClient, args: argparse.Namespace) -> Optional[List[Result]]:
    if args.action == "list":
        rows = cli_select(c.users(), args, require=False)
        show_list("user", rows)
        if args.csv:
            logger.info("\nSaved: %s", export_list("user", rows, args.output))
        return None

    value, value_label = args.value, ""
    if args.action in {"add-team", "remove-team"}:
        if not value:
            raise ValueError(f"users {args.action} requires --value (team name or UUID).")
        team = resolve_one(c.teams(), value, "Team")
        value, value_label = row_id(team), row_name(team)
    elif args.action in {"add-role", "remove-role"}:
        if not value:
            raise ValueError(f"users {args.action} requires --value (role short name).")
        try:
            known = {str(val(r, "role_name")) for r in c.roles()}
            if known and value not in known:
                raise ValueError(f"Unknown role '{value}'. Run 'roles list' to see valid role names.")
        except ApiError:
            logger.warning("Could not verify role name against /roles; continuing.")

    rows = cli_select(c.users(), args, require=True)
    target = f" -> {value_label or value}" if value else ""
    cli_preview(rows, f"Users to {args.action.upper()}{target}", c.dry_run)
    if not rows:
        return []
    typed = {"delete": "DELETE", "remove-role": "REMOVE"}.get(args.action)
    if not cli_confirm(args, "Apply changes?", typed):
        return []
    return users_modify(c, rows, args.action, value, value_label)


def cli_bus(c: VeracodeAdminClient, args: argparse.Namespace) -> Optional[List[Result]]:
    if args.action == "list":
        rows = cli_select(c.bus(), args, require=False)
        show_list("business unit", rows)
        if args.csv:
            logger.info("\nSaved: %s", export_list("business unit", rows, args.output))
        return None
    if args.action == "create":
        names = read_lines(args.input or "")
        if not names:
            raise ValueError("bus create requires --input (file or comma-separated names).")
        return bu_create(c, names)
    if args.action == "delete-empty":
        rows = cli_select(c.bus(), args, require=True)
        cli_preview(rows, "Business units to DELETE (only if empty)", c.dry_run)
        if not rows:
            return []
        return bu_delete_empty(c, rows) if cli_confirm(args, "", "DELETE EMPTY") else []

    # add / remove / move
    if not args.target:
        raise ValueError(f"bus {args.action} requires --target (business unit name or UUID).")
    tokens = read_lines(args.input or "")
    if not tokens:
        raise ValueError(f"bus {args.action} requires --input (team names or UUIDs).")
    bus = c.bus()
    target = resolve_one(bus, args.target, "Business unit")
    teams = resolve_many(c.teams(), tokens, "Team")
    tids = [row_id(t) for t in teams]

    if args.action == "move":
        if not args.source:
            raise ValueError("bus move requires --source (business unit name or UUID).")
        source = resolve_one(bus, args.source, "Business unit")
        cli_preview(teams, f"Teams to MOVE: {row_name(source)} -> {row_name(target)}", c.dry_run)
        if not cli_confirm(args, "Apply assignment changes?"):
            return []
        return bu_move(c, row_id(source), row_id(target), tids, row_name(source), row_name(target))

    remove = args.action == "remove"
    cli_preview(teams, f"Teams to {'REMOVE from' if remove else 'ADD to'} {row_name(target)}", c.dry_run)
    if not cli_confirm(args, "Apply assignment changes?"):
        return []
    return bu_assign(c, row_id(target), tids, remove, row_name(target))


def cli_roles(c: VeracodeAdminClient, args: argparse.Namespace) -> Optional[List[Result]]:
    rows = cli_select(c.roles(), args, require=False)
    show_list("role", rows)
    if args.csv:
        logger.info("\nSaved: %s", export_list("role", rows, args.output))
    return None


def command_line_mode(args: argparse.Namespace) -> None:
    """Run in command-line (non-interactive) mode."""
    handlers = {"teams": cli_teams, "users": cli_users, "bus": cli_bus, "roles": cli_roles}
    with VeracodeAdminClient(args.region, args.rate_limit_per_minute, args.dry_run) as client:
        try:
            results = handlers[args.command](client, args)
        except (ApiError, ValueError) as e:
            logger.error("Error: %s", e)
            sys.exit(1)

    if results is None:
        return
    print_results(results)
    if not results:
        sys.exit(0)
    logger.info("\nResults log: %s", write_results_csv(results, args.output, "results"))
    bad = [r for r in results if r.status in {"failed", "skipped"}]
    if bad:
        logger.info("Failures/skips: %s", write_results_csv(bad, args.output, "failures"))
    sys.exit(1 if any(r.status == "failed" for r in results) else 0)


GLOBAL_DEFAULTS = {
    "dry_run": False,
    "region": "commercial",
    "output": DEFAULT_OUTPUT_DIR,
    "rate_limit_per_minute": VERACODE_REST_EFFECTIVE_LIMIT_PER_MINUTE,
}


def build_parser() -> argparse.ArgumentParser:
    # Global options are accepted before or after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("Global Options")
    g.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS,
                   help="Preview write requests without sending them")
    g.add_argument("--region", "-r", choices=list(VeracodeAdminClient.REGIONS), default=argparse.SUPPRESS,
                   help="Veracode region (default: commercial)")
    g.add_argument("--output", "-o", default=argparse.SUPPRESS,
                   help=f"Output directory for CSV files (default: {DEFAULT_OUTPUT_DIR})")
    g.add_argument("--rate-limit-per-minute", type=int, default=argparse.SUPPRESS,
                   help=f"Client-side REST rate limit (default: {VERACODE_REST_EFFECTIVE_LIMIT_PER_MINUTE}). "
                        "Veracode REST documented limit is 500/minute/IP.")

    parser = argparse.ArgumentParser(
        description="Veracode Admin Manager - Identity API administration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
        epilog="""
Examples:
  Interactive mode:        python veracode_admin_manager.py
  List teams:              python veracode_admin_manager.py teams list
  Create teams:            python veracode_admin_manager.py teams create --input teams.txt
  Add users to a team:     python veracode_admin_manager.py users add-team --filter '*@example.com' --value "AppSec Team"
  Move teams between BUs:  python veracode_admin_manager.py bus move --source "Old BU" --target "New BU" --input teams.txt
  Preview only:            python veracode_admin_manager.py --dry-run teams create --input teams.txt

Rate limiting:
  Veracode REST APIs are documented at 500 requests/minute per IP.
  This tool defaults to 450 requests/minute as a safety margin.
        """,
    )
    sub = parser.add_subparsers(dest="command", metavar="{teams,users,bus,roles}")

    def add(kind: str, actions: List[str], help_text: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(kind, parents=[common], help=help_text, description=help_text)
        sp.add_argument("action", choices=actions)
        t = sp.add_argument_group("Target Options")
        t.add_argument("--input", "-i", help="File path or comma-separated names/emails/UUIDs")
        t.add_argument("--filter", "-f", help="Wildcard on name or email, e.g. 'Demo-*' or '*@example.com'")
        o = sp.add_argument_group("Additional Options")
        o.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")
        o.add_argument("--csv", action="store_true", help="With 'list': also export results to CSV")
        return sp

    add("teams", TEAM_ACTIONS, "Manage teams")
    users = add("users", USER_ACTIONS, "Manage users, team membership and roles")
    users.add_argument("--value", "-v", help="Team name/UUID (add-team/remove-team) or role short name (add-role/remove-role)")
    users.add_argument("--role", help="Only users that currently have this role")
    users.add_argument("--team", help="Only users that are members of this team (name or UUID)")
    state = users.add_mutually_exclusive_group()
    state.add_argument("--active", dest="active", action="store_const", const=True, default=None, help="Only active users")
    state.add_argument("--inactive", dest="active", action="store_const", const=False, help="Only inactive users")
    bus = add("bus", BU_ACTIONS, "Manage business units")
    bus.add_argument("--source", "-s", help="Source business unit name or UUID (move)")
    bus.add_argument("--target", "-t", help="Target business unit name or UUID (add/remove/move)")
    add("roles", ROLE_ACTIONS, "List available roles")
    return parser


def main() -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()
    for key, default in GLOBAL_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, default)

    if not credentials_present():
        logger.warning("Warning: Veracode API credentials not found.")
        logger.warning("   Set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET environment variables")
        logger.warning("   Or create ~/.veracode/credentials file\n")

    try:
        if args.command:
            command_line_mode(args)
        else:
            with VeracodeAdminClient(args.region, args.rate_limit_per_minute, args.dry_run) as client:
                interactive_mode(client, args.output)
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
