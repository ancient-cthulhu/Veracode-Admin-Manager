# Veracode Admin Manager

Manage Veracode teams, users, roles, team membership, and business units through the Identity REST API. Supports both interactive and command-line modes.

---

## How It Works

The script connects to the Veracode Identity API (`/api/authn/v2`) and performs bulk administration for:

- **Teams** - List, create, delete
- **Users** - Add/remove team membership, add/remove roles, activate, deactivate, delete
- **Business Units** - List, create, add/remove/move teams, delete empty units
- **Roles** - List available role short names (used by the role actions)

Every write run produces a timestamped CSV results log so you have an audit trail of what changed.

> **Note:** The account needs the Administrator role (user) or the Admin API role (API service account). Test with `--dry-run` and a small non-production set first.

---

## Quickstart

### Interactive mode

```bash
python veracode_admin_manager.py
```

### Create teams from a file

```bash
python veracode_admin_manager.py teams create --input teams.txt
```

### Add users to a team

```bash
python veracode_admin_manager.py users add-team --filter '*@example.com' --value "AppSec Team"
```

### Move teams between business units

```bash
python veracode_admin_manager.py bus move --source "Old BU" --target "New BU" --input teams.txt
```

### Preview without making changes

```bash
python veracode_admin_manager.py --dry-run users deactivate --filter 'contractor-*'
```

---

## Requirements

```bash
python --version  # Python 3.8+
pip install -r requirements.txt
```

Or directly:

```bash
pip install requests veracode-api-signing
```

---

## Credentials

The script never accepts credentials as command-line arguments. The Veracode signing library reads them from the environment or the standard credentials file.

### Environment variables

```bash
export VERACODE_API_KEY_ID=your_api_key_id
export VERACODE_API_KEY_SECRET=your_api_key_secret
```

### Credentials file

Create `~/.veracode/credentials` (Windows: `%USERPROFILE%\.veracode\credentials`):

```ini
[default]
veracode_api_key_id = your_api_key_id
veracode_api_key_secret = your_api_key_secret
```

If credentials were ever exposed, revoke and regenerate them before use.

---

## Command-Line Reference

### Commands

| Command | Actions |
|---------|---------|
| `teams` | `list`, `create`, `delete` |
| `users` | `list`, `add-team`, `remove-team`, `add-role`, `remove-role`, `activate`, `deactivate`, `delete` |
| `bus` | `list`, `create`, `add`, `remove`, `move`, `delete-empty` |
| `roles` | `list` |

### Flags

| Flag | Description |
|------|-------------|
| `--input`, `-i` | File path or comma-separated names, emails, or UUIDs |
| `--filter`, `-f` | Wildcard on name or email, e.g. `'Demo-*'`, `'*@example.com'` |
| `--value`, `-v` | `users`: team name/UUID (`add-team`, `remove-team`) or role short name (`add-role`, `remove-role`) |
| `--role` | `users`: only users that currently have this role |
| `--team` | `users`: only users that are members of this team (name or UUID) |
| `--active` / `--inactive` | `users`: only active or inactive users |
| `--source`, `-s` | `bus move`: source business unit name or UUID |
| `--target`, `-t` | `bus add/remove/move`: target business unit name or UUID |
| `--yes`, `-y` | Skip confirmation prompts (required for non-interactive runs) |
| `--csv` | With `list`: also export the list to CSV |
| `--dry-run` | Preview write requests without sending them |
| `--output`, `-o` | Output directory for CSV files (default: `admin_output`) |
| `--region`, `-r` | Veracode region: `commercial` (default), `european`, or `federal` |
| `--rate-limit-per-minute` | Client-side REST rate limit (default: `450`) |

Global flags (`--dry-run`, `--region`, `--output`, `--rate-limit-per-minute`) work before or after the command.

### More examples

```bash
python veracode_admin_manager.py teams list --csv
python veracode_admin_manager.py teams delete --filter 'Demo-*'
python veracode_admin_manager.py users list --filter '*@example.com' --inactive
python veracode_admin_manager.py users remove-role --filter 'temp-*' --value extcreator
python veracode_admin_manager.py users remove-team --team "Legacy Team" --value "Legacy Team" --yes
python veracode_admin_manager.py users delete --input offboarded-users.txt
python veracode_admin_manager.py bus create --input business-units.txt
python veracode_admin_manager.py bus add --target "Payments" --input "Team A,Team B"
python veracode_admin_manager.py bus delete-empty --filter '*'
python veracode_admin_manager.py roles list
```

Input files accept one entry per line or comma-separated values. Blank lines and lines starting with `#` are ignored.

---

## Safety Behavior

| Action | Protection |
|--------|------------|
| Team / BU create | Existing names are skipped |
| Team delete | Type `DELETE` to confirm |
| User delete | Type `DELETE` to confirm |
| Role removal | Type `REMOVE` to confirm |
| BU delete | Only empty units are deleted. Type `DELETE EMPTY` to confirm |
| Other writes | Preview of targets plus `[y/N]` confirmation |
| Bulk targeting (CLI) | Write actions require `--filter` or `--input`. Use `--filter '*'` to target everything on purpose |
| Your own account | `delete`, `deactivate`, `remove-role`, and `remove-team` never apply to the account running the tool |
| Role changes | Validates key dependencies: `extseclead`/`extcreator` need a scan submission role, `deletescans` needs `extseclead` or `extcreator` |
| Role names (CLI) | Checked against `/roles` before any change |
| No-op changes | Users already in the requested state are reported as `skipped` |
| Non-interactive runs | Without `--yes`, confirmations fail safe and nothing is changed |

---

## Interactive Mode Features

### Main Menu

```
MAIN MENU
----------------------------------------
  1. Teams
  2. Users
  3. Business Units
  4. Roles
  5. Toggle dry-run mode (currently OFF)
  6. Refresh cached data
----------------------------------------
  0. Exit
```

The header shows the region, the signed-in account, and a banner when dry-run mode is on.

### Submenus

| Menu | Options |
|------|---------|
| Teams | List (with details), Create, Delete, Export to CSV |
| Users | List (with details), Add to team, Remove from team, Add role, Remove role, Activate, Deactivate, Delete, Export to CSV |
| Business Units | List (with details), Create, Add teams, Remove teams, Move teams, Delete empty, Export to CSV |
| Roles | Browse, Export to CSV |

Teams, business units, and roles are picked from lists, so you never need to paste UUIDs. When removing a role or team, the user list is narrowed to current holders or members. When moving teams, the team list is narrowed to the source business unit.

### Browser Controls

| Key | Action |
|-----|--------|
| `#` | Select by number (single), view details (list), or add by number (multi-select) |
| `1,3,5` | Add multiple items by number |
| `N` / `P` | Next / Previous page |
| `A` | Add all matching items (multi-select mode) |
| `L` | Load a list from a file or comma-separated names, emails, or UUIDs |
| `R` | Review selected items and remove any |
| `D` | Done - proceed with selection |
| `X` | Clear selection |
| `C` | Clear filter |
| `text` | Filter by name, email, or ID (wildcards `*` and `?` supported) |
| `0` | Cancel / Back |

Items that cannot be selected are marked, for example `[YOU]` for your own account and `[NOT EMPTY]` for business units that still contain teams.

---

## Output

CSV files are saved to `admin_output/` by default (override with `--output`).

### File naming

| File | Pattern | When |
|------|---------|------|
| Results log | `results_{timestamp}.csv` | Every write run (including dry runs) |
| Failures/skips | `failures_{timestamp}.csv` | CLI: automatic when any failed/skipped. Interactive: on prompt |
| List export | `teams_`, `users_`, `business_units_`, `roles_{timestamp}.csv` | `--csv` or the Export menu option |

Results columns: `operation`, `target`, `status` (`success`, `dry-run`, `skipped`, `failed`), `detail`. Cell values are escaped against spreadsheet formula injection.

### Exit codes (CLI)

| Code | Meaning |
|------|---------|
| `0` | Completed with no failures |
| `1` | Invalid input, API error, or at least one operation failed |
| `130` | Interrupted with Ctrl+C |

---

## Regions

| Region | Flag | API Endpoint |
|--------|------|--------------|
| Commercial (US) | `--region commercial` | `api.veracode.com` |
| European | `--region european` | `api.veracode.eu` |
| Federal | `--region federal` | `api.veracode.us` |

---

## Rate Limiting and Retries

Veracode REST APIs are documented at 500 requests/minute per IP. The script throttles to 450/minute by default (lower it with `--rate-limit-per-minute` if you share an egress IP).

- `429` responses honor `Retry-After` and are retried
- `GET`, `PUT`, and `DELETE` are retried on timeouts, connection errors, and transient `5xx`
- `POST` (create) is never replayed after a `5xx` or timeout, so a create cannot run twice

---

## Troubleshooting

- **"Authentication failed. Check your API credentials."**
  - Verify `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET` are set correctly, or check `~/.veracode/credentials`
  - Confirm `--region` matches where your account is hosted

- **"Access denied."**
  - The account needs the Administrator role (user) or the Admin API role (API service account)

- **"Specify targets with --filter and/or --input"**
  - Write actions do not default to every record. Add a filter, an input list, or `--filter '*'`

- **"Team 'X' is ambiguous"** / **"Business unit 'X' is ambiguous"**
  - More than one record has that name. Use the UUID instead

- **"Unknown role 'X'"**
  - Run `python veracode_admin_manager.py roles list` to see valid role short names

- **"extseclead/extcreator requires at least one scan submission role"**
  - Add a scan role (for example `extsubmitanyscan`) to the user before, or instead of, removing the last one

- **"Confirmation required. Re-run with --yes"**
  - The script is running without a terminal (CI, cron). Add `--yes` once you have validated the run with `--dry-run`

- **"Rate limit exceeded"**
  - The script waits and retries automatically. For very large batches, lower `--rate-limit-per-minute`

- **"Required packages not installed"**
  - Run: `pip install -r requirements.txt`

---

## Notes

Bulk user and business unit changes use partial updates (`partial=true`) with the complete resulting roles, teams, or BU team list. API permissions and supported fields can vary by account type and region.

---

Supported platforms: Veracode Commercial · Veracode European · Veracode Federal
