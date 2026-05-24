import base64
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

import cloudscraper


DEFAULT_CONTAINER = "sub2api-postgres"
DEFAULT_DB_USER = "sub2api"
DEFAULT_DB_NAME = "sub2api"
DEFAULT_GROUP_NAME = "openai-default"
DEFAULT_CONCURRENCY = 10
DEFAULT_PRIORITY = 1
DEFAULT_PSQL_TIMEOUT = 30
REVOKED_ERROR = (
    "Token revoked (401): Your authentication token has been invalidated. "
    "Please try signing in again."
)


@dataclass
class DbConfig:
    container: str
    user: str
    db: str
    group_name: str
    concurrency: int
    priority: int
    dry_run: bool
    psql_timeout: int


@dataclass
class PsqlOptions:
    quiet: bool = False
    tuples_only: bool = False
    unaligned: bool = False


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}


def db_config() -> DbConfig:
    return DbConfig(
        container=os.environ.get("POSTGRES_CONTAINER", DEFAULT_CONTAINER),
        user=os.environ.get("POSTGRES_USER", DEFAULT_DB_USER),
        db=os.environ.get("POSTGRES_DB", DEFAULT_DB_NAME),
        group_name=os.environ.get("GROUP_NAME", DEFAULT_GROUP_NAME),
        concurrency=int(os.environ.get("ACCOUNT_CONCURRENCY", DEFAULT_CONCURRENCY)),
        priority=int(os.environ.get("ACCOUNT_PRIORITY", DEFAULT_PRIORITY)),
        dry_run=env_flag("DRY_RUN"),
        psql_timeout=int(os.environ.get("PSQL_TIMEOUT", DEFAULT_PSQL_TIMEOUT)),
    )


def normalize_token(token: str) -> str:
    token = token.replace("\r", "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("access token does not look like a JWT")

    payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as exc:
        raise ValueError(f"failed to decode access token payload: {exc}") from exc


def access_token_record(access_token: str) -> dict[str, Any]:
    access_token = normalize_token(access_token)
    if not access_token:
        raise ValueError("access token cannot be empty")

    claims = jwt_payload(access_token)
    profile = claims.get("https://api.openai.com/profile") or {}
    auth = claims.get("https://api.openai.com/auth") or {}
    if not isinstance(profile, dict):
        profile = {}
    if not isinstance(auth, dict):
        auth = {}

    email = profile.get("email") or claims.get("email")
    exp = claims.get("exp")
    if not email:
        raise ValueError("no email found in access token claims")
    if not isinstance(exp, int):
        raise ValueError("no numeric exp found in access token claims")

    result: dict[str, Any] = {
        "access_token": access_token,
        "access_token_sha256": hashlib.sha256(access_token.encode()).hexdigest(),
        "email": email,
        "exp": exp,
        "expires_at_utc": dt.datetime.fromtimestamp(exp, dt.UTC).isoformat(),
    }

    optional = {
        "client_id": claims.get("client_id"),
        "chatgpt_user_id": auth.get("chatgpt_user_id") or auth.get("user_id"),
        "chatgpt_account_id": auth.get("chatgpt_account_id"),
        "plan_type": auth.get("chatgpt_plan_type"),
        "organization_id": claims.get("organization_id") or auth.get("organization_id"),
    }
    for key, value in optional.items():
        if value is not None:
            result[key] = value

    return result


def token_record(data: dict[str, Any]) -> dict[str, Any]:
    access_token = normalize_token(str(data.get("accessToken") or data.get("access_token") or ""))
    session_token = str(data.get("sessionToken") or data.get("session_token") or "").strip()
    if not access_token:
        raise ValueError(f"response does not contain accessToken: {data}")
    if not session_token:
        raise ValueError(f"response does not contain sessionToken: {data}")

    result = access_token_record(access_token)
    result["session_token"] = session_token
    result["session_token_sha256"] = hashlib.sha256(session_token.encode()).hexdigest()
    id_token = data.get("idToken") or data.get("id_token")
    if id_token is not None:
        result["id_token"] = id_token
    return result


def fetch_chatgpt_session(session_token: str, max_retries: int = 3) -> dict[str, Any]:
    """Return the full ChatGPT auth session response."""
    scraper = cloudscraper.create_scraper()
    last_err: Exception | None = None
    for attempt in range(max_retries):
        if attempt > 0:
            time.sleep(2**attempt)
        try:
            resp = scraper.get(
                "https://chatgpt.com/api/auth/session",
                cookies={"__Secure-next-auth.session-token": session_token},
                timeout=15,
            )
        except Exception as exc:
            last_err = exc
            continue

        if resp.status_code != 200:
            last_err = RuntimeError(f"request failed (status {resp.status_code}): {resp.text}")
            continue

        data = resp.json()
        if not data.get("accessToken"):
            raise ValueError(f"response does not contain accessToken; token may be invalid: {data}")
        if not data.get("sessionToken"):
            raise ValueError(f"response does not contain sessionToken: {data}")

        return data

    raise RuntimeError(f"failed after {max_retries} retries: {last_err}")


def run_psql(sql: str, cfg: DbConfig, options: PsqlOptions | None = None) -> str:
    options = options or PsqlOptions()
    cmd = [
        "docker",
        "exec",
        "-i",
        cfg.container,
        "psql",
        "-U",
        cfg.user,
        "-d",
        cfg.db,
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-v",
        f"group_name={cfg.group_name}",
        "-v",
        f"account_concurrency={cfg.concurrency}",
        "-v",
        f"account_priority={cfg.priority}",
    ]
    if cfg.dry_run:
        cmd += ["-v", "dry_run=1"]
    if options.quiet:
        cmd.append("-q")
    if options.tuples_only:
        cmd.append("-t")
    if options.unaligned:
        cmd.append("-A")
    cmd += ["-f", "-"]

    try:
        proc = subprocess.run(cmd, input=sql, text=True, capture_output=True, timeout=cfg.psql_timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"psql command timed out after {cfg.psql_timeout}s") from exc

    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(message)
    return proc.stdout


def upsert_record(
    record: dict[str, Any],
    cfg: DbConfig,
    target_account_id: int | None = None,
    expected_email: str | None = None,
    force_email_mismatch: bool = False,
) -> str:
    if (
        target_account_id is not None
        and expected_email
        and record["email"].lower() != expected_email.lower()
        and not force_email_mismatch
    ):
        raise ValueError(
            f"session token returned email {record['email']!r}, "
            f"but target account id={target_account_id} is {expected_email!r}; "
            "use --force-email-mismatch to override"
        )

    sql = r"""
BEGIN;

CREATE TEMP TABLE _sub2api_st_input(payload jsonb) ON COMMIT DROP;

\copy _sub2api_st_input(payload) FROM stdin
"""
    sql += json.dumps(record, separators=(",", ":")) + "\n\\.\n"
    target_clause = (
        f"a.id = {target_account_id}"
        if target_account_id is not None
        else """(
      lower(a.name) = lower(i.email)
      OR lower(a.credentials->>'email') = lower(i.email)
      OR lower(a.extra->>'email') = lower(i.email)
    )"""
    )
    sql += r"""
WITH
input AS (
  SELECT
    payload AS p,
    payload->>'email' AS email,
    (payload->>'exp')::bigint AS exp,
    to_timestamp((payload->>'exp')::double precision) AS expires_at
  FROM _sub2api_st_input
),
model AS (
  SELECT COALESCE(
    (
      SELECT credentials->'model_mapping'
      FROM public.accounts
      WHERE platform = 'openai'
        AND type = 'oauth'
        AND deleted_at IS NULL
        AND credentials ? 'model_mapping'
      ORDER BY id DESC
      LIMIT 1
    ),
    '{}'::jsonb
  ) AS model_mapping
),
targets AS (
  SELECT a.id
  FROM public.accounts a
  CROSS JOIN input i
  WHERE a.deleted_at IS NULL
    AND a.platform = 'openai'
    AND a.type = 'oauth'
    AND TARGET_CLAUSE
),
updated AS (
  UPDATE public.accounts a
  SET
    name = i.email,
    credentials =
      a.credentials
      || jsonb_build_object(
        'access_token', i.p->>'access_token',
        'expires_at', i.exp,
        'email', i.email,
        'model_mapping', COALESCE(a.credentials->'model_mapping', m.model_mapping)
      )
      || CASE WHEN i.p ? 'session_token' THEN jsonb_build_object('session_token', i.p->>'session_token') ELSE '{}'::jsonb END
      || CASE WHEN i.p ? 'id_token' THEN jsonb_build_object('id_token', i.p->>'id_token') ELSE '{}'::jsonb END
      || CASE WHEN i.p ? 'client_id' THEN jsonb_build_object('client_id', i.p->>'client_id') ELSE '{}'::jsonb END
      || CASE WHEN i.p ? 'chatgpt_user_id' THEN jsonb_build_object('chatgpt_user_id', i.p->>'chatgpt_user_id') ELSE '{}'::jsonb END
      || CASE WHEN i.p ? 'chatgpt_account_id' THEN jsonb_build_object('chatgpt_account_id', i.p->>'chatgpt_account_id') ELSE '{}'::jsonb END
      || CASE WHEN i.p ? 'plan_type' THEN jsonb_build_object('plan_type', i.p->>'plan_type') ELSE '{}'::jsonb END
      || CASE WHEN i.p ? 'organization_id' THEN jsonb_build_object('organization_id', i.p->>'organization_id') ELSE '{}'::jsonb END,
    extra =
      a.extra
      || jsonb_build_object(
        'email', i.email,
        'access_token_sha256', i.p->>'access_token_sha256',
        'access_token_updated_at', now()
      )
      || CASE WHEN i.p ? 'session_token_sha256' THEN jsonb_build_object('session_token_sha256', i.p->>'session_token_sha256', 'session_token_updated_at', now()) ELSE '{}'::jsonb END
      || CASE WHEN NOT (a.extra ? 'privacy_mode') THEN jsonb_build_object('privacy_mode', 'training_off') ELSE '{}'::jsonb END
      || CASE WHEN NOT (a.extra ? 'openai_oauth_responses_websockets_v2_enabled') THEN jsonb_build_object('openai_oauth_responses_websockets_v2_enabled', false) ELSE '{}'::jsonb END
      || CASE WHEN NOT (a.extra ? 'openai_oauth_responses_websockets_v2_mode') THEN jsonb_build_object('openai_oauth_responses_websockets_v2_mode', 'off') ELSE '{}'::jsonb END,
    expires_at = i.expires_at,
    status = 'active',
    error_message = NULL,
    schedulable = true,
    rate_limited_at = NULL,
    rate_limit_reset_at = NULL,
    temp_unschedulable_until = NULL,
    temp_unschedulable_reason = NULL,
    updated_at = now()
  FROM input i, model m, targets t
  WHERE a.id = t.id
  RETURNING 'updated'::text AS action, a.id, a.name, a.expires_at
),
inserted AS (
  INSERT INTO public.accounts (
    name,
    platform,
    type,
    credentials,
    extra,
    concurrency,
    priority,
    status,
    schedulable,
    expires_at,
    auto_pause_on_expired,
    rate_multiplier,
    created_at,
    updated_at
  )
  SELECT
    i.email,
    'openai',
    'oauth',
    jsonb_build_object(
      'access_token', i.p->>'access_token',
      'expires_at', i.exp,
      'email', i.email,
      'model_mapping', m.model_mapping
    )
    || CASE WHEN i.p ? 'session_token' THEN jsonb_build_object('session_token', i.p->>'session_token') ELSE '{}'::jsonb END
    || CASE WHEN i.p ? 'id_token' THEN jsonb_build_object('id_token', i.p->>'id_token') ELSE '{}'::jsonb END
    || CASE WHEN i.p ? 'client_id' THEN jsonb_build_object('client_id', i.p->>'client_id') ELSE '{}'::jsonb END
    || CASE WHEN i.p ? 'chatgpt_user_id' THEN jsonb_build_object('chatgpt_user_id', i.p->>'chatgpt_user_id') ELSE '{}'::jsonb END
    || CASE WHEN i.p ? 'chatgpt_account_id' THEN jsonb_build_object('chatgpt_account_id', i.p->>'chatgpt_account_id') ELSE '{}'::jsonb END
    || CASE WHEN i.p ? 'plan_type' THEN jsonb_build_object('plan_type', i.p->>'plan_type') ELSE '{}'::jsonb END
    || CASE WHEN i.p ? 'organization_id' THEN jsonb_build_object('organization_id', i.p->>'organization_id') ELSE '{}'::jsonb END,
    jsonb_build_object(
      'email', i.email,
      'access_token_sha256', i.p->>'access_token_sha256',
      'privacy_mode', 'training_off',
      'openai_oauth_responses_websockets_v2_enabled', false,
      'openai_oauth_responses_websockets_v2_mode', 'off',
      'import_source', CASE WHEN i.p ? 'session_token' THEN 'session_token_helper' ELSE 'access_token_helper' END,
      'imported_at', now(),
      'access_token_updated_at', now()
    )
    || CASE WHEN i.p ? 'session_token_sha256' THEN jsonb_build_object('session_token_sha256', i.p->>'session_token_sha256', 'session_token_updated_at', now()) ELSE '{}'::jsonb END,
    :'account_concurrency'::integer,
    :'account_priority'::integer,
    'active',
    true,
    i.expires_at,
    true,
    1.0,
    now(),
    now()
  FROM input i, model m
  WHERE NOT EXISTS (SELECT 1 FROM targets)
  RETURNING 'inserted'::text AS action, id, name, expires_at
),
result AS (
  SELECT * FROM updated
  UNION ALL
  SELECT * FROM inserted
),
group_write AS (
  INSERT INTO public.account_groups (account_id, group_id, priority)
  SELECT r.id, g.id, :'account_priority'::integer
  FROM result r
  JOIN public.groups g ON g.name = :'group_name'
  ON CONFLICT (account_id, group_id)
  DO UPDATE SET priority = EXCLUDED.priority
  RETURNING account_id
)
SELECT
  r.action,
  r.id,
  r.name AS email,
  to_char(r.expires_at AT TIME ZONE 'Asia/Shanghai', 'YYYY-MM-DD HH24:MI:SS') || ' Asia/Shanghai' AS expires_at,
  CASE WHEN gw.account_id IS NULL THEN 'missing:' || :'group_name' ELSE :'group_name' END AS group_name
FROM result r
LEFT JOIN group_write gw ON gw.account_id = r.id
ORDER BY r.id;

\if :{?dry_run}
ROLLBACK;
\else
COMMIT;
\endif
"""
    sql = sql.replace("TARGET_CLAUSE", target_clause)
    return run_psql(sql, cfg)


def revoked_accounts(cfg: DbConfig) -> list[dict[str, Any]]:
    sql = f"""
SELECT jsonb_build_object(
  'ord', row_number() OVER (ORDER BY id),
  'id', id,
  'name', name,
  'session_token', credentials->>'session_token',
  'status', status,
  'schedulable', schedulable,
  'st_len', length(COALESCE(credentials->>'session_token', '')),
  'updated_at', updated_at
)::text
FROM public.accounts
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth'
  AND error_message = {sql_literal(REVOKED_ERROR)}
  AND credentials ? 'session_token'
  AND COALESCE(credentials->>'session_token', '') <> ''
ORDER BY id;
"""
    out = run_psql(sql, cfg, PsqlOptions(quiet=True, tuples_only=True, unaligned=True))
    accounts = []
    for line in out.splitlines():
        line = line.strip()
        if line and line not in {"BEGIN", "COMMIT"}:
            accounts.append(json.loads(line))
    return accounts


def print_accounts(accounts: list[dict[str, Any]], selected_ord: set[int] | None = None) -> None:
    if not accounts:
        print("No revoked OpenAI OAuth accounts with session_token found.")
        return

    for account in accounts:
        marker = "*" if selected_ord and account["ord"] in selected_ord else " "
        print(
            f"{marker} {account['ord']}. "
            f"id={account['id']} {account['name']} "
            f"status={account.get('status', '')} "
            f"schedulable={account.get('schedulable', '')} "
            f"st_len={account.get('st_len', '')}"
        )


def list_revoked(cfg: DbConfig) -> int:
    print_accounts(revoked_accounts(cfg))
    return 0


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def parse_selection(raw: str, total: int) -> list[int]:
    raw = raw.strip().lower()
    if raw == "all":
        return list(range(1, total + 1))
    if not raw:
        return [1]

    selected: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_raw, end_raw = part.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)
            selected.extend(range(start, end + 1))
        else:
            selected.append(int(part))

    deduped = []
    seen = set()
    for item in selected:
        if item < 1 or item > total:
            raise ValueError(f"selection {item} is out of range 1..{total}")
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def parse_update_args(args: list[str]) -> tuple[str | None, int | None, bool]:
    selection: str | None = None
    account_id: int | None = None
    force_email_mismatch = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--id":
            i += 1
            if i >= len(args):
                raise ValueError("--id requires a database account id")
            account_id = int(args[i])
        elif arg.startswith("--id="):
            account_id = int(arg.split("=", 1)[1])
        elif arg == "--force-email-mismatch":
            force_email_mismatch = True
        elif selection is None:
            selection = arg
        else:
            raise ValueError("too many arguments for update")
        i += 1

    if selection is not None and account_id is not None:
        raise ValueError("use either update selection or update --id, not both")
    return selection or "1", account_id, force_email_mismatch


def update_revoked(
    selection: str,
    cfg: DbConfig,
    account_id: int | None = None,
    force_email_mismatch: bool = False,
) -> int:
    accounts = revoked_accounts(cfg)
    if not accounts:
        print("No revoked OpenAI OAuth accounts with session_token found.")
        return 0

    if account_id is not None:
        selected = [account for account in accounts if int(account["id"]) == account_id]
        if not selected:
            print_accounts(accounts)
            raise ValueError(f"id={account_id} is not an update candidate")
        selected_ord = {int(selected[0]["ord"])}
    else:
        selected_ord = set(parse_selection(selection, len(accounts)))
        selected = [account for account in accounts if account["ord"] in selected_ord]
    print_accounts(accounts, selected_ord)

    failures = 0
    for account in selected:
        print(f"Updating {account['ord']}. id={account['id']} {account['name']} ...")
        try:
            data = fetch_chatgpt_session(account["session_token"])
            record = token_record(data)
        except Exception as exc:
            failures += 1
            print(f"ERROR id={account['id']} {account['name']}: {exc}", file=sys.stdout)
            continue

        try:
            print(
                upsert_record(
                    record,
                    cfg,
                    target_account_id=int(account["id"]),
                    expected_email=account["name"],
                    force_email_mismatch=force_email_mismatch,
                ),
                end="",
            )
        except Exception as exc:
            failures += 1
            print(f"ERROR id={account['id']} {account['name']}: {exc}", file=sys.stdout)

    return 1 if failures else 0


def print_conversion(session_token: str) -> None:
    data = fetch_chatgpt_session(session_token)
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print()
    print(f"AT={data['accessToken']}")
    print(f"ST={data.get('sessionToken', '')}")


def upsert_auto_token(token: str, cfg: DbConfig) -> None:
    try:
        record = access_token_record(token)
    except Exception as at_exc:
        try:
            data = fetch_chatgpt_session(token)
            record = token_record(data)
        except Exception as st_exc:
            raise ValueError(f"token is neither a valid access token nor a valid session token: {st_exc}") from at_exc
    print(upsert_record(record, cfg), end="")


def read_token_arg(args: list[str], label: str) -> str:
    if args:
        token = args[0]
    elif sys.stdin.isatty():
        token = input(f"{label}: ")
    else:
        token = sys.stdin.readline()
    token = token.strip()
    if not token:
        raise ValueError(f"{label} cannot be empty")
    return token


def usage() -> None:
    print(
        """Usage:
  sub2api-helper <access_token|session_token>     Upsert account from access token or session token
  sub2api-helper list                             List update candidates
  sub2api-helper update [1|1,2,3|1-3|all]         Refresh revoked accounts by candidate number
  sub2api-helper update --id <account_id>         Refresh one revoked account by database id
  sub2api-helper convert <session_token>          Only print ChatGPT session response

Environment:
  POSTGRES_CONTAINER=sub2api-postgres
  POSTGRES_USER=sub2api
  POSTGRES_DB=sub2api
  GROUP_NAME=openai-default
  ACCOUNT_CONCURRENCY=10
  ACCOUNT_PRIORITY=1
  PSQL_TIMEOUT=30
  DRY_RUN=1
"""
    )


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in {"-h", "--help", "help"}:
        usage()
        return

    cfg = db_config()
    command = args[0]
    try:
        if command == "convert":
            print_conversion(read_token_arg(args[1:], "ST"))
            return

        if command == "list":
            if len(args) > 1:
                raise ValueError("too many arguments for list")
            raise SystemExit(list_revoked(cfg))

        if command == "update":
            selection, account_id, force_email_mismatch = parse_update_args(args[1:])
            raise SystemExit(update_revoked(selection, cfg, account_id, force_email_mismatch))

        if len(args) > 1:
            raise ValueError("too many arguments")

        upsert_auto_token(read_token_arg(args, "Token"), cfg)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
