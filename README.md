# sub2api-helper

Small helper CLI for maintaining OpenAI OAuth accounts in a Docker-deployed sub2api instance.

Currently only the Docker deployment mode is implemented. The helper talks to the PostgreSQL container through `docker exec`.

ChatGPT session requests use [`zinzied/cloudscraper`](https://github.com/zinzied/cloudscraper).

## Usage

Run it on the host where sub2api is deployed:

```bash
sub2api-helper '<access_token_or_session_token>'
sub2api-helper list
sub2api-helper update
sub2api-helper update --id 6
sub2api-helper update 1,2,3
sub2api-helper update all
sub2api-helper convert '<session_token>'
```

`sub2api-helper <token>` accepts either an OpenAI access token or a ChatGPT session token. Access tokens are decoded locally and update the matching account's `access_token` and expiration time. Session tokens fetch the current ChatGPT auth session, then upsert `access_token`, the returned `session_token`, expiration time, and account metadata into sub2api's `accounts.credentials` JSON.

`sub2api-helper update` finds OpenAI OAuth accounts whose error is:

```text
Token revoked (401): Your authentication token has been invalidated. Please try signing in again.
```

It only considers rows that already have `credentials.session_token`. Use `sub2api-helper list` to show candidates. By default `update` refreshes the first match. Pass `1,2,3`, `1-3`, `all`, or `--id <account_id>` to choose accounts.

## Configuration

Defaults match the standard sub2api Docker deployment:

```bash
POSTGRES_CONTAINER=sub2api-postgres
POSTGRES_USER=sub2api
POSTGRES_DB=sub2api
GROUP_NAME=openai-default
ACCOUNT_CONCURRENCY=10
ACCOUNT_PRIORITY=1
PSQL_TIMEOUT=30
DRY_RUN=0
```

Set `DRY_RUN=1` to run the database transaction and roll it back.

## Build

For local Python usage:

```bash
uv sync
uv run sub2api-helper --help
```

For a Linux x86_64 binary:

```bash
uv sync --dev
uv run pyinstaller --clean --onedir --name sub2api-helper --collect-data cloudscraper main.py
```

The executable is written to `dist/sub2api-helper/sub2api-helper`. Keep the whole `dist/sub2api-helper` directory together when deploying.

## 友情链接

- [LINUX DO - 新的理想型社区](https://linux.do)
