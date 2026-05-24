# sub2api-helper

Small helper CLI for maintaining OpenAI OAuth accounts in a Docker-deployed sub2api instance.

Currently only the Docker deployment mode is implemented. The helper talks to the PostgreSQL container through `docker exec`.

## Usage

Run it on the host where sub2api is deployed:

```bash
sub2api-helper '<session_token>'
sub2api-helper update
sub2api-helper update 1,2,3
sub2api-helper update all
sub2api-helper convert '<session_token>'
```

`sub2api-helper <session_token>` fetches the current ChatGPT auth session, then upserts `access_token`, the returned `session_token`, expiration time, and account metadata into sub2api's `accounts.credentials` JSON.

`sub2api-helper update` finds OpenAI OAuth accounts whose error is:

```text
Token revoked (401): Your authentication token has been invalidated. Please try signing in again.
```

It only considers rows that already have `credentials.session_token`. By default it updates the first match. Pass `1,2,3`, `1-3`, or `all` to update more.

## Configuration

Defaults match the standard sub2api Docker deployment:

```bash
POSTGRES_CONTAINER=sub2api-postgres
POSTGRES_USER=sub2api
POSTGRES_DB=sub2api
GROUP_NAME=openai-default
ACCOUNT_CONCURRENCY=10
ACCOUNT_PRIORITY=1
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
uv run pyinstaller --clean --onefile --name sub2api-helper --collect-data cloudscraper main.py
```

The binary is written to `dist/sub2api-helper`.
