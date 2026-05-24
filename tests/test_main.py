import base64
import json
import unittest
from unittest import mock

import main


def jwt(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"header.{encoded}.sig"


class HelperTests(unittest.TestCase):
    def cfg(self) -> main.DbConfig:
        return main.DbConfig(
            container="postgres",
            user="sub2api",
            db="sub2api",
            group_name="openai-default",
            concurrency=10,
            priority=1,
            dry_run=False,
            psql_timeout=30,
        )

    def sub2api_cfg(self) -> main.Sub2ApiConfig:
        return main.Sub2ApiConfig(
            enabled=True,
            base_url="http://sub2api",
            container="sub2api",
            port="8080",
            timeout=10,
            admin_api_key="admin-key",
            admin_email="",
            admin_password="",
        )

    def test_access_token_record_decodes_email_and_exp(self) -> None:
        token = jwt(
            {
                "exp": 2000000000,
                "https://api.openai.com/profile": {"email": "a@example.com"},
                "https://api.openai.com/auth": {"chatgpt_plan_type": "plus"},
            }
        )

        record = main.access_token_record(token)

        self.assertEqual(record["email"], "a@example.com")
        self.assertEqual(record["exp"], 2000000000)
        self.assertEqual(record["plan_type"], "plus")
        self.assertNotIn("session_token", record)

    def test_auto_token_uses_access_token_without_fetching_session(self) -> None:
        token = jwt({"exp": 2000000000, "email": "a@example.com"})

        with (
            mock.patch.object(main, "fetch_chatgpt_session") as fetch,
            mock.patch.object(main, "upsert_record_and_sync", return_value="ok\n") as upsert,
            mock.patch("builtins.print"),
        ):
            main.upsert_auto_token(token, self.cfg(), self.sub2api_cfg())

        fetch.assert_not_called()
        self.assertEqual(upsert.call_args.args[0]["email"], "a@example.com")
        self.assertNotIn("session_token", upsert.call_args.args[0])

    def test_auto_token_falls_back_to_session_token(self) -> None:
        access_token = jwt({"exp": 2000000000, "email": "a@example.com"})

        with (
            mock.patch.object(
                main,
                "fetch_chatgpt_session",
                return_value={"accessToken": access_token, "sessionToken": "new-st"},
            ) as fetch,
            mock.patch.object(main, "upsert_record_and_sync", return_value="ok\n") as upsert,
            mock.patch("builtins.print"),
        ):
            main.upsert_auto_token("opaque-session-token", self.cfg(), self.sub2api_cfg())

        fetch.assert_called_once_with("opaque-session-token")
        self.assertEqual(upsert.call_args.args[0]["session_token"], "new-st")

    def test_update_arg_parsing_supports_database_id(self) -> None:
        self.assertEqual(main.parse_update_args(["--id", "6"]), ("1", 6, False))
        self.assertEqual(main.parse_update_args(["--id=6", "--force-email-mismatch"]), ("1", 6, True))

    def test_email_mismatch_guard(self) -> None:
        record = {"email": "new@example.com"}
        with self.assertRaisesRegex(ValueError, "returned email"):
            main.upsert_record(record, self.cfg(), target_account_id=6, expected_email="old@example.com")

    def test_parse_account_ids_from_upsert_output(self) -> None:
        output = """ action  | id |        email        |          expires_at           | group_name
---------+----+---------------------+-------------------------------+--------------
 updated |  6 | a@example.com       | 2026-06-03 23:20:46 Asia/Shanghai | openai-default
(1 row)
"""
        self.assertEqual(main.parse_account_ids_from_upsert_output(output), [6])

    def test_upsert_record_and_sync_skips_dry_run(self) -> None:
        cfg = self.cfg()
        cfg.dry_run = True
        with (
            mock.patch.object(main, "upsert_record", return_value=" updated | 6 | a@example.com\n") as upsert,
            mock.patch.object(main, "sync_sub2api_account_state") as sync,
        ):
            output = main.upsert_record_and_sync({"email": "a@example.com"}, cfg, self.sub2api_cfg())

        self.assertIn("updated", output)
        upsert.assert_called_once()
        sync.assert_not_called()

    def test_discover_sub2api_base_url_uses_first_container_ip(self) -> None:
        cfg = self.sub2api_cfg()
        cfg.base_url = ""
        proc = mock.Mock(returncode=0, stdout="172.19.0.4\n172.20.0.4\n", stderr="")
        with mock.patch.object(main.subprocess, "run", return_value=proc) as run:
            self.assertEqual(main.discover_sub2api_base_url(cfg), "http://172.19.0.4:8080")

        self.assertIn("docker", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
