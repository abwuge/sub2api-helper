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
            mock.patch.object(main, "upsert_record", return_value="ok\n") as upsert,
            mock.patch("builtins.print"),
        ):
            main.upsert_auto_token(token, self.cfg())

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
            mock.patch.object(main, "upsert_record", return_value="ok\n") as upsert,
            mock.patch("builtins.print"),
        ):
            main.upsert_auto_token("opaque-session-token", self.cfg())

        fetch.assert_called_once_with("opaque-session-token")
        self.assertEqual(upsert.call_args.args[0]["session_token"], "new-st")

    def test_update_arg_parsing_supports_database_id(self) -> None:
        self.assertEqual(main.parse_update_args(["--id", "6"]), ("1", 6, False))
        self.assertEqual(main.parse_update_args(["--id=6", "--force-email-mismatch"]), ("1", 6, True))

    def test_email_mismatch_guard(self) -> None:
        record = {"email": "new@example.com"}
        with self.assertRaisesRegex(ValueError, "returned email"):
            main.upsert_record(record, self.cfg(), target_account_id=6, expected_email="old@example.com")


if __name__ == "__main__":
    unittest.main()
