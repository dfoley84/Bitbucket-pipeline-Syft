#!/usr/bin/env python3
"""
Bitbucket Pipe: Syft & Grype Security Scan
Reads pipe variables, validates them, then delegates to pipe.sh.
"""

import os
import subprocess
import sys

from bitbucket_pipes_toolkit import Pipe

SCHEMA = {
    "SCAN_PATH": {
        "type": "string",
        "required": False,
        "default": ".",
    },
    "LANGUAGE": {
        "type": "string",
        "required": False,
        "default": "auto",
    },
    "FAIL_ON": {
        "type": "string",
        "required": False,
        "default": "critical",
    },
    "ONLY_FIXED": {
        "type": "boolean",
        "required": False,
        "default": True,
    },
    "SBOM_OUTPUT_DIR": {
        "type": "string",
        "required": False,
        "default": ".",
    },
    "DEBUG": {
        "type": "boolean",
        "required": False,
        "default": False,
    },
    "BB_TOKEN": {
        "type": "string",
        "required": False,
        "default": "",
        "no_get": True,   # mask value in logs
    },
}

VALID_LANGUAGES = {"auto", "java", "python", "go", "generic"}
VALID_FAIL_ON = {"critical", "high", "medium", "low", "none"}


class SyftGrypePipe(Pipe):
    def run(self):
        super().run()

        scan_path = self.get_variable("SCAN_PATH")
        language = self.get_variable("LANGUAGE")
        fail_on = self.get_variable("FAIL_ON")
        only_fixed = self.get_variable("ONLY_FIXED")
        sbom_output_dir = self.get_variable("SBOM_OUTPUT_DIR")
        debug = self.get_variable("DEBUG")

        bb_token = self.get_variable("BB_TOKEN")

        # Validate
        if language not in VALID_LANGUAGES:
            self.fail(
                message=f"Invalid LANGUAGE '{language}'. Must be one of: {', '.join(sorted(VALID_LANGUAGES))}"
            )

        if fail_on not in VALID_FAIL_ON:
            self.fail(
                message=f"Invalid FAIL_ON '{fail_on}'. Must be one of: {', '.join(sorted(VALID_FAIL_ON))}"
            )

        env = os.environ.copy()
        env.update(
            {
                "SCAN_PATH": scan_path,
                "LANGUAGE": language,
                "FAIL_ON": fail_on,
                "ONLY_FIXED": str(only_fixed).lower(),
                "SBOM_OUTPUT_DIR": sbom_output_dir,
                "DEBUG": str(debug).lower(),
                "BB_TOKEN": bb_token,
            }
        )

        result = subprocess.run(["/bin/bash", "/pipe.sh"], env=env)

        if result.returncode != 0:
            self.fail(
                message=f"Syft & Grype scan failed (exit code {result.returncode}). "
                "Check the output above for details."
            )

        # Post vulnerability summary as a PR comment (best-effort — never fails the pipe)
        pr_comment_result = subprocess.run(
            [sys.executable, "/pr_comment.py"],
            env=env,
        )
        if pr_comment_result.returncode != 0:
            print("WARN  | PR comment posting failed — scan results are unaffected.")

        if result.returncode == 0:
            self.success(message="Syft & Grype scan completed successfully.")


if __name__ == "__main__":
    pipe = SyftGrypePipe(pipe_metadata="/pipe.yml", schema=SCHEMA)
    pipe.run()
