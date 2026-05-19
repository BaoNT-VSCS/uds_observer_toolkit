from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ConfigError
from .logging_utils import ConsoleLog, RunLogger
from .runner import Runner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="udstk",
        description="Config-driven UDS observation and testcase toolkit.",
    )
    p.add_argument("-c", "--config", action="append", required=True, help="YAML config file. Repeat to overlay configs.")
    p.add_argument("--case", action="append", dest="cases", help="Run only testcase name. Repeatable.")
    p.add_argument("--dry-run", action="store_true", help="Validate config and print selected cases without sending CAN frames.")
    p.add_argument("--yes-i-am-authorized", action="store_true", help="Required for fuzzing cases unless safety.authorized=true in YAML.")
    p.add_argument("--runs-dir", default="runs", help="Base directory for timestamped JSONL/CSV run logs.")
    p.add_argument("--verbose", action="store_true", help="Show debug/raw RX details.")
    p.add_argument("--show-process", action="store_true", help="Show each UDS step.")
    p.add_argument("--show-can", action="store_true", help="Show transmitted CAN frames.")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = ConsoleLog(verbose=args.verbose, show_process=args.show_process, show_can=args.show_can)
    run_logger = RunLogger(args.runs_dir, run_name="udstk")
    try:
        runner = Runner.from_files(
            args.config,
            console=console,
            run_logger=run_logger,
            dry_run=args.dry_run,
            authorized=args.yes_i_am_authorized,
        )
        rc = runner.run(args.cases)
        console.info(f"\nlogs: {run_logger.dir}")
        return rc
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
