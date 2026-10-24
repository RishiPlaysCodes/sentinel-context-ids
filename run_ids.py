import argparse
import json
from pathlib import Path
import pandas as pd
from sentinel.config import DATA, RESULTS, ARTIFACTS


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Context IDS research prototype"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["develop", "evaluate", "build", "benchmark"]:
        commands.add_parser(name)
    detect = commands.add_parser("detect")
    detect.add_argument("input", type=Path)
    detect.add_argument(
        "--output", type=Path, default=RESULTS / "custom_predictions.csv"
    )
    detect.add_argument(
        "--aggregate-context",
        action="store_true",
        help="Reconstruct causal windows from complete timestamped flow events",
    )
    pcap = commands.add_parser("pcap")
    pcap.add_argument("input", type=Path)
    pcap.add_argument("--output", type=Path, default=RESULTS / "pcap_predictions.csv")
    args = parser.parse_args()
    try:
        if args.command in ["develop", "evaluate", "build"]:
            from sentinel.experiments import build_development, evaluate_final

            if args.command in ["develop", "build"]:
                print(json.dumps({"validation": build_development()}, indent=2))
            if args.command in ["evaluate", "build"]:
                print(json.dumps({"evaluation": evaluate_final()}, indent=2))
        elif args.command == "benchmark":
            from sentinel.benchmark import run_benchmark

            print(run_benchmark())
        else:
            from sentinel.model import ContextDetector

            if args.input.resolve() == args.output.resolve():
                raise ValueError("Input and output paths must differ.")
            if args.command == "pcap":
                from sentinel.capture import read_capture

                frame, quality = read_capture(args.input)
                print(json.dumps(quality, indent=2))
            else:
                from sentinel.io import read_flow_csv

                frame = read_flow_csv(args.input)
                if args.aggregate_context:
                    from sentinel.temporal import add_context

                    frame = add_context(frame)
            result = ContextDetector.load(
                ARTIFACTS / "context_ensemble.joblib"
            ).predict(frame)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            result.to_csv(args.output, index=False)
            print(args.output)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(2, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
