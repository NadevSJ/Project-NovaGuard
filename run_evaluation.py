"""Project-root shim so the README's ``python run_evaluation.py`` command works."""

from evaluation.experiments.experiment_runner import ExperimentRunner, _parse_args


def main() -> None:
    args = _parse_args()
    ExperimentRunner().run_full_experiment(
        mode=args.mode,
        limit=args.limit,
        dry_run=args.dry_run,
        skip_ablation=args.skip_ablation,
    )


if __name__ == "__main__":
    main()
