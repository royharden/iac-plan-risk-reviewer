"""Default-refusal launcher: no CLI input is an approval mechanism."""
import sys

from .context import load_actual_context, run_original


def main(argv=None):
    print('REFUSED: actual root trust and actual observer are uninstalled.', file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
