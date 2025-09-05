import re

import click


def validate_regex(pattern, message: str = None):
    """Return a callback function that validates the argument against the given pattern."""
    def callback(ctx, param, value):
        if not re.match(pattern, value):
            raise click.BadParameter(message if message else f"'{value}' does not match pattern '{pattern}'" )
        return value
    return callback