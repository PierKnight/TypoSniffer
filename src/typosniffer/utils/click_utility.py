import click
from typosniffer.utils.logger import log

# Custom Command that logs start and end
class LoggingCommand(click.Command):
    def invoke(self, ctx):
        log.info(f"Starting command: {ctx.command_path}")
        # Log arguments and options
        #log.info(f"Arguments and options: {ctx.params}")

        result = super().invoke(ctx)
        log.info(f"Finished command: {ctx.command_path}")
        return result

# Custom Group to use LoggingCommand automatically
class LoggingGroup(click.Group):
    def command(self, *args, **kwargs):
        kwargs.setdefault('cls', LoggingCommand)
        return super().command(*args, **kwargs)