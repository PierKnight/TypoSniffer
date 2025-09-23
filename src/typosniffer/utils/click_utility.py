from functools import wraps
import click
from typosniffer.utils.logger import log

# Custom Command class that logs start and end
class LoggingCommand(click.Command):
    def invoke(self, ctx: click.core.Context):
        log.info(f"Starting command: {ctx.command_path}")
        result = super().invoke(ctx)
        log.info(f"Finished command: {ctx.command_path}")
        return result

# Custom Group to use LoggingCommand automatically
class LoggingGroup(click.Group):
    def command(self, *args, **kwargs):
        kwargs.setdefault('cls', LoggingCommand)
        return super().command(*args, **kwargs)
    
# Custom Group that wraps all commands automatically
class LoggingAllGroup(click.Group):
    def add_command(self, cmd, name=None):
        # Wrap the command's callback
        original_callback = cmd.callback
        if original_callback:
            @wraps(original_callback)
            def wrapper(*args, **kwargs):
                log.info(f"Starting command: {cmd.name}")
                try:
                    result = original_callback(*args, **kwargs)
                    log.info(f"Finished command: {cmd.name}")
                    return result
                except Exception as e:
                    log.error(f"Command {cmd.name} failed: {e}")
                    raise
            cmd.callback = wrapper

        super().add_command(cmd, name=name)