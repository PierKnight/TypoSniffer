from datetime import datetime
import enum
from rich.console import Console

console = Console()

class MessageType(enum.Enum):
    INFO = 0
    WARNING = 1
    ERROR = 2

def format_msg(msg_type: MessageType, msg: str):
    if msg_type == MessageType.INFO:
        return f"[bold green]{msg}[/bold green]"
    elif msg_type == MessageType.WARNING:
        return f"[bold yellow]{msg}[/bold yellow]"
    elif msg_type == MessageType.ERROR:
        return f"[bold red]{msg}[/bold red]"
    else:
        return f"[bold]{msg}[/bold]"


def print_msg(msg_type: MessageType, *args):
    
    if type(*args) is str:
        msg = " ".join(str(a) for a in args)
        console.print(format_msg(msg_type, msg))
    else:
        console.print(*args)
    

def print_info(*args):
    print_msg(MessageType.INFO, *args)

def print_warning(*args):
    print_msg(MessageType.WARNING, *args)

def print_error(*args):
    print_msg(MessageType.ERROR, *args)

def status(msg, msg_type: MessageType = MessageType.INFO):
    return console.status(format_msg(msg_type, msg))


def pretty_dict(d, indent=0):
    lines = []
    space = "  " * indent  # 2 spaces per level
    for key, value in d.items():
        # Format datetime nicely
        if isinstance(value, datetime):
            value = value.strftime("%c")
        # Format lists
        elif isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        if isinstance(value, dict):
            # Format nested dicts recursively
            lines.append(f"{space}[bold green]{key}:[/bold green]")
            lines.append(pretty_dict(value, indent=indent+1))
        else:
            lines.append(f"{space}[bold green]{key}:[/bold green] {value}")
        
    
    return "\n".join(lines)




