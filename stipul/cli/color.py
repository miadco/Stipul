RESET  = "\033[0m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"

def colorize(text: str, code: str) -> str:
    import sys
    if sys.stdout.isatty():
        return f"{code}{text}{RESET}"
    return text
