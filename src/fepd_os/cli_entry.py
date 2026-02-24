import sys
import os
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

from .shell import FEPDShellEngine


def main(argv=None):
    argv = argv or sys.argv[1:]
    ws = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    engine = FEPDShellEngine(ws)
    session = PromptSession()
    completer = WordCompleter(["ls", "cd", "pwd", "tree", "find", "cases", "create_case", "use", "users", "exit_user", "stat", "cat", "hash", "hexdump", "strings", "score", "explain", "timeline", "search", "help", "quit", "exit"], ignore_case=True)
    print("FEPD Terminal (read-only). Type 'create_case <name>' to initialize a case.")
    while True:
        try:
            prompt = engine._prompt()
            line = session.prompt(prompt, completer=completer)
            if not line:
                continue
            if line.strip() in ('quit', 'exit'):
                break
            out = engine.dispatch(line)
            if out:
                print(out)
        except KeyboardInterrupt:
            continue
        except EOFError:
            break


if __name__ == '__main__':
    main()
