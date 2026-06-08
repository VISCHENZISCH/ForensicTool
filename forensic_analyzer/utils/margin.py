import sys


class MarginStdin:
    """
    Wrapper pour sys.stdin qui réinitialise le flag at_line_start du stdout
    après chaque lecture de ligne.
    """
    def __init__(self, original_stdin, stdout_wrapper):
        self.original_stdin = original_stdin
        self.stdout_wrapper = stdout_wrapper

    def readline(self, *args, **kwargs):
        res = self.original_stdin.readline(*args, **kwargs)
        self.stdout_wrapper.at_line_start = True
        return res

    def read(self, *args, **kwargs):
        res = self.original_stdin.read(*args, **kwargs)
        self.stdout_wrapper.at_line_start = True
        return res

    def __getattr__(self, name):
        return getattr(self.original_stdin, name)


class MarginStdout:
    """
    Wrapper pour sys.stdout qui applique automatiquement une marge
    à chaque début de ligne.
    """
    def __init__(self, original_stdout, margin=4):
        self.original_stdout = original_stdout
        self.margin_str = " " * margin
        self.at_line_start = True
        
        # Envelopper sys.stdin pour réinitialiser at_line_start après une saisie
        if not isinstance(sys.stdin, MarginStdin):
            sys.stdin = MarginStdin(sys.stdin, self)

    def write(self, string):
        if not string:
            return
        
        parts = string.split('\n')
        for i, part in enumerate(parts):
            if i > 0:
                self.original_stdout.write('\n')
                self.at_line_start = True
            
            if part:
                if self.at_line_start:
                    self.original_stdout.write(self.margin_str)
                    self.at_line_start = False
                self.original_stdout.write(part)

    def flush(self):
        self.original_stdout.flush()
