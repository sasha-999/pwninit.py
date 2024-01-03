import sys

def colourize(x, colour):
    return colour + x + "\x1b[0m"
def red(x):
    return colourize(x, "\x1b[31m")
def orange(x):
    return colourize(x, "\x1b[33m")
def light_red(x):
    return colourize(x, "\x1b[91m")
def green(x):
    return colourize(x, "\x1b[92m")
def blue(x):
    return colourize(x, "\x1b[94m")

def info(msg):
    print(f"[{blue('*')}] {msg}")

def warning(msg):
    print(f"[{orange('!')}] {orange(msg)}")

def success(msg):
    print(f"[{green('+')}] {green(msg)}")

def error(msg):
    print(f"[{light_red('-')}] {light_red(msg)}")

def fatal(msg):
    print(f"[{red('X')}] {red(msg)}")
    sys.exit(1)
