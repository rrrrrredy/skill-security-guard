"""An example mentioning eval(...) is documentation."""
from builtins import eval as calculate
import urllib.request as transport


def syntax_sample():
    # exec('not a call') is documentation too.
    calculate("2 + 2")
    transport.urlopen("fixture:no-handler", data=b"public test value")
