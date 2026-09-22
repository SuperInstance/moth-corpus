import subprocess
import sys


def test_module_invocation_reaches_argparse():
    # rc 2 + usage text = argparse saw us (package invocable);
    # rc 1 with "'moth_corpus' is a package" = missing __main__ regression
    proc = subprocess.run([sys.executable, "-m", "moth_corpus"],
                          capture_output=True, text=True)
    assert proc.returncode == 2, proc.stderr
    assert "usage" in proc.stderr.lower()
