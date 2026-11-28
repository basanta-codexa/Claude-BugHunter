"""#281: a symlinked `cbh` must still import the package. scripts/cbh.py used
os.path.abspath(__file__), which doesn't follow symlinks, so `ln -s .../cbh.py
/usr/local/bin/cbh` broke `import cbh.cli`. realpath fixes it."""
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipIf(sys.platform == "win32", "symlink semantics differ on Windows")
class CbhSymlinkImport(unittest.TestCase):
    def test_symlinked_cbh_imports(self):
        d = tempfile.mkdtemp()
        link = os.path.join(d, "cbh")
        os.symlink(os.path.join(REPO, "scripts", "cbh.py"), link)
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, link, "--help"],
                           cwd=d, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("cbh", r.stdout.lower())


if __name__ == "__main__":
    unittest.main()
