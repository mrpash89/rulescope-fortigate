"""Build a demo fleet site from the bundled sample config (three fictional firewalls, two runs).

    python3 examples/make_demo.py /tmp/rulescope-demo
    open /tmp/rulescope-demo/site/index.html
"""
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from rulescope import fleet  # noqa: E402


def main(out: str, advisor=None) -> None:
    """`advisor`: an optional firmware.AdvisoryClient, to include known CVEs for the demo's FortiOS versions."""
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    with open(os.path.join(ROOT, "tests", "sample.conf"), encoding="utf-8") as fh:
        src = fh.read()

    def write(name: str, text: str) -> str:
        p = os.path.join(out, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    hq = write("hq.conf", src.replace('set hostname "FGT-LAB"', 'set hostname "FGT-HQ"'))
    north = src.replace("FGT60F-7.4.3-FW-build2573", "FGT40F-7.2.10-FW-build1706").replace(
        'set hostname "FGT-LAB"', 'set hostname "FGT-BR-NORTH"').replace(
        "set strong-crypto disable", "set strong-crypto enable").replace(
        "set allowaccess ping https ssh http telnet", "set allowaccess ping https ssh")
    north = re.sub(r"    edit 3[23]\n.*?    next\n", "", north, flags=re.S)
    north = re.sub(r"config vpn ssl settings\n.*?end\n", "", north, flags=re.S)
    north_p = write("north.conf", north)
    south_p = write("south.conf", src.replace('set hostname "FGT-LAB"', 'set hostname "FGT-BR-SOUTH"'))
    inv = write("fleet.ini", f"[HQ]\nconfig = {hq}\nlabel = Headquarters\ngroup = Core\n\n"
                             f"[Branch-North]\nconfig = {north_p}\nlabel = Branch North\ngroup = Branches\n\n"
                             f"[Branch-South]\nconfig = {south_p}\nlabel = Branch South\ngroup = Branches\n")
    devices = fleet.load_inventory(inv)
    site, snaps = os.path.join(out, "site"), os.path.join(out, "snapshots")
    fleet.run(devices, site, snaps, auditor="Demo auditor", advisor=advisor)

    # Second run: someone opens SSH on a WAN interface and adds an admin; another site fixes logging.
    s = open(south_p, encoding="utf-8").read()
    s = s.replace("set allowaccess ping https\n", "set allowaccess ping https ssh\n", 1)
    s = s.replace('    edit "pavel"', '    edit "contractor"\n        set accprofile "super_admin"\n'
                                       '        set vdom "root"\n    next\n    edit "pavel"', 1)
    write("south.conf", s)
    write("north.conf", north.replace("        set logtraffic disable\n", "        set logtraffic all\n", 1))
    fleet.run(devices, site, snaps, auditor="Demo auditor", advisor=advisor)
    print(os.path.join(site, "index.html"))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "rulescope-demo")
