import pathlib

HANDLER = '''

@app.errorhandler(Exception)
def _lab_error(e):
    import traceback
    tb = traceback.format_exc()
    print("[LAB ERROR] " + tb, flush=True)
    return "<pre>Lab error: " + type(e).__name__ + ": " + str(e) + "\\n\\n" + tb + "</pre>", 500
'''

MARKER = "app = Flask(__name__)"

for p in pathlib.Path("vuln_templates").rglob("app.py.template"):
    s = p.read_text(encoding="utf-8")
    if "_lab_error" in s:
        print("already has handler:", p)
        continue
    if MARKER not in s:
        print("MARKER NOT FOUND — skipping:", p)
        continue
    p.write_text(s.replace(MARKER, MARKER + HANDLER, 1), encoding="utf-8")
    print("added handler to", p)