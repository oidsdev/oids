"""Test DB builder: schema.sql + migrations/ applied to a local sqlite database.

schema.sql is a D1 export dump whose statements are NOT semicolon-terminated
(blocks are blank-line separated, indexes listed before tables), so it needs
special handling: strip comments, split blocks, run CREATE TABLEs first, then
ALTERs, then everything else (indexes, triggers). Migration files are normal
semicolon-terminated SQL, except CREATE TRIGGER ... END; blocks which are
kept whole; they are applied in filename order with statement order
preserved (a table-rebuild migration like 030 only works in its written
order). Because schema.sql is a snapshot of the LIVE database, it already
contains most objects the migrations create: duplicate-column ALTERs and
already-exists CREATEs from migration files are skipped, so a fresh build
converges on the snapshot's shape instead of dying on the overlap.
"""
import glob
import os
import re
import sqlite3

OIDS_ROOT = os.path.expanduser("~/workspace/oids")


def _schema_statements():
    blocks, buf = [], []
    with open(os.path.join(OIDS_ROOT, "schema.sql")) as f:
        for line in f:
            line = re.sub(r"--.*$", "", line).rstrip()
            if line.strip():
                buf.append(line)
            elif buf:
                blocks.append(" ".join(buf))
                buf = []
    if buf:
        blocks.append(" ".join(buf))
    return [b + ";" for b in blocks if b.upper().startswith("CREATE")]


def _migration_statements(path):
    with open(path) as f:
        txt = "".join(re.sub(r"--.*$", "", line) for line in f)
    # Preserve file order; CREATE TRIGGER ... END; blocks stay atomic.
    out, pos = [], 0
    trig_re = re.compile(r"CREATE\s+TRIGGER.*?END\s*;", re.I | re.S)
    while pos < len(txt):
        m = trig_re.search(txt, pos)
        chunk_end = m.start() if m else len(txt)
        for s in txt[pos:chunk_end].split(";"):
            if s.strip():
                out.append(s.strip() + ";")
        if not m:
            break
        out.append(m.group(0))
        pos = m.end()
    return out


def _kind(stmt):
    u = stmt.upper()
    if u.startswith("CREATE TABLE"):
        return 0
    if u.startswith("ALTER TABLE"):
        return 1
    return 2


def build_test_db():
    """Return an open sqlite3 connection with the full Oids schema applied."""
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    for stmt in sorted(_schema_statements(), key=_kind):
        cur.execute(stmt)
    for path in sorted(glob.glob(os.path.join(OIDS_ROOT, "migrations", "*.sql"))):
        name = os.path.basename(path)
        for stmt in _migration_statements(path):
            try:
                cur.execute(stmt)
            except sqlite3.OperationalError as e:
                msg = str(e)
                if "duplicate column name" in msg or "already exists" in msg:
                    continue  # schema.sql snapshot already contains it
                raise AssertionError(f"{name}: {e}\n  {stmt[:100]}")
    con.commit()
    return con
