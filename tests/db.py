"""Test DB builder: schema.sql + migrations/ applied to a local sqlite database.

schema.sql is a D1 export dump whose statements are NOT semicolon-terminated
(blocks are blank-line separated, indexes listed before tables), so it needs
special handling: strip comments, split blocks, run CREATE TABLEs first, then
ALTERs, then everything else (indexes, triggers). Migration files are normal
semicolon-terminated SQL, except CREATE TRIGGER ... END; blocks which are
kept whole. Duplicate-column ALTERs (schema.sql was regenerated from the live
DB after some migrations ran) are skipped — same as D1 would behave on a
fresh rebuild.
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
    trigs = re.findall(r"CREATE\s+TRIGGER.*?END\s*;", txt, re.I | re.S)
    rest = re.sub(r"CREATE\s+TRIGGER.*?END\s*;", "", txt, flags=re.I | re.S)
    return trigs + [s.strip() + ";" for s in rest.split(";") if s.strip()]


def _kind(stmt):
    u = stmt.upper()
    if u.startswith("CREATE TABLE"):
        return 0
    if u.startswith("ALTER TABLE"):
        return 1
    return 2


def build_test_db():
    """Return an open sqlite3 connection with the full Oids schema applied."""
    stmts = [("schema.sql", s) for s in _schema_statements()]
    for path in sorted(glob.glob(os.path.join(OIDS_ROOT, "migrations", "*.sql"))):
        stmts += [(os.path.basename(path), s) for s in _migration_statements(path)]
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    for name, stmt in sorted(stmts, key=lambda ps: _kind(ps[1])):
        try:
            cur.execute(stmt)
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                continue  # schema.sql snapshot already contains this column
            raise AssertionError(f"{name}: {e}\n  {stmt[:100]}")
    con.commit()
    return con
