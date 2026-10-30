**What changes and why**

**Checks**

- [ ] `python -m ruff check src tools packaging`
- [ ] `cd src && python -m pytest -q` (the architecture ratchet included)
- [ ] Live contracts unchanged, or the change is on purpose and explained (command-line options, names in `config.py`)
- [ ] If it needs a real computer to verify (UAC, WFP, a real proxy): what was checked and how
