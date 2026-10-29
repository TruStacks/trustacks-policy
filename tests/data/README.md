# Test data

`endoflife.json` is a copy of the endoflife.date snapshot that trustacks-mvp
ships (`control-plane/src/trustacks_control/runtime_eol/endoflife.json`). The
data comes from https://endoflife.date and is used under the MIT License
(https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE). The
snapshot date is inside the file. Refresh it from trustacks-mvp whenever that
copy is refreshed (`make runtime-eol-refresh` there).

`tests/test_pack_runtimes_supported.py` reads it to check that no framework
pack pins a runtime that is end of life or within 90 days of it.
