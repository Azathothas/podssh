# The files of mRemoteNG in this directory

Each `.xml` file here was written by mRemoteNG and is published in its
repository as a file of its tests, under the GNU General Public License,
version 2 (the operator's ruling on Q46, 2026-10-30, `docs/decisions.md`).
Each is kept byte for byte, as fetched from
`https://raw.githubusercontent.com/mRemoteNG/mRemoteNG/COMMIT/PATH` on
2026-10-30, so that `podssh config import mremoteng` is tested on files that
the program wrote (T-327). The license is `COPYING.txt` beside them, as it was
at that commit. None of these files is linked into a binary of podssh: the
tests read them at run time.

| File | Commit | Path there |
| --- | --- | --- |
| `confCons_v2_5.xml` | `25ef453aaf18f292478dd41e5bb26798ff504312` | `mRemoteNGTests/Resources/confCons_v2_5.xml` |
| `confCons_v2_6.xml` | `25ef453aaf18f292478dd41e5bb26798ff504312` | `mRemoteNGTests/Resources/confCons_v2_6.xml` |
| `confCons_v2_6_fullencryption.xml` | `25ef453aaf18f292478dd41e5bb26798ff504312` | `mRemoteNGTests/Resources/confCons_v2_6_fullencryption.xml` |
| `COPYING.txt` | `25ef453aaf18f292478dd41e5bb26798ff504312` | `COPYING.txt` |

Their SHA-256, as fetched:

```text
bd85141ffaf66c95f83643b1e57006b8cc0885a497c0c51fc9227f5b7ac9a3fb  confCons_v2_5.xml
faad55a38bc6a85df3420e954ea6160b7e329e700dee4c90df0ea6e507b25ec0  confCons_v2_6.xml
a93d1c46b28197ffd4972c75810edd7071e7f11ebb0a502e9742b6cb8c702cd1  confCons_v2_6_fullencryption.xml
df84246204e3c54cd24aebbc23714235f5fc41d754d53b65444a2afbf070130f  COPYING.txt
```

mRemoteNG is Copyright the mRemoteNG team and its contributors; see
`https://github.com/mRemoteNG/mRemoteNG`.
