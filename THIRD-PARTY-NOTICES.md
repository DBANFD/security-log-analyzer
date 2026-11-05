# Third-party notices

The application source is MIT licensed. The Windows portable package also includes Python, its standard-library dependencies, Tcl/Tk, SQLite, OpenSSL, libffi, and the unmodified PyInstaller bootloader/runtime hooks. Their respective licenses and notices continue to apply.

Full notice files are preserved under `packaging/licenses` in the source archive and `licenses` in the Windows archive. Python's incorporated-software notices include additional standard-library components. SQLite is distributed as public-domain software; see https://sqlite.org/copyright.html. Microsoft runtime files bundled with the Python Windows distribution retain their original notices and distribution terms.

The frozen builds use Python 3.13.5 and PyInstaller 6.22.3. Build dependencies are pinned in `requirements-build.txt`; they are build tools, not Python packages the end user must install. The application makes no network requests. The presence of standard-library networking/crypto support in the bundle does not enable telemetry or external analysis.

License provenance:

- Python 3.13.5: installed `LICENSE.txt` and CPython `v3.13.5/Doc/license.rst`.
- Tcl/Tk 8.6.15: upstream `core-8-6-15/license.terms` and the installed Tk `license.terms`.
- OpenSSL 3.0.16: upstream `openssl-3.0.16/LICENSE.txt`.
- libffi 3.4.4: upstream `v3.4.4/LICENSE`.
- PyInstaller 6.22.3: installed distribution `licenses/COPYING.txt`, including the bootloader exception and runtime-hook terms.
