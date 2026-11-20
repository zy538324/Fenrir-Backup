# Third-party components

Every dependency shipped in a Fenrir-Backup binary, with its licence.
Policy: only permissive licences (MIT, Apache-2.0, BSD, ISC, Zlib, CC0, Unicode)
are allowed in the Rust crates; copyleft components need explicit approval
and may only be used by `recovery-env` (which assembles a Debian-based
image and keeps its own manifest). CI enforces this with `cargo deny`
(`deny.toml`). Where a crate offers a choice of licences, Fenrir-Backup
uses it under the permissive option.

Regenerate the table with `scripts/third-party.py` after changing dependencies.

## Direct dependencies

| Crate | Version | Licence | Used for |
|---|---|---|---|
| argon2 | 0.5.3 | MIT OR Apache-2.0 | Passphrase key derivation (Argon2id) |
| base64 | 0.22.1 | MIT OR Apache-2.0 | Base64 in JSON metadata |
| blake3 | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception | Keyed chunk hashing, subkey derivation (bundles BLAKE3 C/asm, CC0/Apache-2.0) |
| chacha20poly1305 | 0.10.1 | Apache-2.0 OR MIT | XChaCha20-Poly1305 AEAD |
| clap | 4.6.9 | MIT OR Apache-2.0 | CLI argument parsing |
| crc32fast | 1.5.5 | MIT OR Apache-2.0 | GPT header/entry CRC32 |
| ed25519-dalek | 2.2.0 | BSD-3-Clause | Manifest signatures |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | OS random numbers |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | OS random numbers |
| hex | 0.4.3 | MIT OR Apache-2.0 | Hex encoding of chunk IDs |
| libc | 0.2.191 | MIT OR Apache-2.0 | Linux block-device ioctls |
| rpassword | 7.5.5 | Apache-2.0 | Passphrase prompt without echo |
| serde | 1.0.229 | MIT OR Apache-2.0 | Serialisation framework |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | JSON manifests and CLI output |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | Error types |
| uuid | 1.29.3 | Apache-2.0 OR MIT | Repository, image and partition GUIDs |
| windows | 0.62.2 | MIT OR Apache-2.0 | Win32/COM bindings (VSS, IOCTLs, registry) |
| zeroize | 1.9.2 | Apache-2.0 OR MIT | Wiping key material from memory |
| zstd | 0.13.5 | BSD-3-Clause | zstd compression (Rust binding) |
| zstd-safe | 7.4.1 | BSD-3-Clause | zstd binding layer |
| zstd-sys | 2.1.3+zstd.1.5.7 | BSD-3-Clause AND BSD-2-Clause | Bundled zstd C library (BSD-3-Clause) |

## All crates linked into release binaries (direct and transitive, all targets)

| Crate | Version | Licence |
|---|---|---|
| aead | 0.5.2 | MIT OR Apache-2.0 |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| argon2 | 0.5.3 | MIT OR Apache-2.0 |
| arrayvec | 0.7.8 | MIT OR Apache-2.0 |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| base64ct | 1.8.3 | Apache-2.0 OR MIT |
| blake2 | 0.10.6 | MIT OR Apache-2.0 |
| blake3 | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| bumpalo | 3.20.4 | MIT OR Apache-2.0 |
| cc | 1.11.3 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| chacha20 | 0.9.1 | Apache-2.0 OR MIT |
| chacha20poly1305 | 0.10.1 | Apache-2.0 OR MIT |
| cipher | 0.4.4 | MIT OR Apache-2.0 |
| clap | 4.6.9 | MIT OR Apache-2.0 |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 |
| clap_derive | 4.6.9 | MIT OR Apache-2.0 |
| clap_lex | 1.1.2 | MIT OR Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| const-oid | 0.9.6 | Apache-2.0 OR MIT |
| constant_time_eq | 0.4.2 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 |
| crc32fast | 1.5.5 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| der | 0.7.10 | Apache-2.0 OR MIT |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| find-msvc-tools | 0.1.15 | MIT OR Apache-2.0 |
| futures-core | 0.3.34 | MIT OR Apache-2.0 |
| futures-task | 0.3.34 | MIT OR Apache-2.0 |
| futures-util | 0.3.34 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| inout | 0.1.4 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itoa | 1.0.19 | MIT OR Apache-2.0 |
| jobserver | 0.1.35 | MIT OR Apache-2.0 |
| js-sys | 0.3.107 | MIT OR Apache-2.0 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| memchr | 2.8.3 | Unlicense OR MIT |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| opaque-debug | 0.3.1 | MIT OR Apache-2.0 |
| password-hash | 0.5.0 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.18 | Apache-2.0 OR MIT |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 |
| poly1305 | 0.8.0 | Apache-2.0 OR MIT |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| rpassword | 7.5.5 | Apache-2.0 |
| rtoolbox | 0.0.6 | Apache-2.0 |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| rustversion | 1.0.23 | MIT OR Apache-2.0 |
| semver | 1.0.28 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| signature | 2.2.0 | Apache-2.0 OR MIT |
| slab | 0.4.12 | MIT |
| spki | 0.7.3 | Apache-2.0 OR MIT |
| strsim | 0.11.1 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.119 | MIT OR Apache-2.0 |
| syn | 3.0.10 | MIT OR Apache-2.0 |
| thiserror | 2.0.21 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| universal-hash | 0.5.1 | MIT OR Apache-2.0 |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| uuid | 1.29.3 | Apache-2.0 OR MIT |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.130 | MIT OR Apache-2.0 |
| windows | 0.62.2 | MIT OR Apache-2.0 |
| windows-collections | 0.3.2 | MIT OR Apache-2.0 |
| windows-core | 0.62.2 | MIT OR Apache-2.0 |
| windows-future | 0.3.2 | MIT OR Apache-2.0 |
| windows-implement | 0.60.2 | MIT OR Apache-2.0 |
| windows-interface | 0.59.3 | MIT OR Apache-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-numerics | 0.3.1 | MIT OR Apache-2.0 |
| windows-result | 0.4.1 | MIT OR Apache-2.0 |
| windows-strings | 0.5.1 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| windows-threading | 0.2.1 | MIT OR Apache-2.0 |
| zeroize | 1.9.2 | Apache-2.0 OR MIT |
| zeroize_derive | 1.5.0 | Apache-2.0 OR MIT |
| zmij | 1.0.23 | MIT |
| zstd | 0.13.5 | BSD-3-Clause |
| zstd-safe | 7.4.1 | BSD-3-Clause |
| zstd-sys | 2.1.3+zstd.1.5.7 | BSD-3-Clause AND BSD-2-Clause |

## Test and development only (not shipped)

| Crate | Licence | Used for |
|---|---|---|
| tempfile | MIT OR Apache-2.0 | Temporary directories in tests |
| libfuzzer-sys | (MIT OR Apache-2.0) AND NCSA | Fuzzing harness (`fuzz/`) |

## Platform interfaces

* Windows: Volume Shadow Copy Service, DeviceIoControl, registry and firmware
  APIs are called through their documented public interfaces. The
  `IVssBackupComponents` vtable layout follows the public Windows SDK header
  `vsbackup.h`; no Microsoft code is redistributed.
* Linux: kernel ioctls (`BLKSSZGET`, `BLKPBSZGET`) and `/proc`, `/sys`.
