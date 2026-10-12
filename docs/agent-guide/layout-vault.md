# Agent guide — `crates/undercroft-vault`

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entry for
`crates/undercroft-vault`: the per-vault database file and its legacy name,
the master key and HKDF, sealing, the manifest and its one writer, which
manifest a handle's rows answer to, the archive, restore and delete sides of
the filesystem, and recipient-encrypted, signed export bundles. Read it when
your work touches that crate, a key, a manifest, a vault's files on disk, or a
bundle.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). Where this full text and the core's one-line form of the same
rule differ, this full text governs, and the divergence is a defect, fixed in
the unit that finds it (ruled by the maintainer, 2026-10-12). In the moved
text, "this file" and "here" mean the guide as a whole — the core and its
reference documents.

---

- `crates/undercroft-vault` — security layer (**the per-vault database is
  `vault.db` since 1.5.0, beside `vault.json` — O7: `palace` had named both
  the installation and each vault's file, and the installation keeps the
  word. `Vault::db_path` answers with the file the directory HAS
  (`DbLayout`), so a pre-1.5.0 `palace.db` is served where found; the
  store's WRITABLE open checkpoints the WAL and renames it — a bare rename
  orphans every committed frame in a hot `-wal`, silently — a read-only open
  reports it on `unhealed`, and two files refuse as an integrity verdict on
  both postures. **The rename runs only under an exclusive hold, and a vault
  anything else has open keeps its old name (O281)**: busy from the WAL
  checkpoint was the test, and busy sees only a reader mid-read, so an IDLE
  holder was renamed beneath — a read-only replica then served stale rows and
  a false `verify` failure, and a writable holder's later commits each
  answered OK and were lost with the `-wal` unlinked beneath it (measured
  across processes, released since 1.5.0). The step now reads
  `locking_mode=EXCLUSIVE` back before any statement, then `BEGIN EXCLUSIVE`
  under a zero busy timeout, refused at once beside any connection holding a
  lock on the file (every one that has read it, idle or not — not one opened
  and not yet read, which O279's door refuses once it reads) and, once taken,
  held through the checkpoint and, on unix, the rename (O257's measurement);
  off unix a file SQLite holds cannot be renamed, so the hold closes just
  before it. Refused, the open proceeds on `palace.db` beside the holder, and
  only a handle really left there says so on `unhealed` — the first build put
  the note on one that found `vault.db`, and ran the rename under the hold on
  Windows too, where it would have refused every legacy vault, both found by
  an independent review rather than by a gate. `database_exists` knows both names, or upgrade day would
  read every older vault as A33's missing database;** keys.rs: master key + HKDF
  — **and the master key is created only where nothing refers to one (O204)**:
  `master_key` surveys the root by stat alone (`survey`, errors propagated,
  a symlinked key file counts), `plan` classifies it — the declared file
  present loads, the OTHER file alone is `SourceMismatch`, neither under any
  `vaults/` or `backups/` entry is `MaterialMissing`, both exit 1 as no
  `KeyError` is an integrity verdict — and only then is a key read, derived
  or written, by one private exclusive writer. **That writer publishes
  through the private `publish_new_secret` (O210)**, whose only other door,
  `write_new_identity`, is how the CLI's two keygens write (O321): an
  existing name refused by `symlink_metadata` before a byte is written, the
  bytes into a `create_new` temp owner-only from the open, fsync, then a
  HARD LINK to the name — which fails if it exists, so nothing is replaced
  and no link followed — and a directory fsync before the temp goes. A crash
  before the link leaves no key file, so the next start makes a whole one; a
  short file already there is `CorruptKeyFile` naming it and its length. Only
  where the link error reads as "unsupported" (measured `EPERM` on vfat,
  `ENOSYS` on a FUSE exFAT) does it fall back to O204's exclusive in-place
  create, warning — never to a rename, which replaces; which writer a
  linkless filesystem should get is open (O412). Every other link
  error refuses with the temp kept and named, and the fallback removes
  nothing, because a name it created may already have been loaded (the
  review of its first build found both). Nothing sweeps a crash's leftover
  temp, which may be the last copy of a key. With BOTH files present the
  declared one is used and every open warns; the undeclared key is never
  tried, because a file an offline writer can plant proves nothing and the
  trial would steer a passphrase deployment towards it. `VaultManager::open_as`
  carries the posture: read-only creates nothing, holds no key in a fresh
  installation, refuses `create`/`delete`/`rotation_candidate`, and unlocks
  read-only whatever it is asked; `create` refuses as `KeyOpensNoVault`
  (exit 2) when the key opens none of the installation's manifests, the door a
  split installation was minted through. **A command derives a passphrase's
  key ONCE (O211)**: `KeyCache` keeps the Argon2id output against a SHA-256
  digest of the passphrase and the salt bytes that produced it (both compared
  in constant time over fixed lengths) — and only while a `KeyHold` is alive,
  so an open with no hold keeps nothing. The CLI holds one in a `static` that
  every manager open — its one door, `manager_in`, through `open_cached` —
  derives through, and exactly three holds span the opens of `vault list`,
  `vault rotate` and a `serve-http` start, which run Argon2id once rather than
  once per open; a one-open command (`serve-mcp`, `mine`) keeps the key only
  as long as its manager, as before. The survey, `plan` and the read of
  `kdf.salt` still run on every open, because only the DERIVATION may be
  cached, never the decision about which key file applies. `open_as` keeps
  deriving per call for library callers; a CLI source gate counts the
  binary's one open and its three holds;
  seal.rs: AEAD + HMAC; lib.rs: VaultManager/Vault + manifest-as-rollback-
  anchor + pure chain arithmetic + key rotation primitives
  (rotation_candidate, byte-exact reseal_at_rest, two-phase
  vault.json.next staging, keycheck marker) + **the one manifest file
  writer** (`write_manifest_file`: a random-nonce `create_new` temp, fsync,
  rename, directory sync — `create`, the staging write, every anchor,
  since O257 the promote, since O256 the manifest an archive is
  published with, and since O268 the manifest a restore stages go through
  it, so the crate renames a manifest in ONE place — its other renames
  publish an archive's stage, swap a restore's stage in and take a deleted
  vault out of service — and deletes
  only files it can name as its own; no unlock deletes a
  `vault.json.next` on either posture, a too-new one included — and the
  bare legacy `vault.json.tmp` a 1.6.x process still
  writes is never matched or swept) and the anchor's checked
  read-modify-write, whose failures come back as `AnchorFault::{Io,
  Integrity}` for the store's door to act on (ROADMAP O254) — **and ONE
  rule for which manifest a handle's rows answer to (O266)**:
  `manifest_in_force`, read by `anchored_head`, `anchored_writes`,
  `verified_manifest` and, since O288, the read-only open's
  `deferral_in_force` alone, and since O213 `manifest_history_in_force`, which
  the read-only open's arms ask before the database. Ordinarily `vault.json`; on a handle whose
  keys came from `vault.json.next` (a read-only open that adopted a
  committed rotation, or the rotating handle after a deferred promote),
  the STAGED manifest — `.next` read first, then `vault.json`, and only
  while `vault.json` is byte for byte the retired file the adoption was
  licensed by (a digest of the very buffer whose MAC was verified) and
  `.next` byte for byte what the handle read. A `vault.json` verifying
  under the adopted key is a promote since, followed, never latched; a lost
  `.next` beside the RETIRED bytes is integrity with no tamper event, and any
  other `vault.json` failing the handle's MAC is the tamper verdict whatever
  `.next` holds — **O289**: the rule answered a lost `.next` there, so a
  read-only handle whose promote landed after its open met a forged manifest
  with no page, where an ordinary handle and a fresh unlock page; only the
  refusal arm raises the manifest tamper signal. **Every manifest read the
  unlock, the rule and the anchor's strict read make goes through ONE guarded
  read (O289)**, `read_manifest_file` — a stat, then a bounded read of a
  regular file of at most 1 MiB, so a FIFO is never opened and what is AT the
  path decides the class, never the error kind — and a `vault.json` that is
  missing or not a manifest file is the integrity verdict on EVERY handle
  (**O277**: `anchored_head` fell back over it and `verify` answered OK over a
  vault no open could reopen; a directory there was "other I/O" and still
  would have been under the filed `NotFound`-only split). A present file that
  cannot be read falls back only on an ordinary handle or where `.next` is
  intact, and `.next`'s own read is HELD until `vault.json` is judged — an
  early return there turned a directory planted at `.next` into `VERIFY OK`
  beside a forged manifest. The strict readers — `manifest_on_disk_is_mine`,
  the anchor's own read, `promote` — never take it, and a source gate
  counts the five readers, the guarded read's callers, and the three bare
  manifest reads left in `lib.rs` (O293 files them, and the ones in
  `restores.rs` and `backups.rs`); a
  `test-fixture` feature carries the fault seam, since a nonce name cannot
  be targeted from outside; backups.rs: the archive side of `backup
  create` (ROADMAP O256, O265) — a stage under `backups/.staging/<nonce>`
  (`.staging` judged by `symlink_metadata` first and refused if it is a link
  or not a directory, before the sweep reads it or a stage is made in it —
  O273: the stage and the sweep followed a planted link wherever it pointed)
  published by one rename only when it holds exactly `vault.db` and
  `vault.json`, a stage older than an hour swept, and a vault's archives
  found by their OWN manifest and exact name shape, never a prefix (backing
  up `p` pruned `p-2024`'s archives, and its own beside `p-archive`'s);
  restores.rs: the filesystem side of `backup restore` (ROADMAP O268) — a
  restore area directly under `vaults/` named by a 129-byte constant no vault
  id can equal (`validate_name` trims, then refuses over 128 bytes; a test
  pins it), refused if it is a link; an archive read by `symlink_metadata`
  and copied through an ALLOWLIST of regular files (either database name,
  its `-wal`, the manifest's exact bytes through the one writer, a staged
  rotation manifest — never a `-shm`, a temp or a directory); a stage
  unlocked only through `VaultManager::unlock_stage`, whose shared body
  `unlock_dir` is `unlock_as`'s (keys derive from the manifest's id and salt,
  never the directory, so taking only a stage this crate minted is what keeps
  `backups/<name>` from ever being opened writable); and the swap — two
  renames under the store's hold, an `aside-<sha256 of the id>` that is
  NEVER swept or removed on a failure path, and `create` refusing
  `RestoreInterrupted` while one exists;
  deletes.rs: the filesystem side of a vault delete (ROADMAP O291) — what
  is at `vaults/<id>`, surveyed by `symlink_metadata` with every stat error
  propagated (`Path::exists` follows links and reads any error as absence,
  which is how an unreadable manifest read as no vault), the empty
  `vault.db` a manifest-only vault is held on (made with `create_new`,
  owned only when this call made it, removed while still empty), ONE rename
  of the vault into the restore area as `deleting-<sha256 of the id>` —
  never `aside-`, beside which `create` refuses and tells the operator to
  put the vault back, and never a nonce, which no retry could find — and
  ONE removal judged by what is left, never by `remove_dir_all`'s result.
  It observes and refuses nothing; the store's door classifies. Its survey is
  also the restore's (O301, `restores::irregular_target`): ONE rule for what
  a vault directory may hold when something replaces or removes it. `DbLayout::of`
  is the ONE layout rule, `Vault::db_layout` and O69's hold both asking it;
  bundle.rs:
  recipient-encrypted export bundles — **the vault-sized paths take the
  buffer rather than borrowing it** (`encrypt_for_into` seals IN PLACE and
  writes the header ahead of it; `decrypt_with_owned` opens in place;
  `encrypt_for`/`decrypt_with` are the borrowing wrappers, fine for a test
  and not for a corpus). The returning forms allocated a second whole
  payload beside the caller's, which measured **3.02x on `export --to` and
  4.49x on `import`** — both worse than the unsealed peak O113 was filed to
  fix, on the two paths O113 and O137 never measured (O138). One
  implementation each way: `seal_header`/`open_header` yield the AAD and the
  key together, because they come out of one run of bytes and must not
  drift. **Hybrid post-quantum since
  C3.4**: `keygen` = X25519 + ML-KEM-768 (`pq1` strings), v2 bundles
  derive the file key from BOTH shared secrets (HKDF ikm = DH ‖
  kem_shared, magic+eph+kem_ct all AAD), closing
  harvest-now-decrypt-later on the one asymmetric exchange in the
  codebase; legacy bare-hex X25519 identities still parse, still
  receive v1 bundles they can open, and a hybrid identity opens old v1
  backups with its curve half — but a hybrid recipient NEVER silently
  downgrades and an X25519-only secret gets a typed refusal on v2
  (downgrade-refusal pinned; docs/PQ.md is the posture page, incl. the
  honest boundary: quantum-resistant CRYPTOGRAPHY, never "quantum
  processing") + **signed manifests** (Ed25519 sender attestation
  beside the recipient flow — encryption says who may READ, the signature
  says who WROTE; scope/trust-claim/expiry/counts/provenance +
  unconditionally-checked payload digest; a sender-declared trust label is
  a CLAIM, never a boundary — docs/LABELS.md; legacy payloads import
  unattested-and-said-so); at-rest AAD domains: content, `/emb`, `/tok`
  token matrices, `/pq` index artifacts)
