c-4.5.6.db is a real database written by the C libsqlcipher 4.5.6 library,
copied verbatim from github.com/hanzoai/sqlcipher@v0.1.0/testdata. It is keyed
with the raw key 000102...1e1f (see enc_test.go: sqlcipherInteropKey).

The encrypted-source migrator test uses it ONLY as a source of SQLCipher's
80-byte per-page reserve (SQLite header byte 20): DecryptFile yields a reserved
plaintext canvas, modernc PRESERVES that reserve when the test overwrites the
schema, and EncryptFile can then produce an encrypted shard the test fully
controls. Pure Go cannot ORIGINATE reserved pages, so this vector bootstraps
them. Its own schema/contents are irrelevant — the test wipes them.
