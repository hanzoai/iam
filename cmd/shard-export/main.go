// Command shard-export decrypts encrypted IAM shards to plaintext SQLite copies
// so a restore can be verified against the SOURCE with an independent reader.
// It reuses the pure-Go envelope helpers in hanzoai/sqlite (DeriveKey/UnwrapDEK)
// and the C sqlcipher shell for the WAL-inclusive export — the same recipe
// migrate-v1 uses, never a second crypto implementation.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	hsqlite "github.com/hanzoai/sqlite"
)

type shard struct {
	label string
	path  string
	pt    hsqlite.PrincipalType
	pid   string
}

func main() {
	datadir := flag.String("datadir", "", "encrypted sharded source root")
	out := flag.String("out", "", "output dir for plaintext copies")
	only := flag.String("only", "all", "all | global | <org-slug>")
	flag.Parse()
	if *datadir == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "shard-export: --datadir and --out are required")
		os.Exit(2)
	}
	master, err := hex.DecodeString(strings.TrimSpace(os.Getenv("IAM_KMS_MASTER_KEY")))
	if err != nil || len(master) != 32 {
		fmt.Fprintln(os.Stderr, "shard-export: IAM_KMS_MASTER_KEY must be 64 hex chars")
		os.Exit(2)
	}
	defer zero(master)
	if err := os.MkdirAll(*out, 0o700); err != nil {
		fatal(err)
	}

	var shards []shard
	if *only == "all" || *only == "global" {
		shards = append(shards, shard{"global", filepath.Join(*datadir, "iam.db"), hsqlite.PrincipalGlobal, "iam"})
	}
	if *only != "global" {
		ents, err := os.ReadDir(filepath.Join(*datadir, "orgs"))
		if err != nil {
			fatal(err)
		}
		var slugs []string
		for _, e := range ents {
			if e.IsDir() && (*only == "all" || *only == e.Name()) {
				slugs = append(slugs, e.Name())
			}
		}
		sort.Strings(slugs)
		for _, s := range slugs {
			shards = append(shards, shard{"org." + s, filepath.Join(*datadir, "orgs", s, "iam.db"), hsqlite.PrincipalOrg, s})
		}
	}
	if len(shards) == 0 {
		fatal(fmt.Errorf("no shard matched --only %q", *only))
	}
	for _, sh := range shards {
		if err := export(sh, master, *out); err != nil {
			fatal(err)
		}
	}
}

func export(sh shard, master []byte, out string) error {
	kek, err := hsqlite.DeriveKey(master, sh.pt, sh.pid)
	if err != nil {
		return fmt.Errorf("%s: derive KEK: %w", sh.label, err)
	}
	defer zero(kek)
	wrapped, err := os.ReadFile(sh.path + ".dek")
	if err != nil {
		return fmt.Errorf("%s: read sidecar: %w", sh.label, err)
	}
	dek, err := hsqlite.UnwrapDEK(kek, wrapped, hsqlite.PrincipalAAD(sh.pt, sh.pid))
	if err != nil {
		return fmt.Errorf("%s: unwrap DEK: %w", sh.label, err)
	}
	defer zero(dek)

	dir, err := os.MkdirTemp("", "shard-export-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "src.db")
	for _, suf := range []string{"", "-wal", "-shm"} {
		if _, e := os.Stat(sh.path + suf); e == nil {
			if e := cp(sh.path+suf, src+suf); e != nil {
				return e
			}
		}
	}

	plain := filepath.Join(out, sh.label+".db")
	_ = os.Remove(plain)
	h := make([]byte, hex.EncodedLen(len(dek)))
	hex.Encode(h, dek)
	defer zero(h)

	var script bytes.Buffer
	script.WriteString("PRAGMA key = \"x'")
	script.Write(h)
	script.WriteString("'\";\n")
	script.WriteString("PRAGMA cipher_page_size = 4096;\n")
	script.WriteString("PRAGMA wal_checkpoint(TRUNCATE);\n")
	script.WriteString("ATTACH DATABASE '" + plain + "' AS plaintext KEY '';\n")
	script.WriteString("SELECT sqlcipher_export('plaintext');\n")
	script.WriteString("DETACH DATABASE plaintext;\n")
	defer zero(script.Bytes())

	cmd := exec.Command("sqlcipher", "-bail", src)
	cmd.Stdin = bytes.NewReader(script.Bytes())
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = io.Discard, &errb
	if err := cmd.Run(); err != nil {
		safe := bytes.ReplaceAll(errb.Bytes(), h, []byte("<redacted>"))
		return fmt.Errorf("%s: sqlcipher export: %v: %s", sh.label, err, bytes.TrimSpace(safe))
	}
	fi, err := os.Stat(plain)
	if err != nil {
		return fmt.Errorf("%s: export produced nothing: %w", sh.label, err)
	}
	f, err := os.Open(plain)
	if err != nil {
		return err
	}
	head := make([]byte, 16)
	_, rerr := io.ReadFull(f, head)
	f.Close()
	if rerr != nil || !bytes.Equal(head, []byte("SQLite format 3\x00")) {
		return fmt.Errorf("%s: export is not a plaintext SQLite database", sh.label)
	}
	fmt.Printf("%s\t%s\t%d\n", sh.label, plain, fi.Size())
	return nil
}

func cp(a, b string) error {
	in, err := os.Open(a)
	if err != nil {
		return err
	}
	defer in.Close()
	o, err := os.OpenFile(b, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(o, in); err != nil {
		o.Close()
		return err
	}
	return o.Close()
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "shard-export:", err); os.Exit(1) }
