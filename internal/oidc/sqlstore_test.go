package oidc

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/valyala/fasthttp"
	zaphttp "github.com/zap-proto/http"
)

// sqlstore_test.go runs this package's whole suite against hanzoai/sql when
// IAM_SQL_ADDR names a server: openTestDB gives each test its own table, dropped
// afterwards, so a run never meets another's records.

var scratchSeq atomic.Int64

func sqlExec(t *testing.T, addr, stmt string) {
	t.Helper()
	tr := zaphttp.Dial("tcp", addr)
	defer tr.CloseIdleConnections()
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.Header.SetMethod("POST")
	req.SetRequestURI("/exec")
	req.Header.SetHost(addr)
	body, _ := json.Marshal(map[string]any{"sql": stmt})
	req.SetBody(body)
	if err := tr.Do(req, resp); err != nil || resp.StatusCode() != 200 {
		t.Fatalf("exec %q: %v %d %s", stmt, err, resp.StatusCode(), resp.Body())
	}
}

func sqlScratchDB(t *testing.T, addr string) orm.DB {
	t.Helper()
	table := fmt.Sprintf("t%d_%d", time.Now().UnixNano()%1_000_000_000, scratchSeq.Add(1))
	sqlExec(t, addr, fmt.Sprintf(`CREATE TABLE %q (LIKE _entities INCLUDING DEFAULTS INCLUDING CONSTRAINTS)`, table))
	sqlExec(t, addr, fmt.Sprintf(`ALTER TABLE %q ADD PRIMARY KEY (id)`, table))
	db, err := orm.OpenZap(&ormdb.ZapConfig{Addr: addr, Backend: ormdb.ZapSQL, Collection: table})
	if err != nil {
		t.Fatalf("open zap sql: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		sqlExec(t, addr, fmt.Sprintf(`DROP TABLE IF EXISTS %q`, table))
	})
	return db
}
