package routes

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/router"
	"github.com/hanzoai/dbx"

	v2schema "github.com/hanzoai/iam-v1/cmd/iam-v2/internal/schema"
)

// resp is the canonical v2 response envelope. It preserves the v1
// {status,msg,data} JSON shape (+ data2 for paginated counts) so existing SDK
// clients keep working. Defined ONCE here (projects is the first ported
// entity) and reused by every v2 handler. App errors return HTTP 200 with
// status:"error" (v1 semantics); non-200 is reserved for transport failures.
type resp struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Data   any    `json:"data"`
	Data2  any    `json:"data2,omitempty"`
}

// getId / splitId mirror util.GetId / util.GetOwnerAndNameFromIdWithError,
// inlined so cmd/iam-v2 stays free of the root iam module. Shared by every
// composite-key entity.
func getId(owner, name string) string { return owner + "/" + name }

func splitId(id string) (owner, name string, err error) {
	tokens := strings.Split(id, "/")
	if len(tokens) != 2 {
		return "", "", errors.New("wrong token count for ID: " + id)
	}
	return tokens[0], tokens[1], nil
}

// affectedString renders v1's wrapActionResponse Data payload.
func affectedString(affected bool) string {
	if affected {
		return "Affected"
	}
	return "Unaffected"
}

// projectFields is the closed whitelist of columns a client may filter/sort by
// — the field NAME cannot be a bind param, so it must be validated against a
// fixed set to prevent filter/sort injection (stricter than v1's regex gate).
var projectFields = map[string]bool{
	"owner": true, "name": true, "createdTime": true, "displayName": true,
	"description": true, "organization": true, "tags": true, "metadata": true,
	"isDefault": true,
}

func projectFilterField(field string) bool { return projectFields[field] }

// projectSort maps v1 GetSession's (sortField,sortOrder) to a Base sort token.
// Default is "-createdTime" (v1 Desc(created_time)); "ascend" flips direction.
func projectSort(sortField, sortOrder string) string {
	if sortField == "" || sortOrder == "" || !projectFilterField(sortField) {
		return "-createdTime"
	}
	if sortOrder == "ascend" {
		return sortField
	}
	return "-" + sortField
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// projectFromRecord maps a Base record to the typed wire struct.
func projectFromRecord(r *core.Record) v2schema.Project {
	return v2schema.Project{
		Id:           r.Id,
		Owner:        r.GetString("owner"),
		Name:         r.GetString("name"),
		CreatedTime:  r.GetString("createdTime"),
		DisplayName:  r.GetString("displayName"),
		Description:  r.GetString("description"),
		Organization: r.GetString("organization"),
		Tags:         r.GetStringSlice("tags"),
		Metadata:     r.GetString("metadata"),
		IsDefault:    r.GetBool("isDefault"),
	}
}

func projectsFromRecords(recs []*core.Record) []v2schema.Project {
	out := make([]v2schema.Project, 0, len(recs))
	for _, r := range recs {
		out = append(out, projectFromRecord(r))
	}
	return out
}

// setProjectFields writes the mutable columns from the wire struct onto a
// record. owner/name come from the authoritative caller (URL id on update,
// body on create); createdTime is owned by the AutodateField (OnCreate) and is
// never set here.
func setProjectFields(rec *core.Record, in v2schema.Project, owner, name string) {
	rec.Set("owner", owner)
	rec.Set("name", name)
	rec.Set("displayName", in.DisplayName)
	rec.Set("description", in.Description)
	rec.Set("organization", in.Organization)
	rec.Set("tags", []string(in.Tags))
	rec.Set("metadata", in.Metadata)
	rec.Set("isDefault", in.IsDefault)
}

// mountProjects registers the project routes on the single /v1/iam/v2 group.
// Called from routes.Mount — NOT a parallel mounter; it binds verb lines on
// the existing group:
//
//	func Mount(r *router.Router[*core.RequestEvent]) {
//	    g := r.Group("/v1/iam/v2")
//	    g.GET("/health", health)
//	    mountProjects(g)
//	    // … other entities …
//	}
func mountProjects(g *router.RouterGroup[*core.RequestEvent]) {
	g.GET("/projects", listProjects)                          // <- get-projects
	g.GET("/projects/{id}", getProject)                       // <- get-project?id=
	g.GET("/organization-projects", listOrganizationProjects) // <- get-organization-projects?organization=
	g.POST("/projects", addProject)                           // <- add-project
	g.PUT("/projects/{id}", updateProject)                    // <- update-project?id=
	g.DELETE("/projects/{id}", deleteProject)                 // <- delete-project
}

// listProjects <- GET /v1/iam/get-projects. Owner-scoped, with optional
// whitelisted LIKE (field/value) and snake-free sort. When pageSize+p are
// present the total count rides in data2 (v1 ResponseOk(projects, count)).
func listProjects(e *core.RequestEvent) error {
	q := e.Request.URL.Query()
	owner := q.Get("owner")
	field := q.Get("field")
	value := q.Get("value")

	filter := "owner = {:owner}"
	params := dbx.Params{"owner": owner}
	if field != "" && value != "" && projectFilterField(field) {
		filter += " && " + field + " ~ {:value}"
		params["value"] = value
	}
	sort := projectSort(q.Get("sortField"), q.Get("sortOrder"))

	pageSize := q.Get("pageSize")
	page := q.Get("p")
	if pageSize == "" || page == "" {
		recs, err := e.App.FindRecordsByFilter("projects", filter, sort, 0, 0, params)
		if err != nil {
			return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
		}
		return e.JSON(http.StatusOK, resp{Status: "ok", Data: projectsFromRecords(recs)})
	}

	limit := atoiDefault(pageSize, 0)
	offset := 0
	if p := atoiDefault(page, 1); p > 1 && limit > 0 {
		offset = (p - 1) * limit
	}
	total, err := e.App.CountRecords("projects", projectCountExprs(owner, field, value)...)
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	recs, err := e.App.FindRecordsByFilter("projects", filter, sort, limit, offset, params)
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	return e.JSON(http.StatusOK, resp{Status: "ok", Data: projectsFromRecords(recs), Data2: total})
}

// projectCountExprs builds the same owner (+ optional LIKE) predicate as
// listProjects for the paginated total.
func projectCountExprs(owner, field, value string) []dbx.Expression {
	exprs := []dbx.Expression{dbx.HashExp{"owner": owner}}
	if field != "" && value != "" && projectFilterField(field) {
		exprs = append(exprs, dbx.Like(field, value))
	}
	return exprs
}

// getProject <- GET /v1/iam/get-project?id=. Not-found returns {ok,data:null}
// (v1 getProject returns a nil project via ResponseOk).
func getProject(e *core.RequestEvent) error {
	owner, name, err := splitId(e.Request.PathValue("id"))
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	rec, err := e.App.FindRecordById("projects", getId(owner, name))
	if errors.Is(err, sql.ErrNoRows) {
		return e.JSON(http.StatusOK, resp{Status: "ok", Data: nil})
	}
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	return e.JSON(http.StatusOK, resp{Status: "ok", Data: projectFromRecord(rec)})
}

// listOrganizationProjects <- GET /v1/iam/get-organization-projects. Filters by
// the organization column, Desc(createdTime).
func listOrganizationProjects(e *core.RequestEvent) error {
	organization := e.Request.URL.Query().Get("organization")
	recs, err := e.App.FindRecordsByFilter(
		"projects",
		"organization = {:organization}",
		"-createdTime",
		0, 0,
		dbx.Params{"organization": organization},
	)
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	return e.JSON(http.StatusOK, resp{Status: "ok", Data: projectsFromRecords(recs)})
}

// addProject <- POST /v1/iam/add-project. Save upserts by the synthetic
// owner/name id.
func addProject(e *core.RequestEvent) error {
	var in v2schema.Project
	if err := e.BindBody(&in); err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	col, err := e.App.FindCollectionByNameOrId("projects")
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	rec := core.NewRecord(col)
	rec.Id = getId(in.Owner, in.Name)
	setProjectFields(rec, in, in.Owner, in.Name)
	if err := e.App.Save(rec); err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	return e.JSON(http.StatusOK, resp{Status: "ok", Data: affectedString(true)})
}

// updateProject <- POST /v1/iam/update-project?id=. Read-modify-write in one tx
// (GAP #2: Base Save is whole-record). Missing row -> Unaffected, matching v1
// (existing == nil returns false). owner/name are pinned to the URL id.
func updateProject(e *core.RequestEvent) error {
	owner, name, err := splitId(e.Request.PathValue("id"))
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	var in v2schema.Project
	if err := e.BindBody(&in); err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	affected := false
	err = e.App.RunInTransaction(func(txApp core.App) error {
		rec, ferr := txApp.FindRecordById("projects", getId(owner, name))
		if errors.Is(ferr, sql.ErrNoRows) {
			return nil
		}
		if ferr != nil {
			return ferr
		}
		setProjectFields(rec, in, owner, name)
		affected = true
		return txApp.Save(rec)
	})
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	return e.JSON(http.StatusOK, resp{Status: "ok", Data: affectedString(affected)})
}

// deleteProject <- POST /v1/iam/delete-project. Missing row -> Unaffected.
func deleteProject(e *core.RequestEvent) error {
	owner, name, err := splitId(e.Request.PathValue("id"))
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	rec, err := e.App.FindRecordById("projects", getId(owner, name))
	if errors.Is(err, sql.ErrNoRows) {
		return e.JSON(http.StatusOK, resp{Status: "ok", Data: affectedString(false)})
	}
	if err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	if err := e.App.Delete(rec); err != nil {
		return e.JSON(http.StatusOK, resp{Status: "error", Msg: err.Error()})
	}
	return e.JSON(http.StatusOK, resp{Status: "ok", Data: affectedString(true)})
}
