# Mutation table for hanzoai/iam. The engine is scripts/mutate.py NEXT TO THIS
# FILE, which is strict-scored (a mutant that fails to COMPILE, or whose anchor
# drifted, or whose -run matched nothing, is a hard FAILURE and never a kill).
# This file is only the data: which property to break, and which test must go red
# when it does.
#
#   scripts/mutate.py [name-substring-filter]
#
# The engine lives here rather than in a sibling repo because a score nobody can
# reproduce from this checkout is a claim, not a measurement.
#
# Two sentences are under test. The FIRST: consent to train is an explicit
# "granted" and nothing else, and the absence of an answer is a refusal. The
# SECOND: that answer has exactly one writer — the person it is about — so no
# other write path may forge it, destroy it, or answer a question the request
# never asked, and the evidence for it cannot be authored or erased by anyone.

C = "pkg/schema/consent.go"
G = "internal/oidc/signup.go"
U = "internal/users/users.go"
P = "internal/oidc/preferences.go"
T = "internal/oidc/consent.go"
A = "internal/auditlogs/auditlogs.go"
PS = "./pkg/schema/"
PO = "./internal/oidc/"
PU = "./internal/users/"
PA = "./internal/auditlogs/"

MUTANTS = [
    # The default. If a first-ever read defaults to a grant, every user who was
    # never asked becomes trainable — the exact failure the tri-state exists to
    # prevent.
    ("consent: silence defaults to a GRANT", [
        (C, "c := Consent{Insights: true, Training: Unanswered}",
            "c := Consent{Insights: true, Training: Granted}")],
     "TestSilenceIsRefusal", PS),

    # The predicate itself, widened from "is granted" to "is not an explicit
    # refusal" — the plausible-looking bug that admits everyone who never answered.
    ("consent: predicate admits anything not refused", [
        (C, "func (c Consent) MayTrain() bool { return c.Training == Granted }",
            "func (c Consent) MayTrain() bool { return c.Training != Refused }")],
     "TestSilenceIsRefusal", PS),

    # The predicate widened the other way — any non-empty answer passes.
    ("consent: predicate admits any non-empty answer", [
        (C, "func (c Consent) MayTrain() bool { return c.Training == Granted }",
            "func (c Consent) MayTrain() bool { return c.Training != Unanswered }")],
     "TestOnlyGrantedGrants", PS),

    # Normalization of an unrecognized token. Without it a value like "yes" stays
    # in the record and can be written back to the store by Encode, where a later
    # reader gets to decide what it meant.
    ("consent: an unknown answer is left in the record", [
        (C, "\tif !c.Training.Valid() {\n\t\tc.Training = Unanswered\n\t}\n",
            "")],
     "TestOnlyGrantedGrants", PS),

    # The write boundary. If Valid admits everything, the HTTP surface persists
    # whatever a client sends.
    ("consent: the write boundary accepts any answer", [
        (C, "return a == Unanswered || a == Granted || a == Refused",
            "return true")],
     "TestAnswerValid", PS),

    # The tri-state collapsing back to two states: a refusal recorded as silence is
    # indistinguishable from never having been asked, so the screen would ask again
    # forever and a deliberate "no" would be unprovable.
    ("consent: a refusal is recorded as silence", [
        (C, "\tGranted    Answer = \"granted\"\n\tRefused    Answer = \"refused\"",
            "\tGranted    Answer = \"granted\"\n\tRefused    Answer = \"\"")],
     "TestRefusalIsRefusal", PS),

    # The accessor reading a different property than the writer writes.
    ("consent: the accessor reads the wrong property", [
        (C, "func (u *User) Consent() Consent { return ConsentOf(u.Properties[PreferencesKey]) }",
            "func (u *User) Consent() Consent { return ConsentOf(u.Properties[\"preferences\"]) }")],
     "TestUserConsent", PS),

    # The write half clobbering the rest of the preferences blob — a consent write
    # that silently drops a user's theme and pinned items.
    ("consent: the write clobbers unrelated keys", [
        (C, "\tmerged := map[string]json.RawMessage{}\n\tif prefs != \"\" {\n\t\t_ = json.Unmarshal([]byte(prefs), &merged)\n\t}",
            "\tmerged := map[string]json.RawMessage{}\n")],
     "TestEncodePreservesOtherKeys", PS),

    # The signup screen is where the answer is collected. If the handler records a
    # grant regardless of what the screen sent, every new account is trainable and
    # the screen is decoration.
    ("consent: signup records a grant regardless of the answer", [
        (G, "consent := schema.Consent{Insights: true, Training: schema.Answer(f.Training)}",
            "consent := schema.Consent{Insights: true, Training: schema.Granted}")],
     "TestSignup_SilenceIsRefusal|TestSignup_RefusalIsRecorded", PO),

    # An unknown answer reaching the record through signup now takes TWO gates
    # falling: the screen's own boundary check, and the store's refusal to encode
    # an answer it cannot read. Removing either alone leaves the property standing
    # — which is the point of having both, and why this mutant breaks the pair.
    # A single-edit version of this row SURVIVES, correctly, and a runner that
    # scored it a kill would be reporting depth this system has as depth it lacks.
    ("consent: signup accepts an unknown answer (both gates)", [
        (G, "\t\tif !consent.Training.Valid() {\n\t\t\treturn httpx.Err(c, \"training must be one of: \\\"\\\", granted, refused\")\n\t\t}\n",
            ""),
        (C, "\tif !c.Training.Valid() {\n\t\treturn nil, fmt.Errorf(",
            "\tif false && !c.Training.Valid() {\n\t\treturn nil, fmt.Errorf(")],
     "TestSignup_UnknownAnswerIsRejected", PO),

    # The answer has to REACH the create path. Signup is the one caller entitled to
    # state one, and it says so by filling the off-the-wire seam; dropping the
    # answer there discards what the screen collected while still creating the
    # account, which looks like success from every angle except the record.
    ("consent: signup drops the answer the screen collected", [
        (G, "\t\t\tConsent: &consent,",
            "\t\t\tConsent: nil,")],
     "TestSignup_GrantIsRecorded", PO),

    # --- the SECOND sentence: one writer, and evidence nobody else can author ---

    # The full-row update carrying the stored answer. Without it a body that names
    # a consent FORGES one, and a body with no properties at all DESTROYS one —
    # the same missing line is both attacks, which is why one mutant kills two
    # tests.
    ("one-writer: a full-row update takes consent from the body", [
        (U, "\tif err := u.CarryConsentFrom(existing); err != nil {\n\t\treturn nil, zip.ErrInternal(err.Error())\n\t}\n",
            "")],
     "TestUpdateCannotForgeAConsent|TestUpdateCannotDestroyAConsent", PU),

    # The create path dropping a caller-supplied answer. Provisioning is done BY
    # somebody, never by the person the answer is about, so a consent in a create
    # body is an assertion on another's behalf.
    ("one-writer: a create body may assert a consent", [
        (U, "\tif err := u.SetConsent(in.Consent); err != nil {\n\t\treturn nil, zip.ErrBadRequest(err.Error())\n\t}\n",
            "")],
     "TestCreateDropsACallerSuppliedConsent", PU),

    # The preferences surface refusing the one key that is not a preference.
    # Without it there is a second, unvalidated, unaudited writer of the record.
    ("one-writer: preferences can write the consent key", [
        (P, "\tif _, ok := patchMap[schema.ConsentKey]; ok {\n\t\treturn \"\", nil, fmt.Errorf(\"consent is not a preference; use PUT %s to answer\", PathConsent)\n\t}\n",
            "")],
     "TestPreferencesRefusesTheConsentKey", PO),

    # The tri-state on the wire. Collapsing "absent" into the zero value makes a
    # save of one switch silently answer the other question — the person answers
    # one thing and has a second answer changed for them.
    ("one-writer: an absent field answers its question anyway", [
        (T, "\t\t\tif in.Insights != nil {\n\t\t\t\tnext.Insights = *in.Insights\n\t\t\t}\n",
            "\t\t\tnext.Insights = in.Insights != nil && *in.Insights\n")],
     "TestConsentPutLeavesAnUnaskedQuestionAlone", PO),

    # The write half refusing what the read half normalizes. Without it an answer
    # this version cannot interpret is persisted for a later reader to guess at.
    ("one-writer: the write half stores an answer it cannot read", [
        (C, "\tif !c.Training.Valid() {\n\t\treturn nil, fmt.Errorf(",
            "\tif false && !c.Training.Valid() {\n\t\treturn nil, fmt.Errorf(")],
     "TestEncodeRefusesAnAnswerItWouldHaveToNormalize", PS),

    # The audit covering the WHOLE record. Narrowing it back to the training
    # answer leaves an insights withdrawal unevidenced — a consent event with no
    # trail, which is the state Article 7(1) asks us not to be in.
    ("evidence: only the training answer is audited", [
        (T, "\tif from == to {\n\t\treturn nil\n\t}\n",
            "\tif from.Training == to.Training {\n\t\treturn nil\n\t}\n")],
     "TestConsentChangeIsAudited", PO),

    # The ingress address staying out of the row. It identifies our own pod, not
    # the person, while still being personal data with a retention obligation.
    ("evidence: the audit row records the ingress address", [
        (T, "\tlog.StatusCode = 200\n",
            "\tlog.ClientIp = c.Fiber().IP()\n\tlog.StatusCode = 200\n")],
     "TestConsentChangeIsAudited", PO),

    # The reserved namespace on the way in. Without it an org admin mints a
    # consent-training row granting permission nobody gave, indistinguishable
    # from the one the consent endpoint writes.
    ("evidence: the audit CRUD can forge a platform row", [
        (A, "\tif err := refusePlatformAction(in.Action); err != nil {\n\t\treturn nil, err\n\t}\n\tswitch _, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name)); {",
            "\tswitch _, err := orm.Get[schema.AuditLog](h.db, key(in.Owner, in.Name)); {")],
     "TestCreateRefusesAPlatformAction", PA),

    # And on the way out. A row recording a refusal is exactly the row an
    # interested party would want gone.
    ("evidence: the audit CRUD can delete a platform row", [
        (A, "\tif err := refusePlatformAction(log.Action); err != nil {\n\t\treturn nil, err\n\t}\n\tif err := log.DeleteCtx",
            "\tif err := log.DeleteCtx")],
     "TestDeleteRefusesAPlatformRow", PA),
]
