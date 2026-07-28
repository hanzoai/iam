# Mutation table for hanzoai/iam. The engine is cloud's scripts/mutate.py, which is
# strict-scored (a mutant that fails to COMPILE, or whose anchor drifted, or whose
# -run matched nothing, is a hard FAILURE and never a kill). This file is only the
# data: which property to break, and which test must go red when it does.
#
#   MUTATE_ROOT=<iam tree> MUTATE_TABLE=<this file> <cloud>/scripts/mutate.py [filter]
#
# Every row here breaks one clause of a single sentence: consent to train is an
# explicit "granted" and nothing else, and the absence of an answer is a refusal.

C = "pkg/schema/consent.go"
PS = "./pkg/schema/"

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
]
