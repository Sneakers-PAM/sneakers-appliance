// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// progressFile keeps the last stage, apply or revert in Paths.APIDir, so a
// base apply's steps carry over the reboot to the release it boots.
const progressFile = "upgrade-progress.json"

// The steps of an update, as UpgradeStep.id names them.
const (
	stepVerify   = "verify"
	stepStage    = "stage"
	stepSwitch   = "switch"
	stepReboot   = "reboot"
	stepHealth   = "health"
	stepMarkGood = "mark_good"
	stepRestart  = "restart"
)

// The states of a step, as stored.
const (
	statePending = "pending"
	stateActive  = "active"
	stateDone    = "done"
	stateFailed  = "failed"
)

type progressStep struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// progressRecord is one stage, apply or revert, as stored.
type progressRecord struct {
	Action  string         `json:"action"`
	Target  string         `json:"target"`
	Version string         `json:"version,omitempty"`
	Steps   []progressStep `json:"steps"`
	Code    string         `json:"code,omitempty"`
	Started time.Time      `json:"started"`
	Updated time.Time      `json:"updated"`
	// BootID and RebootAt are the boot the reboot step started on and
	// when, for the reboot watchdog.
	BootID   string    `json:"boot_id,omitempty"`
	RebootAt time.Time `json:"reboot_at,omitzero"`
}

// progress holds the record in memory, read from its file the first time.
type progress struct {
	mu     sync.Mutex
	loaded bool
	rec    *progressRecord
	// following is true while a goroutine follows the product coming up;
	// closing stop (Close) ends it, and done counts it.
	following bool
	stop      chan struct{}
	stopped   bool
	done      sync.WaitGroup
}

func (r *progressRecord) find(id string) int {
	for i, s := range r.Steps {
		if s.ID == id {
			return i
		}
	}
	return -1
}

// active is the step in progress, or "".
func (r *progressRecord) active() string {
	for _, s := range r.Steps {
		if s.State == stateActive {
			return s.ID
		}
	}
	return ""
}

func (r *progressRecord) failed() bool {
	for _, s := range r.Steps {
		if s.State == stateFailed {
			return true
		}
	}
	return false
}

// stageLabel is the staging step as the screens show it.
func stageLabel(target osadminv1.UpdateTarget, slot string) string {
	switch {
	case target == osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT:
		return "Staging into the free product slot"
	case slot != "":
		return "Staging into slot " + slot
	}
	return "Staging into the other slot"
}

// stepsFor are an action's steps, all pending: a stage or an apply runs
// them all, a revert has no file to verify or stage, and a stage whose
// target isn't known yet (its header isn't read) has only verifying.
func stepsFor(action string, target osadminv1.UpdateTarget, slot string, followUp bool) []progressStep {
	product := target == osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
	if target == osadminv1.UpdateTarget_UPDATE_TARGET_UNSPECIFIED {
		return []progressStep{{ID: stepVerify, Label: "Verifying (signature, channel, SHA-256)", State: statePending}}
	}
	var out []progressStep
	if action != "revert" {
		out = append(out, progressStep{ID: stepVerify, Label: "Verifying (signature, channel, SHA-256)"}, progressStep{ID: stepStage, Label: stageLabel(target, slot)})
	}
	out = append(out, progressStep{ID: stepSwitch, Label: "Switching slots"})
	if product {
		out = append(out, progressStep{ID: stepRestart, Label: "Restarting the product"})
		if followUp {
			out = append(out, productUpSteps...)
		}
	} else {
		out = append(out, progressStep{ID: stepReboot, Label: "Rebooting"}, progressStep{ID: stepHealth, Label: "Checking health"}, progressStep{ID: stepMarkGood, Label: "Marking good"})
	}
	for i := range out {
		out[i].State = statePending
	}
	return out
}

// interrupted are the steps osadmin runs itself, start to end, in one
// call: one found active when osadmin starts was cut off. A switch or a
// reboot found active is the reboot the apply ended in.
var interrupted = map[string]bool{stepVerify: true, stepStage: true, stepRestart: true}

// loadProgress reads the record once, failing a step osadmin was cut off
// in the middle of.
func (s *Server) loadProgress() {
	if s.progress.loaded {
		return
	}
	s.progress.loaded = true
	b, err := os.ReadFile(s.ownPath(progressFile)) // #nosec G304 -- osadmin's own file
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.o.Logger.Warn("osadmin: the update progress doesn't read", log.F("error", err.Error()))
		}
		return
	}
	var r progressRecord
	if err := json.Unmarshal(b, &r); err != nil {
		s.o.Logger.Warn("osadmin: the update progress doesn't parse; ignored", log.F("error", err.Error()))
		return
	}
	s.progress.rec = &r
	if a := r.active(); interrupted[a] {
		s.o.Logger.Warn("osadmin: an update step was cut off by a restart", log.F("step", a), log.F("version", r.Version))
		s.failStepLocked(a, "osadmin restarted before this step finished; try again", "")
	}
}

func (s *Server) saveProgressLocked() {
	r := s.progress.rec
	r.Updated = s.o.Clock.Now().UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	if err := os.MkdirAll(s.o.Paths.APIDir(), 0o700); err != nil {
		s.o.Logger.Error(err, "osadmin: the update progress wasn't saved")
		return
	}
	if err := writeAtomic(s.ownPath(progressFile), b); err != nil {
		s.o.Logger.Error(err, "osadmin: the update progress wasn't saved")
	}
}

// beginProgress starts a new record for action, every step pending.
func (s *Server) beginProgress(action string, target osadminv1.UpdateTarget, version, slot string) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	s.newRecordLocked(action, target, version, slot)
	s.saveProgressLocked()
}

// recordTarget is a record's target as stored: "" while a stage hasn't
// read its file's header.
func recordTarget(t osadminv1.UpdateTarget) string {
	if t == osadminv1.UpdateTarget_UPDATE_TARGET_UNSPECIFIED {
		return ""
	}
	return targetName(t)
}

func (s *Server) newRecordLocked(action string, target osadminv1.UpdateTarget, version, slot string) {
	s.progress.rec = &progressRecord{Action: action, Target: recordTarget(target), Version: version, Steps: stepsFor(action, target, slot, s.o.ProductUp != nil), Started: s.o.Clock.Now().UTC()}
	s.o.Logger.Info("osadmin: update progress begins", log.F("action", action), log.F("target", recordTarget(target)), log.F("version", version))
}

// continueApply carries a stage's record on into its apply, or starts one
// with verifying and staging done when the stage isn't the last record (an
// earlier release staged it, say).
func (s *Server) continueApply(target osadminv1.UpdateTarget, version, slot string) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	if r := s.progress.rec; r != nil && r.Action == "stage" && r.Target == targetName(target) && r.Version == version && !r.failed() && r.active() == "" {
		r.Action = "apply"
		s.o.Logger.Info("osadmin: update progress goes on from the stage", log.F("version", version))
		s.saveProgressLocked()
		return
	}
	s.newRecordLocked("apply", target, version, slot)
	for i, st := range s.progress.rec.Steps {
		if st.ID == stepVerify || st.ID == stepStage {
			s.progress.rec.Steps[i].State = stateDone
		}
	}
	s.saveProgressLocked()
}

// setVersion names the release once a stage has read the file's header.
func (s *Server) setVersion(v string) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	if r := s.progress.rec; r != nil {
		r.Version = v
		s.saveProgressLocked()
	}
}

// setStep makes id the active step with detail, every step before it
// done. A step that isn't in the record is ignored.
func (s *Server) setStep(id, detail string) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	r := s.progress.rec
	if r == nil {
		return
	}
	at := r.find(id)
	if at < 0 {
		return
	}
	for i := range r.Steps {
		switch {
		case i < at:
			r.Steps[i].State, r.Steps[i].Detail = stateDone, ""
		case i == at:
			if r.Steps[i].State != stateActive || r.Steps[i].Detail != detail {
				s.o.Logger.Info("osadmin: update step", log.F("step", id), log.F("detail", detail), log.F("version", r.Version))
			}
			if id == stepReboot && r.Steps[i].State != stateActive {
				r.BootID, r.RebootAt = s.o.BootID, s.o.Clock.Now().UTC()
			}
			r.Steps[i].State, r.Steps[i].Detail = stateActive, detail
		case r.Steps[i].State == stateActive:
			// The product came up to a later step and went back (a pod
			// fell over): the later step waits again.
			r.Steps[i].State, r.Steps[i].Detail = statePending, ""
		}
	}
	s.saveProgressLocked()
}

// failStep marks id failed with why; the steps after it stay pending.
func (s *Server) failStep(id string, err error) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	if s.progress.rec == nil {
		return
	}
	s.failStepLocked(id, describe(err), failureCode(err))
}

// failActive fails the active step of an action's record with err: the
// step a stage was on when it was refused.
func (s *Server) failActive(action string, err error) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	r := s.progress.rec
	if r == nil || r.Action != action {
		return
	}
	if a := r.active(); a != "" {
		s.failStepLocked(a, describe(err), failureCode(err))
	}
}

// describedCodeRE finds a code in a daemon's description of a refusal,
// "UPGRADE_UNPREDICTABLE (2502): ...", passed on as a Connect error.
var describedCodeRE = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+ \((\d+)\)`)

// failureCode is err's code symbol, or "" when it has none.
func failureCode(err error) string {
	if c, ok := codes.Of(err); ok {
		return codes.Symbol(c)
	}
	if m := describedCodeRE.FindStringSubmatch(err.Error()); m != nil {
		if n, cerr := strconv.Atoi(m[1]); cerr == nil {
			return codes.Symbol(n)
		}
	}
	return ""
}

func (s *Server) failStepLocked(id, why, code string) {
	r := s.progress.rec
	at := r.find(id)
	if at < 0 {
		return
	}
	for i := range r.Steps {
		switch {
		case i < at:
			r.Steps[i].State, r.Steps[i].Detail = stateDone, ""
		case i == at:
			r.Steps[i].State, r.Steps[i].Detail = stateFailed, why
		case r.Steps[i].State == stateActive:
			r.Steps[i].State, r.Steps[i].Detail = statePending, ""
		}
	}
	r.Code = code
	s.o.Logger.Warn("osadmin: update step failed", log.F("step", id), log.F("version", r.Version), log.F("code", code), log.F("why", why))
	s.saveProgressLocked()
}

// finishSteps marks every step through last done: the end of a stage
// (through staging) or of the whole update.
func (s *Server) finishSteps(last string) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	r := s.progress.rec
	if r == nil {
		return
	}
	at := r.find(last)
	if at < 0 {
		return
	}
	for i := 0; i <= at; i++ {
		r.Steps[i].State, r.Steps[i].Detail = stateDone, ""
	}
	s.o.Logger.Info("osadmin: update steps done", log.F("through", last), log.F("action", r.Action), log.F("version", r.Version))
	s.saveProgressLocked()
}

// progressSnapshot is a copy of the record, or nil.
func (s *Server) progressSnapshot() *progressRecord {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	if s.progress.rec == nil {
		return nil
	}
	c := *s.progress.rec
	c.Steps = append([]progressStep(nil), c.Steps...)
	return &c
}

var stepStates = map[string]osadminv1.UpgradeStepState{
	statePending: osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_PENDING,
	stateActive:  osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_ACTIVE,
	stateDone:    osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_DONE,
	stateFailed:  osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED,
}

// progressToWire is the record for GetUpgrades and GetStatus. img is
// init's image status, read anyway by both: while a base release is
// written into its slot, it gives the staging step's bytes.
func (s *Server) progressToWire(img *initv1.ImageServiceStatusResponse) *osadminv1.UpgradeProgress {
	r := s.progressSnapshot()
	if r == nil {
		return nil
	}
	target := osadminv1.UpdateTarget_UPDATE_TARGET_BASE
	switch r.Target {
	case "product":
		target = osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
	case "":
		target = osadminv1.UpdateTarget_UPDATE_TARGET_UNSPECIFIED
	}
	out := &osadminv1.UpgradeProgress{Action: r.Action, Target: target, Version: r.Version, Code: r.Code, StartedAt: timestamppb.New(r.Started), UpdatedAt: timestamppb.New(r.Updated)}
	for _, st := range r.Steps {
		w := &osadminv1.UpgradeStep{Id: st.ID, Label: st.Label, State: stepStates[st.State], Detail: st.Detail}
		if st.ID == stepStage && st.State == stateActive && target == osadminv1.UpdateTarget_UPDATE_TARGET_BASE && img.GetStageTotalBytes() > 0 {
			w.DoneBytes, w.TotalBytes = img.GetStageWrittenBytes(), img.GetStageTotalBytes()
		}
		switch st.State {
		case stateActive:
			out.InProgress = true
		case stateFailed:
			out.Failed = true
		}
		out.Steps = append(out.Steps, w)
	}
	return out
}

// publicProgress is the record for the public GetPhase, for the restart
// page before anyone signs in: the steps' ids, labels and states only,
// while the update is in progress or for MaintenanceBound after it ended.
func (s *Server) publicProgress() *osadminv1.UpgradeProgress {
	full := s.progressToWire(nil)
	if full == nil || (!full.GetInProgress() && s.o.Clock.Now().Sub(full.GetUpdatedAt().AsTime()) > MaintenanceBound) {
		return nil
	}
	out := &osadminv1.UpgradeProgress{Action: full.GetAction(), Target: full.GetTarget(), InProgress: full.GetInProgress(), Failed: full.GetFailed()}
	for _, st := range full.GetSteps() {
		out.Steps = append(out.Steps, &osadminv1.UpgradeStep{Id: st.GetId(), Label: st.GetLabel(), State: st.GetState()})
	}
	return out
}
