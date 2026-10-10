// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productimport runs a product's import of an earlier install
// (docs/import.md): the import directory on the state volume holds the
// import key, which is made on the box and never leaves it, the uploaded
// export and mapping files, and each step's output. Each step runs as a
// Job from the product bundle's template, written into the import stack
// that k0s applies. The steps run sneakers-migrate: review, mapping
// (convert or check), import and verify.
package productimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The files of the import directory.
const (
	KeyFile       = "import.key"
	RecipientFile = "recipient"
	OutDir        = "out"
	runsFile      = "runs.json"
	// MaxFile bounds an upload: an export of a large install fits well.
	MaxFile = 2 << 30
	// maxOutput is how much of a step's output is shown.
	maxOutput = 256 << 10
)

// Kind is an uploaded file's kind, and its fixed name.
type Kind string

// The uploads.
const (
	Bundle  Kind = "bundle"
	Mapping Kind = "mapping"
	Sheet   Kind = "sheet"
	Types   Kind = "types"
)

var fileNames = map[Kind]string{Bundle: "bundle.age", Mapping: "mapping.json", Sheet: "sheet.tsv", Types: "types.json"}

// FileName is a kind's file name, or false for an unknown kind.
func FileName(k Kind) (string, bool) { n, ok := fileNames[k]; return n, ok }

// Step is one sneakers-migrate run.
type Step string

// The steps, in their usual order.
const (
	Review  Step = "review"
	Convert Step = "convert"
	Check   Step = "check"
	Import  Step = "import"
	Verify  Step = "verify"
)

// Options are a step's choices.
type Options struct {
	// Rehearsal, Wipe and OwnerEmail are import's --rehearsal,
	// --wipe-target and --owner-email.
	Rehearsal  bool
	Wipe       bool
	OwnerEmail string
	// Parent and Personal are mapping --tsv's --new-folder-parent and
	// --personal.
	Parent   string
	Personal string
}

// Run is one step's Job and how it went.
type Run struct {
	Job     string    `json:"job"`
	Step    Step      `json:"step"`
	Options Options   `json:"options"`
	Started time.Time `json:"started"`
	// Set from the output files when Runs reads them.
	Finished  time.Time `json:"-"`
	Done      bool      `json:"-"`
	Exit      int       `json:"-"`
	Output    string    `json:"-"`
	HasOwner  bool      `json:"-"`
	Report    []byte    `json:"-"`
	ReviewDoc []byte    `json:"-"`
	Template  []byte    `json:"-"`
}

// Manager is the box's import directory and the import stack.
type Manager struct {
	// Dir is the import directory (the Job's /import).
	Dir string
	// UID owns Dir and its files: the Job's user.
	UID int
	// Stack is the directory of the import stack in front of k0s
	// (<manifests>/<stack>); a step's Job is written there.
	Stack string
	// Template is the bundle's Job template.
	Template string
	Clock    clock.Clock
	Logger   log.Logger
	// chown is os.Chown; tests run unprivileged.
	Chown func(path string, uid, gid int) error

	mu sync.Mutex
}

func (m *Manager) lg() log.Logger {
	if m.Logger == nil {
		return log.Nop()
	}
	return m.Logger
}

func (m *Manager) now() time.Time {
	if m.Clock == nil {
		return time.Now()
	}
	return m.Clock.Now()
}

func (m *Manager) own(path string) error {
	ch := m.Chown
	if ch == nil {
		ch = os.Chown
	}
	return ch(path, m.UID, m.UID)
}

// Open makes the import directory and the import key, once, and returns
// the key's recipient, which the export is encrypted to.
func (m *Manager) Open() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range []string{m.Dir, filepath.Join(m.Dir, OutDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", fmt.Errorf("productimport: %w", err)
		}
		if err := m.own(d); err != nil {
			return "", fmt.Errorf("productimport: %w", err)
		}
	}
	if r, err := os.ReadFile(filepath.Join(m.Dir, RecipientFile)); err == nil { // #nosec G304 -- the box's own file
		return strings.TrimSpace(string(r)), nil
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("productimport: %w", err)
	}
	key := filepath.Join(m.Dir, KeyFile)
	if err := os.WriteFile(key, []byte(id.String()+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("productimport: %w", err)
	}
	if err := m.own(key); err != nil {
		return "", fmt.Errorf("productimport: %w", err)
	}
	rcpt := id.Recipient().String()
	if err := os.WriteFile(filepath.Join(m.Dir, RecipientFile), []byte(rcpt+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("productimport: %w", err)
	}
	m.lg().Info("productimport: import opened; the import key was made on the box", log.F("recipient", rcpt))
	return rcpt, nil
}

// Recipient is the open import's recipient, or "" when none is open.
func (m *Manager) Recipient() string {
	r, err := os.ReadFile(filepath.Join(m.Dir, RecipientFile)) // #nosec G304 -- the box's own file
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(r))
}

// File is an uploaded file present in the import directory.
type File struct {
	Kind Kind
	Size int64
	At   time.Time
}

// Files lists the uploads present.
func (m *Manager) Files() []File {
	var out []File
	for _, k := range []Kind{Bundle, Mapping, Sheet, Types} {
		if st, err := os.Stat(filepath.Join(m.Dir, fileNames[k])); err == nil {
			out = append(out, File{Kind: k, Size: st.Size(), At: st.ModTime()})
		}
	}
	return out
}

// Save stores an upload under its kind's name, replacing an earlier one.
func (m *Manager) Save(k Kind, r io.Reader) (int64, error) {
	name, ok := fileNames[k]
	if !ok {
		return 0, codes.New(codes.NotAvailable, "an import takes a bundle, a mapping file, a proposal sheet or type rules, not %q", k)
	}
	if m.Recipient() == "" {
		return 0, codes.New(codes.NotAvailable, "no import is open; open one first")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	final := filepath.Join(m.Dir, name)
	tmp := final + ".part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- a fixed name in the import directory
	if err != nil {
		return 0, fmt.Errorf("productimport: %w", err)
	}
	n, err := io.Copy(f, io.LimitReader(r, MaxFile+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > MaxFile {
		err = fmt.Errorf("the file is over %d bytes", int64(MaxFile))
	}
	if err == nil {
		err = m.own(tmp)
	}
	if err == nil {
		err = os.Rename(tmp, final)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("productimport: %s: %w", k, err)
	}
	m.lg().Info("productimport: file saved", log.F("kind", string(k)), log.F("bytes", n))
	return n, nil
}

var emailRE = regexp.MustCompile(`^[^\s@"]+@[^\s@"]+$`)

// args are the step's sneakers-migrate arguments, with the import
// directory at /import.
func args(step Step, job string, o Options, has map[Kind]bool) ([]string, error) {
	const dir = "/import/"
	base := []string{"--bundle", dir + fileNames[Bundle], "--identity", dir + KeyFile}
	need := func(k Kind) error {
		if !has[k] {
			return codes.New(codes.NotAvailable, "the %s step needs the %s uploaded first", step, k)
		}
		return nil
	}
	if err := need(Bundle); err != nil {
		return nil, err
	}
	out := dir + OutDir + "/" + job
	switch step {
	case Review:
		return append(append([]string{"review"}, base...), "--report", out+".review.json", "--template", out+".template.json"), nil
	case Convert:
		if err := need(Sheet); err != nil {
			return nil, err
		}
		a := append(append([]string{"mapping"}, base...), "--tsv", dir+fileNames[Sheet], "--out", dir+fileNames[Mapping])
		if has[Types] {
			a = append(a, "--types", dir+fileNames[Types])
		}
		if o.Parent != "" {
			a = append(a, "--new-folder-parent", o.Parent)
		}
		if o.Personal != "" {
			if !emailRE.MatchString(o.Personal) {
				return nil, codes.New(codes.NotAvailable, "%q isn't an email address", o.Personal)
			}
			a = append(a, "--personal", o.Personal)
		}
		return a, nil
	case Check:
		if err := need(Mapping); err != nil {
			return nil, err
		}
		return append(append([]string{"mapping"}, base...), "--check", dir+fileNames[Mapping]), nil
	case Import:
		if err := need(Mapping); err != nil && !o.Rehearsal {
			return nil, err
		}
		a := append(append([]string{"import"}, base...), "--report", out+".report.json")
		if has[Mapping] {
			a = append(a, "--mapping", dir+fileNames[Mapping])
		}
		if o.Rehearsal {
			a = append(a, "--rehearsal")
		}
		if o.Wipe {
			a = append(a, "--wipe-target")
		}
		if o.OwnerEmail != "" {
			if !emailRE.MatchString(o.OwnerEmail) {
				return nil, codes.New(codes.NotAvailable, "%q isn't an email address", o.OwnerEmail)
			}
			a = append(a, "--owner-email", o.OwnerEmail)
		}
		return a, nil
	case Verify:
		a := append(append([]string{"verify"}, base...), "--report", out+".report.json")
		if has[Mapping] {
			a = append(a, "--mapping", dir+fileNames[Mapping])
		}
		return a, nil
	}
	return nil, codes.New(codes.NotAvailable, "there is no import step %q", step)
}

// Start runs a step: its Job goes into the import stack, for k0s to apply.
// One step runs at a time.
func (m *Manager) Start(step Step, o Options) (Run, error) {
	if m.Recipient() == "" {
		return Run{}, codes.New(codes.NotAvailable, "no import is open; open one first")
	}
	runs, err := m.Runs()
	if err != nil {
		return Run{}, err
	}
	for _, r := range runs {
		if !r.Done {
			return Run{}, codes.New(codes.NotAvailable, "the %s step (%s) is still running; wait for it to finish", r.Step, r.Job)
		}
	}
	has := map[Kind]bool{}
	for _, f := range m.Files() {
		has[f.Kind] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job := fmt.Sprintf("sneakers-migrate-%s-%d", step, len(runs)+1)
	a, err := args(step, job, o, has)
	if err != nil {
		return Run{}, err
	}
	if step == Convert {
		// mapping --tsv writes a new file and refuses an existing one.
		if err := os.Rename(filepath.Join(m.Dir, fileNames[Mapping]), filepath.Join(m.Dir, fileNames[Mapping]+".prev")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Run{}, fmt.Errorf("productimport: %w", err)
		}
	}
	tpl, err := os.ReadFile(m.Template)
	if err != nil {
		return Run{}, codes.New(codes.NotAvailable, "the installed product carries no import Job template: %v", err)
	}
	argv, _ := json.Marshal(a)
	doc := strings.NewReplacer("${JOB_NAME}", job, "${ARGS}", string(argv), "${HOST_DIR}", m.Dir).Replace(string(tpl))
	if err := os.MkdirAll(m.Stack, 0o755); err != nil { // #nosec G301 -- k0s's stack directory
		return Run{}, fmt.Errorf("productimport: %w", err)
	}
	r := Run{Job: job, Step: step, Options: o, Started: m.now().UTC()}
	runs = append(runs, r)
	if err := m.writeRuns(runs); err != nil {
		return Run{}, err
	}
	if err := os.WriteFile(filepath.Join(m.Stack, "job-"+job+".yaml"), []byte(doc), 0o644); err != nil { // #nosec G306 G703 -- a stack k0s reads; the job name is built from a checked step
		return Run{}, fmt.Errorf("productimport: %w", err)
	}
	m.lg().Info("productimport: step started", log.F("step", string(step)), log.F("job", job), log.F("rehearsal", o.Rehearsal), log.F("wipe", o.Wipe))
	return r, nil
}

func (m *Manager) writeRuns(runs []Run) error {
	b, err := json.Marshal(runs)
	if err != nil {
		return err
	}
	p := filepath.Join(m.Dir, runsFile)
	if err := os.WriteFile(p+".new", b, 0o600); err != nil {
		return fmt.Errorf("productimport: %w", err)
	}
	return os.Rename(p+".new", p)
}

// Runs are the open import's steps, oldest first, with what each printed.
func (m *Manager) Runs() ([]Run, error) {
	b, err := os.ReadFile(filepath.Join(m.Dir, runsFile)) // #nosec G304 -- the box's own file
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("productimport: %w", err)
	}
	var runs []Run
	if err := json.Unmarshal(b, &runs); err != nil {
		return nil, fmt.Errorf("productimport: %w", err)
	}
	out := filepath.Join(m.Dir, OutDir)
	for i := range runs {
		r := &runs[i]
		base := filepath.Join(out, r.Job)
		if b, err := readCapped(base + ".txt"); err == nil {
			r.Output = ansiCodes.ReplaceAllString(b, "")
		}
		if b, err := os.ReadFile(base + ".txt.exit"); err == nil { // #nosec G304 -- the box's own file
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				r.Done, r.Exit = true, n
				if st, err := os.Stat(base + ".txt.exit"); err == nil {
					r.Finished = st.ModTime().UTC()
				}
			}
		}
		_, err := os.Stat(base + ".owner")
		r.HasOwner = err == nil
		r.Report, _ = os.ReadFile(base + ".report.json")     // #nosec G304 -- the box's own file
		r.ReviewDoc, _ = os.ReadFile(base + ".review.json")  // #nosec G304 -- the box's own file
		r.Template, _ = os.ReadFile(base + ".template.json") // #nosec G304 -- the box's own file
	}
	return runs, nil
}

// ansiCodes are the terminal control sequences (colours, line clears) a
// step's console log carries; the Import page shows the output as text.
var ansiCodes = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func readCapped(p string) (string, error) {
	f, err := os.Open(p) // #nosec G304 -- the box's own file
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() > maxOutput {
		if _, err := f.Seek(st.Size()-maxOutput, io.SeekStart); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxOutput))
	return string(b), err
}

// TakeOwnerPassword returns the first admin's one-time password an import
// step left, once: the file is removed as it's read.
func (m *Manager) TakeOwnerPassword(job string) (string, error) {
	if !regexp.MustCompile(`^sneakers-migrate-[a-z]+-[0-9]+$`).MatchString(job) {
		return "", codes.New(codes.NotAvailable, "there is no import step %q", job)
	}
	p := filepath.Join(m.Dir, OutDir, job+".owner")
	b, err := os.ReadFile(p) // #nosec G304 -- a checked name in the box's own directory
	if errors.Is(err, os.ErrNotExist) {
		return "", codes.New(codes.NotAvailable, "the one-time password of %s was already shown, or there is none", job)
	}
	if err != nil {
		return "", fmt.Errorf("productimport: %w", err)
	}
	if err := os.Remove(p); err != nil {
		return "", fmt.Errorf("productimport: %w", err)
	}
	m.lg().Info("productimport: the first admin's one-time password was shown and removed", log.F("job", job))
	return strings.TrimSpace(string(b)), nil
}

// Close removes the import's Jobs from the stack and everything in the
// import directory: the export, the key and the outputs.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	jobs, _ := filepath.Glob(filepath.Join(m.Stack, "job-*.yaml"))
	sort.Strings(jobs)
	var errs []error
	for _, j := range jobs {
		if err := os.Remove(j); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.RemoveAll(m.Dir); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("productimport: %w", err)
	}
	m.lg().Info("productimport: import closed; the export, its key and the outputs are removed", log.F("jobs", len(jobs)))
	return nil
}

// Marker records that the box's product data came from an import.
type Marker struct {
	BundleID string    `json:"bundle_id"`
	Job      string    `json:"job"`
	At       time.Time `json:"at"`
	Mode     string    `json:"mode"`
}

// ReadMarker reads the imported marker at path.
func ReadMarker(path string) (Marker, bool) {
	b, err := os.ReadFile(path) // #nosec G304 -- the box's own file
	if err != nil {
		return Marker{}, false
	}
	var mk Marker
	if json.Unmarshal(b, &mk) != nil || mk.BundleID == "" {
		return Marker{}, false
	}
	return mk, true
}

// WriteMarker records an import that passed.
func WriteMarker(path string, mk Marker) error {
	b, err := json.Marshal(mk)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path+".new", b, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}

// ImportReport is what the box reads from an import's report: its bundle
// and whether it ran in rehearsal mode.
type ImportReport struct {
	BundleID string `json:"bundle_id"`
	Mode     string `json:"mode"`
}

// ParseImportReport reads an import step's report.
func ParseImportReport(b []byte) (ImportReport, bool) {
	var r ImportReport
	if json.Unmarshal(b, &r) != nil || r.BundleID == "" {
		return ImportReport{}, false
	}
	return r, true
}
