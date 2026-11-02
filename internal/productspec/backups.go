// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"path"
	"regexp"
	"strings"
)

// BackupRoot is the box's encrypted backup partition.
const BackupRoot = "/var/lib/sneakers/backup"

// SetsDir holds the backup sets, beside the store in Backups.Dir.
const SetsDir = "sets"

// Backups is how the box backs up and restores the product's database
// (docs/backups.md). The cluster archives on its own; the box cuts sets from
// what it archived and restores one. The appliance knows no chart: everything
// it needs is named here.
type Backups struct {
	// Label is the words for the restore in Updates and the console.
	Label string `yaml:"label"`
	// After is the phase holding the cluster; a restore stops the phases
	// after it.
	After string `yaml:"after"`
	// Cluster is the database. The tools run in its first pod.
	Cluster DataCluster `yaml:"cluster"`
	// Claim is the PersistentVolumeClaim the render's pods use for the
	// store; the stacks mount Dir there instead.
	Claim string `yaml:"claim"`
	// Root is the backup partition, BackupRoot unless a test or a rehearsal
	// says otherwise; product.yaml can't set it.
	Root string `yaml:"-"`
	// Dir is the directory on the backup partition the pods get.
	Dir string `yaml:"dir"`
	// Mount is where the pods see Dir.
	Mount string `yaml:"mount"`
	// Store is the archive's directory under Dir.
	Store string `yaml:"store"`
	// Data names the entry in data that holds the cluster's volume, and
	// PGData is the data directory under it.
	Data   string `yaml:"data"`
	PGData string `yaml:"pgdata"`
	// Databases are the ones the checks may name.
	Databases []string `yaml:"databases"`
	// Command asks the running cluster for a base backup now; the tool
	// runs in its first pod.
	Command []string `yaml:"command"`
	// Status says where the cluster records how its backups went.
	Status BackupStatus `yaml:"status"`
	// Restore says how the cluster starts from a set.
	Restore BackupRestore `yaml:"restore"`
	// Checks run on the restored cluster before the services start.
	Checks []DataCheck `yaml:"checks"`
}

// BackupStatus names the Lease annotations a cluster keeps its outcomes in:
// each of Success, Failure and Verify holds an RFC 3339 time, and
// VerifyResult holds VerifyOK when the last restore check passed.
type BackupStatus struct {
	Lease        string `yaml:"lease"`
	Success      string `yaml:"success"`
	Failure      string `yaml:"failure"`
	Verify       string `yaml:"verify"`
	VerifyResult string `yaml:"verify_result"`
	VerifyOK     string `yaml:"verify_ok"`
}

// BackupRestore is how the cluster comes up from a set.
type BackupRestore struct {
	// Env goes on the StatefulSet for the restore, and comes off after.
	// In a value, {set} is the set's store as the pod sees it and {point}
	// the restore point's name.
	Env map[string]string `yaml:"env"`
	// IdentityLease is the Lease holding what ties the cluster to the data
	// moved aside, and IdentityAnnotations those of its annotations a
	// restore clears, so the cluster starts from the set.
	IdentityLease       string   `yaml:"identity_lease"`
	IdentityAnnotations []string `yaml:"identity_annotations"`
}

// HostDir is Dir on the box.
func (b Backups) HostDir() string {
	if b.Root != "" {
		return path.Join(b.Root, b.Dir)
	}
	return path.Join(BackupRoot, b.Dir)
}

// StoreHostDir is the archive on the box.
func (b Backups) StoreHostDir() string { return path.Join(b.HostDir(), b.Store) }

// SetsHostDir is where the box keeps the sets.
func (b Backups) SetsHostDir() string { return path.Join(b.HostDir(), SetsDir) }

// PodSetStore is a set's store as the pods see it.
func (b Backups) PodSetStore(set string) string {
	return path.Join(b.Mount, SetsDir, set, "store")
}

// RestoreEnv is the environment that restores the named set to its point.
func (b Backups) RestoreEnv(set, point string) map[string]string {
	out := make(map[string]string, len(b.Restore.Env))
	r := strings.NewReplacer("{set}", b.PodSetStore(set), "{point}", point)
	for k, v := range b.Restore.Env {
		out[k] = r.Replace(v)
	}
	return out
}

// BackupData is the data path holding the cluster's volume.
func (s Spec) BackupData() (DataPath, bool) {
	if s.Backups == nil {
		return DataPath{}, false
	}
	for _, d := range s.Data {
		if d.Name == s.Backups.Data {
			return d, true
		}
	}
	return DataPath{}, false
}

// BackupLater are the phases a restore stops.
func (s Spec) BackupLater() []Phase {
	if s.Backups == nil {
		return nil
	}
	for i, p := range s.Phases {
		if p.Name == s.Backups.After {
			return s.Phases[i+1:]
		}
	}
	return nil
}

var (
	backupDirRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reservedDir = map[string]bool{"data-move": true, "escrow": true, "os-audit": true}
)

func (s Spec) checkBackups() error {
	b := s.Backups
	if b == nil {
		return nil
	}
	if b.Label == "" {
		return bad("backups: a label is required")
	}
	if len(s.BackupLater()) == 0 {
		return bad("backups: after %q isn't a phase with later phases", b.After)
	}
	if i, ok := s.PhaseOf(b.Cluster.Name); !ok || s.Phases[i].Name != b.After {
		return bad("backups: the cluster %q isn't a workload of the phase %q", b.Cluster.Name, b.After)
	}
	if err := checkDataCluster(s, b.After, "cluster", b.Cluster); err != nil {
		return err
	}
	if !dnsNameRE.MatchString(b.Claim) {
		return bad("backups: a claim is required")
	}
	if !backupDirRE.MatchString(b.Dir) || reservedDir[b.Dir] {
		return bad("backups: dir %q isn't a directory of its own on the backup partition", b.Dir)
	}
	if !backupDirRE.MatchString(b.Store) || b.Store == SetsDir {
		return bad("backups: store %q isn't a directory of its own beside the sets", b.Store)
	}
	if !inPodPath.MatchString(b.Mount) || path.Clean(b.Mount) != b.Mount {
		return bad("backups: mount %q isn't an absolute path", b.Mount)
	}
	if !backupDirRE.MatchString(b.PGData) {
		return bad("backups: pgdata %q isn't a directory of the data path", b.PGData)
	}
	if _, ok := s.BackupData(); !ok {
		return bad("backups: data %q isn't a declared data path", b.Data)
	}
	if len(b.Command) == 0 || !inPodPath.MatchString(b.Command[0]) {
		return bad("backups: command needs the tool's absolute path")
	}
	st := b.Status
	if !dnsNameRE.MatchString(st.Lease) || st.Success == "" || st.Failure == "" || st.Verify == "" || st.VerifyResult == "" || st.VerifyOK == "" {
		return bad("backups: status needs its lease and every annotation")
	}
	if err := checkBackupRestore(b.Restore); err != nil {
		return err
	}
	dbs := map[string]bool{}
	for _, db := range b.Databases {
		if !dbNameRE.MatchString(db) {
			return bad("backups: database %q is invalid", db)
		}
		dbs[db] = true
	}
	for _, c := range b.Checks {
		if c.Name == "" || !dbs[c.Database] || !sqlFileRE.MatchString(c.File) {
			return bad("backups: check %q needs a name, one of the databases and a .sql file in the slot", c.Name)
		}
	}
	if len(s.Escrow) == 0 {
		return bad("backups: the product declares no escrow keys, so a set can't be tied to the box that holds them")
	}
	return nil
}

func checkBackupRestore(r BackupRestore) error {
	var set, point bool
	for k, v := range r.Env {
		if !envNameRE.MatchString(k) {
			return bad("backups: restore env %q isn't a variable's name", k)
		}
		set = set || strings.Contains(v, "{set}")
		point = point || strings.Contains(v, "{point}")
	}
	if !set || !point {
		return bad("backups: restore env has to carry {set} and {point}")
	}
	if !dnsNameRE.MatchString(r.IdentityLease) {
		return bad("backups: restore needs its identity_lease")
	}
	return nil
}
