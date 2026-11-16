// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsecrets

import (
	"fmt"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Rotation is a key moved to a new value: Current is the new key, Previous
// the one it replaces. Both are secrets; the caller never logs them.
type Rotation struct {
	Current  string
	Previous string
	// Resumed is true when the rotation was already begun, so no new key was
	// made this time.
	Resumed bool
}

// rotatable finds the escrow key called name, which the bundle must give a
// previous key to, and its ids in the values file.
func rotatable(spec productspec.Spec, name string) (current, previous string, err error) {
	for _, e := range spec.Escrow {
		if e.Name != name {
			continue
		}
		if e.Previous == "" {
			return "", "", fmt.Errorf("boxsecrets: the bundle names no previous key for %s, so it can't be rotated", name)
		}
		return e.Secret + "/" + e.Key, e.Secret + "/" + e.Previous, nil
	}
	return "", "", fmt.Errorf("boxsecrets: the bundle doesn't escrow a key called %s", name)
}

// BeginRotation moves the escrow key called name in the bundle in slot to a
// new value and keeps the old one as its previous key, in one write: a
// power cut leaves the key as it was or both. When the previous key is
// already held the rotation was begun before, and the keys held are
// returned without making a new one, so a restart resumes and never makes a
// second key over a vault that has already moved to the first. The stack
// carries the previous key (the next Ensure writes it) until EndRotation.
func (s *Store) BeginRotation(slot, name string) (Rotation, error) {
	spec, err := productspec.Load(slot)
	if err != nil {
		return Rotation{}, err
	}
	cur, prev, err := rotatable(spec, name)
	if err != nil {
		return Rotation{}, err
	}
	values, err := s.load()
	if err != nil {
		return Rotation{}, err
	}
	if values[prev] != "" {
		if values[cur] == "" {
			return Rotation{}, fmt.Errorf("boxsecrets: the rotation of %s holds a previous key and no current one", name)
		}
		s.logger().Info("boxsecrets: a rotation is already begun; it carries on", log.F("key", name))
		return Rotation{Current: values[cur], Previous: values[prev], Resumed: true}, nil
	}
	old := values[cur]
	if old == "" {
		return Rotation{}, fmt.Errorf("boxsecrets: %s has no value to rotate yet", name)
	}
	for _, b := range spec.BoxSecrets {
		for _, k := range b.Keys {
			if b.Secret+"/"+k.Key == cur && k.Generate != "" {
				v, err := generate(k.Generate)
				if err != nil {
					return Rotation{}, err
				}
				values[prev], values[cur] = old, v
				if err := s.save(values); err != nil {
					return Rotation{}, err
				}
				s.logger().Info("boxsecrets: a rotation begins; the old key is kept as the previous one", log.F("key", name))
				return Rotation{Current: v, Previous: old}, nil
			}
		}
	}
	return Rotation{}, fmt.Errorf("boxsecrets: %s isn't a key the box generates, so it can't make a new one", name)
}

// EndRotation drops the previous key of the escrow key called name, once the
// product has moved off it. Dropping what isn't held is not an error.
func (s *Store) EndRotation(slot, name string) error {
	spec, err := productspec.Load(slot)
	if err != nil {
		return err
	}
	_, prev, err := rotatable(spec, name)
	if err != nil {
		return err
	}
	values, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := values[prev]; !ok {
		return nil
	}
	delete(values, prev)
	if err := s.save(values); err != nil {
		return err
	}
	s.logger().Info("boxsecrets: the previous key is dropped", log.F("key", name))
	return nil
}

// Rotating reports whether any escrow key of the bundle in slot is held with
// a previous key: a rotation that hasn't ended.
func (s *Store) Rotating(slot string) (bool, error) {
	spec, err := productspec.Load(slot)
	if err != nil {
		return false, err
	}
	values, err := s.load()
	if err != nil {
		return false, err
	}
	for _, e := range spec.Escrow {
		if e.Previous != "" && values[e.Secret+"/"+e.Previous] != "" {
			return true, nil
		}
	}
	return false, nil
}

// Value is the current value of the escrow key called name in the bundle in
// slot; found is false when the box hasn't made it yet.
func (s *Store) Value(slot, name string) (value string, found bool, err error) {
	spec, err := productspec.Load(slot)
	if err != nil {
		return "", false, err
	}
	for _, e := range spec.Escrow {
		if e.Name != name {
			continue
		}
		values, err := s.load()
		if err != nil {
			return "", false, err
		}
		v := values[e.Secret+"/"+e.Key]
		return v, v != "", nil
	}
	return "", false, fmt.Errorf("boxsecrets: the bundle doesn't escrow a key called %s", name)
}
