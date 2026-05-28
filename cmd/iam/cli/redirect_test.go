// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"reflect"
	"testing"
)

func TestUnionPreserveOrder(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []string
		combined []string
		added    []string
	}{
		{
			name:     "empty + new",
			a:        nil,
			b:        []string{"https://a", "https://b"},
			combined: []string{"https://a", "https://b"},
			added:    []string{"https://a", "https://b"},
		},
		{
			name:     "existing + new",
			a:        []string{"https://a"},
			b:        []string{"https://b", "https://c"},
			combined: []string{"https://a", "https://b", "https://c"},
			added:    []string{"https://b", "https://c"},
		},
		{
			name:     "all duplicates",
			a:        []string{"https://a", "https://b"},
			b:        []string{"https://a", "https://b"},
			combined: []string{"https://a", "https://b"},
			added:    nil,
		},
		{
			name:     "partial overlap",
			a:        []string{"https://a", "https://b"},
			b:        []string{"https://b", "https://c"},
			combined: []string{"https://a", "https://b", "https://c"},
			added:    []string{"https://c"},
		},
		{
			name:     "dedup within b",
			a:        nil,
			b:        []string{"https://a", "https://a", "https://b"},
			combined: []string{"https://a", "https://b"},
			added:    []string{"https://a", "https://b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, added := unionPreserveOrder(tt.a, tt.b)
			if !reflect.DeepEqual(got, tt.combined) {
				t.Errorf("combined = %v, want %v", got, tt.combined)
			}
			if !reflect.DeepEqual(added, tt.added) {
				t.Errorf("added = %v, want %v", added, tt.added)
			}
		})
	}
}

func TestFilterOut(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		target  string
		out     []string
		removed bool
	}{
		{
			name:    "remove present",
			in:      []string{"a", "b", "c"},
			target:  "b",
			out:     []string{"a", "c"},
			removed: true,
		},
		{
			name:    "absent",
			in:      []string{"a", "b"},
			target:  "z",
			out:     []string{"a", "b"},
			removed: false,
		},
		{
			name:    "empty",
			in:      nil,
			target:  "z",
			out:     nil,
			removed: false,
		},
		{
			name:    "first",
			in:      []string{"a", "b"},
			target:  "a",
			out:     []string{"b"},
			removed: true,
		},
		{
			name:    "last",
			in:      []string{"a", "b"},
			target:  "b",
			out:     []string{"a"},
			removed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, removed := filterOut(tt.in, tt.target)
			if removed != tt.removed {
				t.Errorf("removed = %v, want %v", removed, tt.removed)
			}
			// Normalize nil vs empty slice for comparison: filterOut may
			// return an allocated empty slice when target is absent.
			if len(got) == 0 && len(tt.out) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.out) {
				t.Errorf("out = %v, want %v", got, tt.out)
			}
		})
	}
}
