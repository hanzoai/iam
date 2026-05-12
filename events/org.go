// Copyright 2021 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package events

import "context"

// SubjectOrgCreated is the canonical subject for an organization-created
// event. Subjects are flat: package + verb, no further nesting.
const SubjectOrgCreated = "org.created"

// Created is the payload of an org.created event.
//
// ID is the IAM-internal owner/name pair (e.g. "admin/acme") that
// uniquely identifies the org. Slug is the URL-safe org name. Name is
// the display name. OwnerID identifies the IAM user who created the
// org; OwnerEmail is the user's email at creation time. TS is a Unix
// millisecond timestamp.
type Created struct {
	ID         string `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	OwnerID    string `json:"ownerId"`
	OwnerEmail string `json:"ownerEmail"`
	TS         int64  `json:"ts"`
}

// PublishOrgCreated is a typed helper around Publish for the org.created
// subject. Use it instead of hand-rolling the subject string at call
// sites.
func (n *NATS) PublishOrgCreated(ctx context.Context, c Created) error {
	return n.Publish(ctx, SubjectOrgCreated, c)
}
