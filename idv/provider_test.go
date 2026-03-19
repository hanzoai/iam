// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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

package idv

import (
	"testing"
)

func TestGetIdvProvider_Jumio(t *testing.T) {
	p := GetIdvProvider("Jumio", "token", "secret", "https://netverify.com/api/v4")
	if p == nil {
		t.Fatal("expected Jumio provider, got nil")
	}
	if _, ok := p.(*complianceAdapter); !ok {
		t.Fatalf("expected complianceAdapter, got %T", p)
	}
}

func TestGetIdvProvider_Onfido(t *testing.T) {
	p := GetIdvProvider("Onfido", "token", "", "https://api.onfido.com/v3.6")
	if p == nil {
		t.Fatal("expected Onfido provider, got nil")
	}
	if _, ok := p.(*complianceAdapter); !ok {
		t.Fatalf("expected complianceAdapter, got %T", p)
	}
}

func TestGetIdvProvider_Plaid(t *testing.T) {
	p := GetIdvProvider("Plaid", "client-id", "secret", "https://sandbox.plaid.com")
	if p == nil {
		t.Fatal("expected Plaid provider, got nil")
	}
	if _, ok := p.(*complianceAdapter); !ok {
		t.Fatalf("expected complianceAdapter, got %T", p)
	}
}

func TestGetIdvProvider_AlibabaCloud(t *testing.T) {
	p := GetIdvProvider("Alibaba Cloud", "key", "secret", "")
	if p == nil {
		t.Fatal("expected Alibaba Cloud provider, got nil")
	}
	if _, ok := p.(*AlibabaCloudIdvProvider); !ok {
		t.Fatalf("expected AlibabaCloudIdvProvider, got %T", p)
	}
}

func TestGetIdvProvider_Default(t *testing.T) {
	p := GetIdvProvider("Unknown", "token", "secret", "https://example.com")
	if p == nil {
		t.Fatal("expected default provider, got nil")
	}
	// Default falls through to Jumio (complianceAdapter)
	if _, ok := p.(*complianceAdapter); !ok {
		t.Fatalf("expected complianceAdapter as default, got %T", p)
	}
}

func TestComplianceAdapter_ImplementsInterface(t *testing.T) {
	var _ IdvProvider = (*complianceAdapter)(nil)
}

func TestAlibabaCloud_ImplementsInterface(t *testing.T) {
	var _ IdvProvider = (*AlibabaCloudIdvProvider)(nil)
}

func TestComplianceAdapter_EmptyCredentials(t *testing.T) {
	// Compliance providers should handle empty credentials gracefully
	p := GetIdvProvider("Jumio", "", "", "")
	if p == nil {
		t.Fatal("expected provider even with empty creds")
	}
	// Calling VerifyIdentity with empty creds should return an error, not panic
	_, err := p.VerifyIdentity("passport", "AB123456", "John Doe")
	if err == nil {
		t.Fatal("expected error with empty credentials")
	}
}
