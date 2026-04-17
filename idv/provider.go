//go:build idv

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
	"context"

	cidv "github.com/hanzoai/idv/provider"
)

// IdvProvider is the sync identity verification interface used by IAM controllers.
// For async workflows (webhooks, redirect flows), use the compliance module directly.
type IdvProvider interface {
	VerifyIdentity(idCardType string, idCard string, realName string) (bool, error)
}

// GetIdvProvider returns an IDV provider by type. Jumio, Onfido, and Plaid
// delegate to luxfi/compliance for the full verification workflow. Alibaba
// Cloud remains IAM-native (China-market specific).
func GetIdvProvider(typ string, clientId string, clientSecret string, endpoint string) IdvProvider {
	switch typ {
	case "Jumio":
		return &complianceAdapter{
			provider: cidv.NewJumio(cidv.JumioConfig{
				BaseURL:   endpoint,
				APIToken:  clientId,
				APISecret: clientSecret,
			}),
		}
	case "Onfido":
		return &complianceAdapter{
			provider: cidv.NewOnfido(cidv.OnfidoConfig{
				BaseURL:  endpoint,
				APIToken: clientId,
			}),
		}
	case "Plaid":
		return &complianceAdapter{
			provider: cidv.NewPlaid(cidv.PlaidConfig{
				BaseURL:  endpoint,
				ClientID: clientId,
				Secret:   clientSecret,
			}),
		}
	case "Alibaba Cloud":
		return NewAlibabaCloudIdvProvider(clientId, clientSecret, endpoint)
	default:
		// Default to Jumio for backward compatibility
		return &complianceAdapter{
			provider: cidv.NewJumio(cidv.JumioConfig{
				BaseURL:   endpoint,
				APIToken:  clientId,
				APISecret: clientSecret,
			}),
		}
	}
}

// complianceAdapter wraps a luxfi/compliance IDV provider to satisfy
// the sync IdvProvider interface. It initiates verification and returns
// success if a session was created (the full async flow with webhooks
// is handled by the compliance service separately).
type complianceAdapter struct {
	provider cidv.Provider
}

func (a *complianceAdapter) VerifyIdentity(idCardType string, idCard string, realName string) (bool, error) {
	resp, err := a.provider.InitiateVerification(context.Background(), &cidv.VerificationRequest{
		GivenName:    realName,
		DocumentType: idCardType,
		DocumentID:   idCard,
	})
	if err != nil {
		return false, err
	}
	// Session initiated successfully — for sync callers, this means
	// the provider accepted the request. Full verification completes
	// asynchronously via webhooks handled by the compliance service.
	return resp.VerificationID != "", nil
}
