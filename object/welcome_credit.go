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

package object

import (
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/iam/util"
)

const (
	WelcomeCreditAmount   = 0
	WelcomeCreditCurrency = "USD"
	WelcomeCreditTag      = "welcome-credit"
	WelcomeCreditDays     = 30
)

// GrantWelcomeCredit grants a $5 USD welcome credit to a newly signed-up user.
// The credit expires in 30 days. It creates a Recharge transaction tagged
// "welcome-credit" and updates both the user's balance and the organization's
// user-balance sum.
func GrantWelcomeCredit(user *User, lang string) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}

	expiresAt := time.Now().AddDate(0, 0, WelcomeCreditDays).Format(time.RFC3339)

	transactionId := strings.ReplaceAll(util.GenerateId(), "-", "")
	transaction := &Transaction{
		Owner:       user.Owner,
		Name:        transactionId,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: transactionId,
		Category:    TransactionCategoryRecharge,
		Type:        "Welcome Credit",
		Tag:         WelcomeCreditTag,
		User:        user.Name,
		Amount:      WelcomeCreditAmount,
		Currency:    WelcomeCreditCurrency,
		State:       "Approved",
		ExpiresAt:   expiresAt,
	}

	_, err := ormer.Engine.Insert(transaction)
	if err != nil {
		return fmt.Errorf("failed to insert welcome credit transaction: %w", err)
	}

	// Credit the user's balance
	err = UpdateUserBalance(user.Owner, user.Name, WelcomeCreditAmount, WelcomeCreditCurrency, lang)
	if err != nil {
		return fmt.Errorf("failed to update user balance for welcome credit: %w", err)
	}

	// Update the organization's user-balance sum
	err = UpdateOrganizationBalance("admin", user.Owner, WelcomeCreditAmount, WelcomeCreditCurrency, false, lang)
	if err != nil {
		return fmt.Errorf("failed to update org user balance for welcome credit: %w", err)
	}

	return nil
}
