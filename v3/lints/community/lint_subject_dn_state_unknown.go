package community

/*
 * ZLint Copyright 2020 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"errors"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"

	"github.com/pkic/regions/check"
)

type provinceUnknown struct{}

func (l *provinceUnknown) Initialize() error {
	return nil
}

func (l *provinceUnknown) CheckApplies(c *x509.Certificate) bool {
	if len(c.Subject.Province) > 0 {
		return true
	}
	return false
}

func (l *provinceUnknown) Execute(c *x509.Certificate) *lint.LintResult {
	for _, country := range c.Subject.Country {
		for _, province := range c.Subject.Province {
			if err := check.IsCountryRegion(country, province); err != nil {
				// ErrRegionUnknown means that the region is not known but might exists
				// as the country is not been strictly verified.
				if errors.Is(err, check.ErrRegionUnknown) {
					return &lint.LintResult{Status: lint.Notice}
				}
				// ErrRegionNotExists means that the region does not exist.
				return &lint.LintResult{Status: lint.Warn}
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "n_subject_state_unknown",
		Description:   "The state/province name field SHOULD contain an official region value for the country in which the subject's place of business is located.",
		Citation:      "PKIC",
		Source:        lint.Community,
		EffectiveDate: util.ZeroDate,
		Lint:          &provinceUnknown{},
	})
}
