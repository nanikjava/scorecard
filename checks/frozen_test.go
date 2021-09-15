// Copyright 2020 Security Scorecard Authors
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

package checks

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/ossf/scorecard/v2/checker"
	scut "github.com/ossf/scorecard/v2/utests"
)

func TestFrozenNodeModule(t *testing.T) {
	//t.Parallel()

	tests := []struct {
		name     string
		filename string
		expected scut.TestReturn
	}{
		{
			name:     "package.json with module pinned",
			filename: "./testdata/frozen-package-json-module-pinned.json",
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			},
		},
		{
			name:     "package.json with module not pinned",
			filename: "./testdata/frozen-package-json-module-not-pinned.json",
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			},
		},
		{
			name:     "package.json with bin pinned",
			filename: "./testdata/frozen-package-json-bin-pinned.json",
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			},
		},
		{
			name:     "package.json with bin not pinned",
			filename: "./testdata/frozen-package-json-bin-not-pinned.json",
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var content []byte
			var err error

			content, err = ioutil.ReadFile(tt.filename)
			if err != nil {
				panic(fmt.Errorf("cannot read file: %w", err))
			}

			dl := scut.TestDetailLogger{}
			s, e := testIsFrozen(tt.filename, content, &dl)
			actual := checker.CheckResult{
				Score:  s,
				Error2: e,
			}
			if !scut.ValidateTestReturn(t, tt.name, &tt.expected, &actual, &dl) {
				t.Fail()
			}
		})
	}
}
