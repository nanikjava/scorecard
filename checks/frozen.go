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
	"encoding/json"
	"fmt"
	"github.com/ossf/scorecard/v2/checker"
	sce "github.com/ossf/scorecard/v2/errors"
	"regexp"
	"strings"
)

type PackageJSON struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Keywords     []string          `json:"keywords"`
	Homepage     string            `json:"homepage"`
	License      string            `json:"license"`
	Files        []string          `json:"files"`
	Main         string            `json:"main"`
	Scripts      map[string]string `json:"scripts"`
	Os           []string          `json:"os"`
	Cpu          []string          `json:"cpu"`
	Private      bool              `json:"private"`
	Bin          map[string]string `json:"bin"`
	Dependencies map[string]string `json:"dependencies"`
}

// CheckFrozen is the exported name for Frozen-Check check.
const CheckFrozen = "Frozen"

type frozenPinningResult struct {
	module pinnedResult
	frozen pinnedResult
}

const (
	module pinnedResult = iota
	binary
)

//nolint:gochecknoinits
func init() {
	registerCheck(CheckFrozen, Frozen)
}

func addFrozenPinnedResult(w *frozenPinningResult, frozen, m bool) {
	w.frozen = notPinned

	if frozen {
		w.frozen = pinned
	}

	if m {
		w.module = module
	} else {
		w.module = binary
	}

}

func isPackageJson(filename string) (bool, error) {
	return strings.HasPrefix(strings.ToLower(filename), "package.json"), nil
}

func testIsFrozen(pathfn string, content []byte, dl checker.DetailLogger) (int, error) {
	var r frozenPinningResult
	_, err := validateFrozenIsPinned(pathfn, content, dl, &r)
	return createReturnForIsFrozen(r, dl, err)
}

func createReturnForIsFrozen(r frozenPinningResult, dl checker.DetailLogger, err error) (int, error) {
	return createReturnValuesForIsFrozen(r, "no frozen dependencies foound", dl, err)
}

func createReturnValuesForIsFrozen(r frozenPinningResult, infoMsg string, dl checker.DetailLogger, err error) (int, error) {
	if err != nil {
		return checker.InconclusiveResultScore, err
	}

	switch {
	case (r.module == module) && (r.frozen == pinned):
		return checker.MinResultScore, nil
	case (r.module == module) && (r.frozen == notPinned):
		return checker.MaxResultConfidence, nil
	case (r.module == binary) && (r.frozen == pinned):
		return checker.MinResultScore, nil
	case (r.module == binary) && (r.frozen == notPinned):
		return checker.MaxResultConfidence, nil
	default:
		return checker.MinResultScore, nil
	}
}

func isFrozenDependencies(c *checker.CheckRequest) (int, error) {
	var r frozenPinningResult
	err := CheckFilesContent("package.json", false, c, validateFrozenIsPinned, &r)
	return createReturnForIsFrozen(r, c.Dlogger, err)
}

func validateFrozenIsPinned(pathfn string, content []byte,
	dl checker.DetailLogger, data FileCbData) (bool, error) {

	pdata, ok := data.(*frozenPinningResult)
	if !ok {
		// panic if it is not correct type
		panic("type need to be of frozenPinningResult")
	}

	var pjson = PackageJSON{}
	err := json.Unmarshal(content, &pjson)

	if err != nil {
		return false, sce.WithMessage(sce.ErrScorecardInternal,
			fmt.Sprintf("%v: %v", errInternalInvalidYamlFile, err))
	}

	// use regex to check no dependencies are pinned
	// ^([0-9]+)\.([0-9]+)\.([0-9]+)?$
	regex := regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)?$`)
	frozen := false

	for _, v := range pjson.Dependencies {
		// check if the dependency match
		if regex.Match([]byte(v)) {
			frozen = true
			break
		}
	}

	// check whether there is a bin information
	module := true

	// if there is bin that means we can assume module
	if len(pjson.Main) == 0 {
		module = false
	}

	//func addFrozenPinnedResult(w *frozenPinningResult, frozen, m bool) {
	addFrozenPinnedResult(pdata, frozen, module)
	return true, nil
}

func isTempFrozenDependencies(c *checker.CheckRequest) checker.CheckResult {
	matchedFiles, err := c.RepoClient.ListFiles(isPackageJson)

	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("RepoClient.ListFiles: %v", err))
		return checker.CreateRuntimeErrorResult(CheckFrozen, e)
	}

	for _, fp := range matchedFiles {
		fmt.Println("reading file ", fp)

		pj, err := c.RepoClient.GetFileContent(fp)

		if err != nil {
			e := sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("RepoClient.GetFileContent: %v", err))
			return checker.CreateRuntimeErrorResult(CheckFrozen, e)
		}

		var pjson = PackageJSON{}
		err = json.Unmarshal(pj, &pjson)

		if err != nil {
			e := sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("RepoClient.GetFileContent: %v", err))
			return checker.CreateRuntimeErrorResult(CheckFrozen, e)
		}

		fmt.Println("package.json Name - ", pjson.Main)

		// use regex to check no dependencies are pinned
		// ^([0-9]+)\.([0-9]+)\.([0-9]+)?$
		regex := regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)?$`)
		pinned := false

		for _, k := range pjson.Dependencies {
			d := pjson.Dependencies[k]

			// check if the dependency match
			if !regex.Match([]byte(d)) {
				pinned = true
				break
			}
		}

		// check whether there is a bin information
		module := true
		binary := true

		// if there is no main it is not a module
		if len(pjson.Main) == 0 {
			module = false
		}

		// if there is no bin it is not a bin
		if len(pjson.Bin) == 0 {
			binary = false
		}

		switch {
		case (module) && (pinned):
			return checker.CreateMinScoreResult(CheckFrozen, "frozen libs/program detected")
		case (module) && (!pinned):
			return checker.CreateMaxScoreResult(CheckFrozen, "frozen libs/program detected")
		case (binary) && (pinned):
			return checker.CreateMinScoreResult(CheckFrozen, "frozen libs/program detected")
		case (binary) && (!pinned):
			return checker.CreateMaxScoreResult(CheckFrozen, "frozen libs/program detected")
		}

	}

	return checker.CreateMaxScoreResult(CheckFrozen, "frozen libs/program detected")
}

// Frozen runs Frozen check.
func Frozen(c *checker.CheckRequest) checker.CheckResult {
	return isTempFrozenDependencies(c)
}
