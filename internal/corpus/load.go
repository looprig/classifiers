package corpus

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed testdata/*.json
var testdataFS embed.FS

// Load decodes and validates every case in testdata, in a stable order
// (sorted by ID, independent of file layout), and rejects a duplicate ID.
// Every returned case has already passed Case.Validate.
func Load() ([]Case, error) {
	entries, err := fs.Glob(testdataFS, "testdata/*.json")
	if err != nil {
		return nil, fmt.Errorf("corpus: Load: %w", err)
	}
	var cases []Case
	for _, entry := range entries {
		data, err := testdataFS.ReadFile(entry)
		if err != nil {
			return nil, fmt.Errorf("corpus: Load: reading %s: %w", entry, err)
		}
		var fileCases []Case
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&fileCases); err != nil {
			return nil, fmt.Errorf("corpus: Load: decoding %s: %w", entry, err)
		}
		cases = append(cases, fileCases...)
	}

	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if _, duplicate := seen[c.ID]; duplicate {
			return nil, fmt.Errorf("corpus: Load: duplicate case id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, nil
}
