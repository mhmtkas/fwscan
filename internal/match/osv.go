package match

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mhmtkas/fwscan/internal/catalog"
	"github.com/mhmtkas/fwscan/internal/model"
)

// DefaultBaseURL is the public OSV API. No key is needed, and the spike drew no
// throttling from several hundred queries a minute (spike/NOTES.md T0.3).
const DefaultBaseURL = "https://api.osv.dev"

// Tuning, all taken from the spike's measurements.
const (
	// defaultBatchSize is well inside what OSV handles: 393 purls in one call
	// returned in 1.3 s with no pagination.
	defaultBatchSize = 250
	// defaultConcurrency is for the per-vulnerability detail fetches, which
	// querybatch does not include. Ten workers turned 79 s of serial fetching
	// into 8 s and drew no throttling.
	defaultConcurrency = 10
	defaultTimeout     = 60 * time.Second
	// maxResponseBytes bounds a single API response. OSV is a trusted service,
	// but nothing that reads from a network gets to allocate without a limit.
	maxResponseBytes = 64 << 20
)

// OSV queries OSV.dev.
type OSV struct {
	BaseURL     string
	HTTPClient  *http.Client
	BatchSize   int
	Concurrency int
}

// NewOSV returns a matcher pointed at the public API.
func NewOSV() *OSV {
	return &OSV{
		BaseURL:     DefaultBaseURL,
		HTTPClient:  &http.Client{Timeout: defaultTimeout},
		BatchSize:   defaultBatchSize,
		Concurrency: defaultConcurrency,
	}
}

// query is one entry in a querybatch request.
type query struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
}

type batchRequest struct {
	Queries []query `json:"queries"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// vulnRecord is the part of an OSV vulnerability document fwscan reads.
type vulnRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	Affected         []affected     `json:"affected"`
}

type affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
		} `json:"events"`
	} `json:"ranges"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// queryKey identifies one distinct OSV lookup. Many binary packages share a
// source package, and querying each binary separately would be roughly 28% more
// requests for identical answers (spike/NOTES.md T0.3).
type queryKey struct {
	source  string
	version string
	distro  string
}

func keyFor(c model.Component) queryKey {
	source, version := c.Source, c.SourceVersion
	if source == "" {
		source, version = c.Name, c.Version
	}
	return queryKey{source: source, version: version, distro: c.Distro}
}

// Match implements Matcher.
func (o *OSV) Match(ctx context.Context, comps []model.Component) ([]model.Finding, error) {
	if len(comps) == 0 {
		return nil, nil
	}

	// Group components by the lookup they need, so each lookup happens once and
	// its answer fans back out to every package that shares a source.
	order := make([]queryKey, 0, len(comps))
	grouped := make(map[queryKey][]model.Component, len(comps))
	for _, c := range comps {
		key := keyFor(c)
		if key.source == "" || key.version == "" {
			continue // nothing to ask about
		}
		if _, seen := grouped[key]; !seen {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], c)
	}
	if len(order) == 0 {
		return nil, nil
	}

	hits, err := o.queryBatch(ctx, order)
	if err != nil {
		return nil, err
	}

	// Collect the distinct vulnerability ids before fetching details: the same
	// CVE routinely affects several packages in one image.
	var ids []string
	seen := map[string]bool{}
	for _, vulnIDs := range hits {
		for _, id := range vulnIDs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)

	records, err := o.fetchVulns(ctx, ids)
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	for _, key := range order {
		for _, id := range hits[key] {
			record, ok := records[id]
			if !ok {
				continue
			}
			for _, comp := range grouped[key] {
				findings = append(findings, buildFinding(record, comp, key))
			}
		}
	}
	slices.SortFunc(findings, model.CompareFindings)
	return findings, nil
}

// queryBatch asks OSV about every key, in chunks, returning the vulnerability
// ids per key.
func (o *OSV) queryBatch(ctx context.Context, keys []queryKey) (map[queryKey][]string, error) {
	size := o.BatchSize
	if size <= 0 {
		size = defaultBatchSize
	}

	out := make(map[queryKey][]string, len(keys))
	for start := 0; start < len(keys); start += size {
		end := min(start+size, len(keys))
		chunk := keys[start:end]

		req := batchRequest{Queries: make([]query, len(chunk))}
		for i, key := range chunk {
			req.Queries[i].Package.PURL = catalog.SourcePURL(key.source, key.version, key.distro)
		}

		var resp batchResponse
		if err := o.postJSON(ctx, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != len(chunk) {
			return nil, fmt.Errorf("osv: asked about %d packages, got %d results", len(chunk), len(resp.Results))
		}
		for i, result := range resp.Results {
			if len(result.Vulns) == 0 {
				continue
			}
			ids := make([]string, 0, len(result.Vulns))
			for _, v := range result.Vulns {
				ids = append(ids, v.ID)
			}
			slices.Sort(ids)
			out[chunk[i]] = ids
		}
	}
	return out, nil
}

// fetchVulns retrieves full records for each id. querybatch returns identifiers
// only; severity and fixed versions live in the individual documents.
func (o *OSV) fetchVulns(ctx context.Context, ids []string) (map[string]vulnRecord, error) {
	workers := o.Concurrency
	if workers <= 0 {
		workers = defaultConcurrency
	}
	workers = min(workers, len(ids))
	if workers == 0 {
		return map[string]vulnRecord{}, nil
	}

	var (
		mu       sync.Mutex
		records  = make(map[string]vulnRecord, len(ids))
		firstErr error
		wg       sync.WaitGroup
	)
	work := make(chan string)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				var record vulnRecord
				err := o.getJSON(ctx, "/v1/vulns/"+id, &record)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
						cancel() // stop the rest; one failure fails the scan
					}
				} else {
					records[record.ID] = record
				}
				mu.Unlock()
			}
		}()
	}

	for _, id := range ids {
		select {
		case work <- id:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return records, nil
}

func (o *OSV) postJSON(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("osv: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url(path), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return o.do(req, out)
}

func (o *OSV) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.url(path), nil)
	if err != nil {
		return fmt.Errorf("osv: build request: %w", err)
	}
	return o.do(req, out)
}

func (o *OSV) do(req *http.Request, out any) error {
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %s unreachable: %w", req.URL.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s returned %s", req.URL.Path, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("osv: read response: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("osv: decode response: %w", err)
	}
	return nil
}

func (o *OSV) url(path string) string {
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	return strings.TrimSuffix(base, "/") + path
}
