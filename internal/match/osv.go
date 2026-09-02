package match

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// query is one entry in a querybatch request. OSV accepts either a purl or a
// name plus ecosystem; which one is required depends on the ecosystem, so both
// shapes are modelled and the empty fields are omitted.
type query struct {
	Package queryPackage `json:"package"`
	Version string       `json:"version,omitempty"`
}

type queryPackage struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type batchRequest struct {
	Queries []query `json:"queries"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	// OSV paginates a result once a single package has more vulnerabilities
	// than one page holds. The spike saw none at the sizes fwscan sends, but
	// "not observed" is not "cannot happen", and silently dropping the rest
	// would under-report.
	NextPageToken string `json:"next_page_token"`
}

// vulnRecord is the part of an OSV vulnerability document fwscan reads.
type vulnRecord struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Upstream         []string        `json:"upstream"`
	Severity         []severityEntry `json:"severity"`
	DatabaseSpecific map[string]any  `json:"database_specific"`
	Affected         []affected      `json:"affected"`
}

// severityEntry is one assessment on a record: a CVSS vector under its type.
type severityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
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
	// release is the same release as distro, under the number OSV's advisory
	// records use rather than the codename its per-CVE records use.
	release string
	kind    packageKind
}

// packageKind selects the query shape. Debian is queried by purl with a distro
// qualifier; Alpine cannot be, because OSV's Alpine records carry no distro
// qualifier and keep the release in their ecosystem field instead. A purl query
// for Alpine returns nothing, silently (spike/NOTES.md T0.3a).
type packageKind int

const (
	kindUnknown packageKind = iota
	kindDeb
	kindApk
)

func keyFor(c model.Component) queryKey {
	source, version := c.Source, c.SourceVersion
	if source == "" {
		source, version = c.Name, c.Version
	}
	return queryKey{
		source:  source,
		version: version,
		distro:  c.Distro,
		release: c.DistroVersion,
		kind:    kindOf(c),
	}
}

// kindOf reads the package type off the component's purl. Components with no
// purl are heuristic results, which nothing knows how to look up.
// ecosystem returns the OSV ecosystem string for an apk key, e.g.
// "Alpine:v3.16". It is empty for Debian, which is matched by purl instead.
func (k queryKey) ecosystem() string {
	if k.kind == kindApk && k.distro != "" {
		return "Alpine:" + k.distro
	}
	return ""
}

// advisoryEcosystem is how a Debian advisory names this key's release. A DSA or
// DLA record's affected purl carries no distro qualifier -- it is the same purl
// for every release the advisory covers -- and the release is in the ecosystem
// field instead, as "Debian:11". For an oldstable image advisories are the only
// records OSV returns, so without this the fixed version they carry is
// unreachable (spike/NOTES.md T18a, question 7).
func (k queryKey) advisoryEcosystem() string {
	if k.kind == kindDeb && k.release != "" {
		return "Debian:" + k.release
	}
	return ""
}

func kindOf(c model.Component) packageKind {
	switch {
	case strings.HasPrefix(c.PURL, "pkg:deb/"):
		return kindDeb
	case strings.HasPrefix(c.PURL, "pkg:apk/"):
		return kindApk
	default:
		return kindUnknown
	}
}

// queryFor builds the request entry for a key, in whichever shape its ecosystem
// requires.
func queryFor(key queryKey) (query, bool) {
	switch key.kind {
	case kindDeb:
		var q query
		q.Package.PURL = catalog.SourcePURL(key.source, key.version, key.distro)
		return q, true
	case kindApk:
		if key.distro == "" {
			// Without the release there is no ecosystem to ask about, and a
			// bare "Alpine" returns nothing.
			return query{}, false
		}
		var q query
		q.Package.Name = key.source
		q.Package.Ecosystem = key.ecosystem()
		q.Version = key.version
		return q, true
	default:
		return query{}, false
	}
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
		if key.source == "" || key.version == "" || key.kind == kindUnknown {
			continue // nothing that can be looked up
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
	borrowed := o.borrowSeverities(ctx, records)
	if err := ctx.Err(); err != nil {
		// Borrowing tolerates its own failures, so a cancellation during it
		// would otherwise pass through as a complete-looking report with
		// every advisory left at unknown.
		return nil, fmt.Errorf("osv: %w", err)
	}

	// assessed returns the record with the assessment a finding should carry:
	// its own if it has one, otherwise the one borrowed from the record named
	// for that CVE, which may already be among the fetched records.
	assessed := func(record vulnRecord, from string) vulnRecord {
		if len(record.Severity) > 0 || from == "" {
			return record
		}
		if source, ok := records[from]; ok && len(source.Severity) > 0 {
			record.Severity = source.Severity
		} else if severity, ok := borrowed[from]; ok {
			record.Severity = severity
		}
		return record
	}

	var findings []model.Finding
	for _, key := range order {
		for _, id := range hits[key] {
			record, ok := records[id]
			if !ok {
				// fetchVulns guarantees a record for every id it was asked
				// about, and every id here came from its input, so this cannot
				// happen without a bug above. Dropping the finding instead
				// would turn that bug into a quietly incomplete report.
				return nil, fmt.Errorf("osv: no record fetched for %s", id)
			}
			// An advisory that shipped one upload for several CVEs is several
			// findings: output-spec section 1 is one finding per vulnerability,
			// and each CVE has an assessment of its own.
			for _, ident := range identities(record) {
				source := assessed(record, ident.borrowFrom)
				for _, comp := range grouped[key] {
					findings = append(findings, buildFinding(source, ident, comp, key))
				}
			}
		}
	}
	findings = dedupeFindings(findings)
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

		req := batchRequest{Queries: make([]query, 0, len(chunk))}
		asked := make([]queryKey, 0, len(chunk))
		for _, key := range chunk {
			q, ok := queryFor(key)
			if !ok {
				continue
			}
			req.Queries = append(req.Queries, q)
			asked = append(asked, key)
		}
		if len(req.Queries) == 0 {
			continue
		}

		var resp batchResponse
		if err := o.postJSON(ctx, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != len(asked) {
			return nil, fmt.Errorf("osv: asked about %d packages, got %d results", len(asked), len(resp.Results))
		}
		for i, result := range resp.Results {
			if result.NextPageToken != "" {
				// Reporting a partial answer as if it were complete is the one
				// outcome a vulnerability scanner must never produce.
				return nil, fmt.Errorf(
					"osv returned a paginated result for %s, which fwscan cannot yet follow; "+
						"the report would be incomplete", asked[i].source)
			}
			if len(result.Vulns) == 0 {
				continue
			}
			ids := make([]string, 0, len(result.Vulns))
			for _, v := range result.Vulns {
				ids = append(ids, v.ID)
			}
			slices.Sort(ids)
			out[asked[i]] = ids
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
				// The id comes back from OSV rather than from the user, but it
				// still ends up in a request path, so it is escaped.
				err := o.getJSON(ctx, "/v1/vulns/"+url.PathEscape(id), &record)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
						cancel() // stop the rest; one failure fails the scan
					}
				} else {
					// Keyed by the id that was asked for, not the one that came
					// back. A record whose id differs -- withdrawn, superseded
					// -- would otherwise be dropped without a word.
					records[id] = record
				}
				mu.Unlock()
			}
		}()
	}

	// A cancelled context ends the loop rather than skipping one id and trying
	// the next. Skipping silently dropped every remaining id, and since no
	// worker had failed, firstErr stayed nil and a short map was returned as a
	// complete one -- a scan reporting fewer vulnerabilities than exist, with
	// nothing anywhere saying so.
	var stopped error
	for _, id := range ids {
		select {
		case work <- id:
		case <-ctx.Done():
			stopped = ctx.Err()
		}
		if stopped != nil {
			break
		}
	}
	close(work)
	wg.Wait()

	// A worker's own failure is the more specific explanation, so it is
	// preferred: cancel() above means an internal failure closes the context
	// too, and reporting that as a cancellation would hide the cause.
	if firstErr != nil {
		return nil, firstErr
	}
	if stopped != nil {
		return nil, fmt.Errorf("osv: %w", stopped)
	}
	// Nothing above should be able to produce a short map without an error, so
	// this is the assertion that no future change quietly starts to. Returning
	// fewer vulnerabilities than were found, without saying so, is the one
	// outcome a vulnerability scanner must never produce.
	if len(records) != len(ids) {
		return nil, fmt.Errorf("osv: fetched %d of %d vulnerability records", len(records), len(ids))
	}
	return records, nil
}

// borrowSeverities fetches the assessments for records that have none of
// their own, from the records they name as upstream, and returns them keyed by
// the id they were fetched under.
//
// A DSA or DLA advisory carries no severity array. It names the CVEs it shipped
// a fix for in `upstream`, and each of their DEBIAN-CVE-… records has a CVSS
// vector -- the vector describes the vulnerability rather than the release, so
// borrowing it says nothing the data does not support. For an oldstable Debian
// release advisories are the only records OSV returns at all, so without this
// every finding on such an image reports as unknown, and --fail-on cannot fire
// on it (spike/NOTES.md T18a, question 6).
//
// Records already fetched are not fetched again; Match reads their assessment
// directly. Failing to borrow is not a failure of the scan, which is why this
// does not use fetchVulns and returns no error: the worst case is the unknown
// bucket the advisory would have produced anyway. fetchVulns promises to return
// everything it was asked for or fail; this promises only to improve what it
// can. Match checks the context itself afterwards, so a cancellation here does
// not pass through as a complete-looking report.
func (o *OSV) borrowSeverities(ctx context.Context, records map[string]vulnRecord) map[string][]severityEntry {
	needed := map[string]bool{}
	for _, record := range records {
		if len(record.Severity) > 0 {
			continue
		}
		for _, ident := range identities(record) {
			from := ident.borrowFrom
			if from == "" {
				continue
			}
			if _, fetched := records[from]; fetched {
				continue
			}
			needed[from] = true
		}
	}
	borrowed := map[string][]severityEntry{}
	if len(needed) == 0 {
		return borrowed
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan string)

	workers := o.Concurrency
	if workers <= 0 {
		workers = defaultConcurrency
	}
	workers = min(workers, len(needed))

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for from := range work {
				var source vulnRecord
				if err := o.getJSON(ctx, "/v1/vulns/"+url.PathEscape(from), &source); err != nil {
					continue // an absent vector is the status quo, not a failure
				}
				if len(source.Severity) == 0 {
					continue
				}
				mu.Lock()
				borrowed[from] = source.Severity
				mu.Unlock()
			}
		}()
	}

	ids := make([]string, 0, len(needed))
	for from := range needed {
		ids = append(ids, from)
	}
	slices.Sort(ids)
	for _, from := range ids {
		select {
		case work <- from:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()
	return borrowed
}

// userAgent identifies fwscan to the API. The URL is there so an operator
// looking at their logs can find out what is calling them.
const userAgent = "fwscan (+https://github.com/mhmtkas/fwscan)"

// withSameHostRedirects copies a client, adding a policy that refuses a
// redirect to a different host. The copy is shallow and deliberate: the
// caller's client is theirs, and a scanner should not reach in and change it.
func withSameHostRedirects(client *http.Client) *http.Client {
	copied := *client
	copied.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("refusing a redirect from %s to %s", via[0].URL.Host, req.URL.Host)
		}
		return nil
	}
	return &copied
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
	// Identify the caller. An unattributed client is one OSV cannot ask to slow
	// down or contact about a problem, and every other tool that queries this
	// API says who it is.
	req.Header.Set("User-Agent", userAgent)

	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	// A redirect that changes host is not followed. The default policy would
	// carry the request -- and on a POST, the body -- to wherever the response
	// pointed, which for a scanner reading an answer it will act on is a
	// decision worth making deliberately rather than inheriting.
	if client.CheckRedirect == nil {
		client = withSameHostRedirects(client)
	}
	resp, err := client.Do(req)
	if err != nil {
		// A cancelled or expired context is not a network problem, and telling
		// whoever pressed Ctrl-C to check their network is wrong twice over.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("lookup stopped: %w", err)
		}
		// Whatever else the transport said, the actionable part is the same:
		// the lookup needs the network, and there is a flag to skip it.
		return fmt.Errorf("cannot reach %s for the vulnerability lookup: %w. "+
			"check the network, or rerun with --no-network to produce the SBOM only",
			req.URL.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv.dev returned %s for %s; the service may be rate limiting or down, "+
			"rerun later or with --no-network", resp.Status, req.URL.Path)
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
