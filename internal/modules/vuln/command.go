package vuln

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// --- `dsecrat vuln` command body ----------------------------------------------
//
// The frontend owns argument dispatch; this exported entry point is the command
// body the master wires in (see NOTES.md). It intentionally lives in the module
// package so all vuln-related surface stays in one lane.

// Command implements `dsecrat vuln <subcommand>`. It returns a process exit code.
//
//	dsecrat vuln update --from <dir> [--url <mirror>] [--ecosystems <list>] --out <path> [--source <label>]
//	dsecrat vuln info   [--db <path>]
func Command(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "vuln: expected a subcommand (update|info)")
		return 2
	}
	switch args[0] {
	case "update":
		return cmdUpdate(args[1:])
	case "info":
		return cmdInfo(args[1:])
	case "cron":
		return cmdCron(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "vuln: unknown subcommand %q (want update|info|cron)\n", args[0])
		return 2
	}
}

// defaultDBPath is where a refreshed DB is written when --out is omitted: the
// same location scan/watch resolve by default ($HOME/.dsecrat/vulndb.json), so a
// refresh is picked up without extra flags.
func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "vulndb.json"
	}
	return filepath.Join(home, ".dsecrat", "vulndb.json")
}

// parseSince turns a --since value into a lastModified lower bound. It accepts a
// Go duration ("720h"), a bare "<N>d" day count ("30d"), or "" (full pull → zero
// time). Returns the zero Time for a full pull.
func parseSince(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid --since %q: %w", s, err)
		}
		return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --since %q (want e.g. 30d or 720h): %w", s, err)
	}
	return time.Now().UTC().Add(-d), nil
}

// writeDB atomically writes a rebuilt DB to out (temp file + rename), so a
// mid-write failure never corrupts the previous good DB.
func writeDB(db *vulndb.DB, out string) error {
	data, err := db.Marshal()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(out); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

func cmdUpdate(args []string) int {
	fs := flag.NewFlagSet("vuln update", flag.ContinueOnError)
	from := fs.String("from", "", "directory of OSV JSON feed documents (air-gapped source)")
	url := fs.String("url", "", "OSV mirror URL to fetch (opt-in network access)")
	ecos := fs.String("ecosystems", "", "comma-separated OSV ecosystems to pull from the public osv.dev export (e.g. Debian,Alpine,PyPI,npm,Go)")
	nvd := fs.Bool("nvd", false, "collect from the NVD CVE API 2.0 (full corpus; opt-in network access)")
	nvdKey := fs.String("nvd-key", "", "NVD API key (else $NVD_API_KEY); raises the rate limit ~10x")
	since := fs.String("since", "", "incremental: only CVEs modified since this window, e.g. 30d or 720h (NVD only; empty = full pull)")
	maxPages := fs.Int("max-pages", 0, "cap the number of NVD API pages fetched (0 = all; 2000 CVEs/page)")
	daemon := fs.Bool("daemon", false, "run continuously, refreshing the DB every --interval (self-updating)")
	interval := fs.Duration("interval", 24*time.Hour, "refresh interval when --daemon is set")
	epss := fs.Bool("epss", false, "also fetch the full daily EPSS scoreset (FIRST) and fold it into the DB")
	epssURL := fs.String("epss-url", "", "EPSS scoreset URL (default: FIRST daily gzipped CSV)")
	kev := fs.Bool("kev", false, "also fetch the CISA KEV catalog (known-exploited CVEs) and fold it into the DB")
	kevURL := fs.String("kev-url", "", "CISA KEV catalog URL (default: CISA feed)")
	out := fs.String("out", "", "write the rebuilt advisory DB here (default: ~/.dsecrat/vulndb.json)")
	source := fs.String("source", "dsecrat vuln update", "human label recorded in the DB")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// EPSS enrichment is shared by both the NVD and OSV paths: fetch it once
	// (opt-in) and fold the CVE→probability map into whatever DB is built.
	var epssScores map[string]float64
	if *epss {
		var err error
		epssScores, err = vulndb.NewEPSSFetcher(*epssURL).Fetch(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "vuln update:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "vuln update: fetched %d EPSS scores\n", len(epssScores))
	}
	var kevIDs []string
	if *kev {
		var err error
		kevIDs, err = vulndb.NewKEVFetcher(*kevURL).Fetch(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "vuln update:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "vuln update: fetched %d KEV entries\n", len(kevIDs))
	}

	// --nvd path: full/incremental collection from the NVD CVE API, with an
	// optional self-updating daemon loop.
	if *nvd {
		dst := *out
		if dst == "" {
			dst = defaultDBPath()
		}
		sinceT, err := parseSince(*since)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vuln update:", err)
			return 2
		}
		key := *nvdKey
		if key == "" {
			key = os.Getenv("NVD_API_KEY")
		}
		build := func(ctx context.Context, s time.Time) (*vulndb.DB, error) {
			f := &vulndb.NVDFetcher{APIKey: key, Since: s, MaxPages: *maxPages}
			return vulndb.UpdateNVD(ctx, f, *source, time.Now().UTC(), epssScores, kevIDs)
		}
		if *daemon {
			return runUpdateDaemon(build, dst, sinceT, *interval)
		}
		db, err := build(context.Background(), sinceT)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vuln update:", err)
			return 1
		}
		if err := writeDB(db, dst); err != nil {
			fmt.Fprintln(os.Stderr, "vuln update:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "vuln update: wrote %d advisories (NVD) to %s\n", db.Count(), dst)
		return 0
	}

	if *out == "" {
		fmt.Fprintln(os.Stderr, "vuln update: --out is required")
		return 2
	}

	// Split/trim --ecosystems up front: a value like "," or " , " must not be
	// treated as "an ecosystem list was provided" just because the flag
	// string itself is non-empty — every token trimming to "" leaves zero
	// real ecosystems, which is the same as not passing --ecosystems at all.
	var ecoList []string
	for _, e := range strings.Split(*ecos, ",") {
		if e = strings.TrimSpace(e); e != "" {
			ecoList = append(ecoList, e)
		}
	}
	if *from == "" && *url == "" && len(ecoList) == 0 {
		fmt.Fprintln(os.Stderr, "vuln update: provide --from <dir>, --url <mirror>, or --ecosystems <list>")
		return 2
	}

	opts := vulndb.Options{
		FromDir: *from,
		Now:     time.Now().UTC(),
		Source:  *source,
		EPSS:    epssScores,
		KEV:     kevIDs,
	}
	if *url != "" {
		opts.Fetcher = vulndb.NewHTTPFetcher(*url)
	}
	if len(ecoList) > 0 {
		var fetchers []vulndb.Fetcher
		if opts.Fetcher != nil {
			fetchers = append(fetchers, opts.Fetcher)
		}
		for _, e := range ecoList {
			fetchers = append(fetchers, vulndb.NewHTTPFetcher(vulndb.EcosystemFeedURL(e)))
		}
		opts.Fetcher = &vulndb.MultiFetcher{Fetchers: fetchers}
	}

	db, err := vulndb.Update(context.Background(), opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vuln update:", err)
		return 1
	}
	if db.Count() == 0 {
		fmt.Fprintln(os.Stderr, "vuln update: WARNING: rebuilt DB has 0 advisories (check --from/--url/--ecosystems); writing it to --out anyway rather than silently leaving a stale DB in place")
	}
	if db.SkippedRecords > 0 {
		fmt.Fprintf(os.Stderr, "vuln update: WARNING: skipped %d malformed feed record(s) while rebuilding the DB; the feed source may be partially corrupt\n", db.SkippedRecords)
	}
	if err := writeDB(db, *out); err != nil {
		fmt.Fprintln(os.Stderr, "vuln update:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "vuln update: wrote %d advisories to %s\n", db.Count(), *out)
	return 0
}

func cmdInfo(args []string) int {
	fs := flag.NewFlagSet("vuln info", flag.ContinueOnError)
	path := fs.String("db", "", "advisory DB path (default: embedded snapshot)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var (
		db  *vulndb.DB
		err error
	)
	if *path == "" {
		db, err = vulndb.Default()
	} else {
		db, err = vulndb.Open(*path)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vuln info:", err)
		return 1
	}
	fmt.Printf("advisories: %d\n", db.Count())
	fmt.Printf("built_at:   %s\n", db.BuiltAt.UTC().Format(time.RFC3339))
	fmt.Printf("source:     %s\n", db.Source)
	fmt.Printf("age:        %d days\n", int(db.Age(time.Now().UTC()).Hours()/24))
	return 0
}

// runUpdateDaemon refreshes the DB immediately and then every interval, until
// SIGINT/SIGTERM. The first refresh uses the caller's since window; subsequent
// ones use a rolling incremental window (interval + slack) so each tick fetches
// only what changed — cheap enough to run hourly/daily forever. This is the
// self-updating mode; a systemd unit or `vuln cron` (below) are the alternatives
// when a long-lived process is not wanted.
func runUpdateDaemon(build func(context.Context, time.Time) (*vulndb.DB, error), out string, firstSince time.Time, interval time.Duration) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	refresh := func(since time.Time) {
		db, err := build(ctx, since)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vuln update (daemon):", err)
			return
		}
		if err := writeDB(db, out); err != nil {
			fmt.Fprintln(os.Stderr, "vuln update (daemon):", err)
			return
		}
		fmt.Fprintf(os.Stderr, "vuln update (daemon): wrote %d advisories to %s\n", db.Count(), out)
	}

	refresh(firstSince) // initial pull
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	fmt.Fprintf(os.Stderr, "vuln update (daemon): refreshing every %s (Ctrl-C to stop)\n", interval)
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "vuln update (daemon): stopped")
			return 0
		case <-ticker.C:
			// Incremental window: interval plus slack to cover clock skew and
			// NVD's own indexing lag, so no modified CVE slips between ticks.
			refresh(time.Now().UTC().Add(-interval - 2*time.Hour))
		}
	}
}

// cmdCron installs, removes, or shows a crontab entry that runs `vuln update
// --nvd` on a schedule — the "tool updates its own database" path for hosts that
// prefer cron over a long-lived --daemon process.
//
//	dsecrat vuln cron install [--schedule "0 3 * * *"] [--out <path>] [--since 7d]
//	dsecrat vuln cron uninstall
//	dsecrat vuln cron status
func cmdCron(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "vuln cron: expected install|uninstall|status")
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("vuln cron", flag.ContinueOnError)
	schedule := fs.String("schedule", "0 3 * * *", "cron schedule (default: daily at 03:00)")
	out := fs.String("out", "", "DB path the cron job writes (default: ~/.dsecrat/vulndb.json)")
	since := fs.String("since", "7d", "incremental window the cron job pulls each run")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if _, err := exec.LookPath("crontab"); err != nil {
		fmt.Fprintln(os.Stderr, "vuln cron: crontab not found on PATH; use --daemon or a systemd timer instead")
		return 1
	}
	const marker = "# dsecrat-vuln-autoupdate"

	readCrontab := func() (string, error) {
		outB, err := exec.Command("crontab", "-l").CombinedOutput()
		if err != nil {
			// crontab -l exits non-zero when there is no crontab yet; treat as empty.
			if strings.Contains(string(outB), "no crontab") {
				return "", nil
			}
			return "", nil
		}
		return string(outB), nil
	}
	writeCrontab := func(content string) error {
		c := exec.Command("crontab", "-")
		c.Stdin = strings.NewReader(content)
		return c.Run()
	}
	// stripLine removes any existing dsecrat auto-update line(s).
	stripLine := func(cur string) string {
		var kept []string
		for _, ln := range strings.Split(cur, "\n") {
			if strings.Contains(ln, marker) {
				continue
			}
			kept = append(kept, ln)
		}
		return strings.Join(kept, "\n")
	}

	switch action {
	case "install":
		self, err := os.Executable()
		if err != nil || self == "" {
			self = "dsecrat"
		}
		dst := *out
		if dst == "" {
			dst = defaultDBPath()
		}
		cur, _ := readCrontab()
		cur = strings.TrimRight(stripLine(cur), "\n")
		line := fmt.Sprintf("%s %s vuln update --nvd --since %s --out %s %s",
			*schedule, self, *since, dst, marker)
		content := line + "\n"
		if cur != "" {
			content = cur + "\n" + line + "\n"
		}
		if err := writeCrontab(content); err != nil {
			fmt.Fprintln(os.Stderr, "vuln cron install:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "vuln cron: installed — %q\n", line)
		fmt.Fprintln(os.Stderr, "note: set NVD_API_KEY in the cron environment for the faster rate limit.")
		return 0
	case "uninstall":
		cur, _ := readCrontab()
		stripped := strings.TrimRight(stripLine(cur), "\n")
		content := ""
		if stripped != "" {
			content = stripped + "\n"
		}
		if err := writeCrontab(content); err != nil {
			fmt.Fprintln(os.Stderr, "vuln cron uninstall:", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "vuln cron: removed the dsecrat auto-update entry")
		return 0
	case "status":
		cur, _ := readCrontab()
		for _, ln := range strings.Split(cur, "\n") {
			if strings.Contains(ln, marker) {
				fmt.Println(strings.TrimSpace(ln))
				return 0
			}
		}
		fmt.Fprintln(os.Stderr, "vuln cron: no dsecrat auto-update entry installed")
		return 1
	default:
		fmt.Fprintf(os.Stderr, "vuln cron: unknown action %q (want install|uninstall|status)\n", action)
		return 2
	}
}
