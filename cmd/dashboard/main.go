// Dashboard reads alerts.jsonl (written by cmd/agent) and serves a simple
// live-updating web view. Run this as a regular user — unlike the agent,
// it never touches eBPF or the kernel, it just reads a log file, so it
// does NOT need sudo.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"sort"
	"time"
)

// Alert mirrors the Alert struct written by cmd/agent/main.go. Kept as a
// separate copy here rather than a shared internal package — this project
// is small enough that duplicating one struct is simpler than the extra
// module wiring a shared package would need.
type Alert struct {
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	Comm      string    `json:"comm"`
	Detail    string    `json:"detail"`
}

// readAlerts parses alerts.jsonl fresh on every call. Re-reading the whole
// file each request is intentionally simple — for a resume/demo project
// serving a handful of dashboard clients, this is more than fast enough,
// and it avoids the complexity of tailing a live-appended file correctly.
func readAlerts(path string, limit int) ([]Alert, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Alert{}, nil // no alerts yet isn't an error
		}
		return nil, err
	}
	defer f.Close()

	var alerts []Alert
	scanner := bufio.NewScanner(f)
	// Give lines generous room; the default 64KB scanner buffer is plenty
	// here but this makes the ceiling explicit rather than implicit.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var a Alert
		if err := json.Unmarshal(line, &a); err != nil {
			continue // skip a malformed line rather than failing the whole read
		}
		alerts = append(alerts, a)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Newest first — that's what you want to see on a live dashboard.
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})

	if limit > 0 && len(alerts) > limit {
		alerts = alerts[:limit]
	}
	return alerts, nil
}

func main() {
	alertLogPath := flag.String("alertlog", "alerts.jsonl", "path to the agent's alerts.jsonl file")
	addr := flag.String("addr", ":8080", "address to serve the dashboard on")
	limit := flag.Int("limit", 200, "max number of recent alerts to show")
	flag.Parse()

	http.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		alerts, err := readAlerts(*alertLogPath, *limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(alerts); err != nil {
			log.Printf("encoding response: %v", err)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	log.Printf("dashboard serving on http://localhost%s (reading %s)", *addr, *alertLogPath)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// dashboardHTML is a single self-contained page: no build step, no
// external JS dependencies, just fetch() polling the API above. Kept
// inline in the Go binary so the whole dashboard is one file to run.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>eBPF Threat Detector — Live Alerts</title>
<style>
  :root {
    --bg: #0b0f14;
    --panel: #121820;
    --border: #1f2937;
    --text: #e5e7eb;
    --muted: #8b98a5;
    --high: #f87171;
    --high-bg: #3b1414;
    --medium: #fbbf24;
    --medium-bg: #3a2c0a;
    --accent: #38bdf8;
    --mono: "SF Mono", "Fira Code", ui-monospace, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    padding: 32px;
  }
  header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    margin-bottom: 24px;
    flex-wrap: wrap;
    gap: 12px;
  }
  h1 {
    font-size: 20px;
    font-weight: 600;
    margin: 0;
    letter-spacing: -0.01em;
  }
  h1 span { color: var(--accent); }
  .status {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    font-size: 13px;
    font-family: var(--mono);
  }
  .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #34d399;
    box-shadow: 0 0 8px #34d399;
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
  }
  .card .n { font-size: 26px; font-weight: 700; font-family: var(--mono); }
  .card .l { font-size: 12px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
  .card.high .n { color: var(--high); }
  .card.medium .n { color: var(--medium); }

  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    font-size: 13px;
  }
  thead th {
    text-align: left;
    padding: 10px 14px;
    color: var(--muted);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border-bottom: 1px solid var(--border);
  }
  tbody td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    white-space: nowrap;
  }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: #16202b; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .badge.high { background: var(--high-bg); color: var(--high); }
  .badge.medium { background: var(--medium-bg); color: var(--medium); }
  .kind { color: var(--accent); }
  .detail { color: var(--text); max-width: 360px; overflow: hidden; text-overflow: ellipsis; }
  .empty {
    text-align: center;
    padding: 48px;
    color: var(--muted);
    font-family: var(--mono);
  }
</style>
</head>
<body>
  <header>
    <h1>eBPF Threat Detector — <span>Live Alerts</span></h1>
    <div class="status"><span class="dot"></span><span id="updated">connecting…</span></div>
  </header>

  <div class="cards">
    <div class="card"><div class="n" id="total">0</div><div class="l">Total Alerts</div></div>
    <div class="card high"><div class="n" id="highCount">0</div><div class="l">High Severity</div></div>
    <div class="card medium"><div class="n" id="medCount">0</div><div class="l">Medium Severity</div></div>
    <div class="card"><div class="n" id="pidCount">0</div><div class="l">Unique Processes</div></div>
  </div>

  <table id="alertTable">
    <thead>
      <tr>
        <th>Time</th><th>Severity</th><th>Kind</th><th>PID</th><th>UID</th><th>Comm</th><th>Detail</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>

<script>
async function refresh() {
  try {
    const res = await fetch('/api/alerts');
    const alerts = await res.json();

    const rows = document.getElementById('rows');
    const highCount = alerts.filter(a => a.severity === 'high').length;
    const medCount = alerts.filter(a => a.severity === 'medium').length;
    const pids = new Set(alerts.map(a => a.pid));

    document.getElementById('total').textContent = alerts.length;
    document.getElementById('highCount').textContent = highCount;
    document.getElementById('medCount').textContent = medCount;
    document.getElementById('pidCount').textContent = pids.size;
    document.getElementById('updated').textContent =
      'live · updated ' + new Date().toLocaleTimeString();

    if (alerts.length === 0) {
      rows.innerHTML = '<tr><td colspan="7" class="empty">No alerts yet — trigger one to see it appear here.</td></tr>';
      return;
    }

    rows.innerHTML = alerts.map(a => {
      const t = new Date(a.timestamp).toLocaleTimeString();
      const detail = a.detail ? a.detail : '—';
      return '<tr>' +
        '<td>' + t + '</td>' +
        '<td><span class="badge ' + a.severity + '">' + a.severity + '</span></td>' +
        '<td class="kind">' + a.kind + '</td>' +
        '<td>' + a.pid + '</td>' +
        '<td>' + a.uid + '</td>' +
        '<td>' + a.comm + '</td>' +
        '<td class="detail">' + detail + '</td>' +
        '</tr>';
    }).join('');
  } catch (e) {
    document.getElementById('updated').textContent = 'connection lost — retrying…';
  }
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
`