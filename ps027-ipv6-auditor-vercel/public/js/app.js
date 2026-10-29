(function () {
  var HEX = ["2001", "0db8", "a1c4", "5e07", "00ff", "9b3d", "7c20", "1f88"];
  var DC = [["Apex AAAA", 15, .7, "Domain resolves to an IPv6 address", "Add an AAAA record for the root domain."], ["www AAAA", 10, .72, "www host resolves over IPv6", "Add an AAAA record for www."], ["Nameservers", 15, .62, "Authoritative servers answer over IPv6", "Enable IPv6 on at least two nameservers."], ["Mail (MX)", 5, .55, "Mail exchangers have AAAA records", "Give each MX host an AAAA record."], ["HTTPS on IPv6", 20, .68, "Port 443 accepts connections over IPv6", "Bind the web server and firewall to IPv6."], ["TLS on IPv6", 10, .8, "Certificate valid over IPv6", "Serve the same certificate on both families."], ["Dependencies", 15, .6, "Third-party hosts reachable over IPv6", "Replace or proxy IPv4-only hosts."], ["IPv6-only test", 10, .58, "Page loads without IPv4", "Remove hard-coded IPv4 literals."]];
  var POOL = [["fonts.googleapis.com", 1], ["cdn.jsdelivr.net", 1], ["cdnjs.cloudflare.com", 1], ["www.googletagmanager.com", 1], ["api.payments.example", .7], ["js.heatmap-tool.example", .45], ["ads.legacy-network.example", .1], ["img.cdn-v4only.example", 0]];
  var LABEL = { pass: "Pass", warn: "Review", fail: "Fail", info: "Not tested" };

  function $(i) { return document.getElementById(i); }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function hash(s) { var x = 1779033703 ^ s.length; for (var i = 0; i < s.length; i++) { x = Math.imul(x ^ s.charCodeAt(i), 3432918353); x = x << 13 | x >>> 19; } return x >>> 0; }
  function rng(a) { return function () { a |= 0; a = a + 1831565813 | 0; var t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
  function host(v) { return v.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[\/?#].*$/, "").replace(/^www\./, ""); }
  function verdict(s) { return s >= 85 ? "IPv6 ready" : s >= 60 ? "Partly ready" : "Not ready for IPv6 users"; }

  // Simulated results, used only when the backend cannot be reached
  function demo(d) {
    var r = rng(hash(d)), n = 5 + Math.floor(r() * 3), pool = POOL.slice(), deps = [], bad = 0, i;
    for (i = 0; i < n && pool.length; i++) { var e = pool.splice(Math.floor(r() * pool.length), 1)[0]; var ok = r() < e[1]; if (!ok) bad++; deps.push({ host: e[0], v6: ok, v4: true }); }
    var checks = DC.map(function (c) {
      var v = r(), s;
      if (c[0] === "Dependencies") s = bad === 0 ? "pass" : bad <= 2 ? "warn" : "fail";
      else s = v < c[2] ? "pass" : v < c[2] + .14 ? "warn" : "fail";
      return { k: c[0], w: c[1], status: s, detail: c[3], fix: s === "pass" ? "" : c[4] };
    });
    var s = 0; checks.forEach(function (c) { s += c.w * (c.status === "pass" ? 1 : c.status === "warn" ? .5 : 0); });
    s = Math.round(s);
    return { domain: d, mode: "demo", score: s, verdict: verdict(s), checks: checks, deps: deps, ipv6Egress: true };
  }

  function render(data) {
    var c = data.checks, sc = data.score;
    var stamp = data.mode === "live" ? "live results" : "simulated data";
    $("target").innerHTML = "<b>" + esc(data.domain) + "</b><br>Report ID SC-" + hash(data.domain).toString(16).toUpperCase().slice(0, 6) + "<br>Generated " + new Date().toLocaleString() + " (" + stamp + ")";
    $("mode").textContent = data.mode === "live"
      ? "Live mode. DNS lookups, TLS checks and the dependency crawl ran on the server just now." + (data.ipv6Egress === false ? " This server has no outbound IPv6, so the HTTPS and TLS over IPv6 checks are marked Not tested and left out of the score." : "")
      : "Demo mode. The backend could not be reached, so these results are simulated.";
    $("addr").innerHTML = c.map(function (x, j) { return '<div class="hx ' + x.status + '" title="' + esc(x.k) + ': ' + LABEL[x.status] + '"><b>' + HEX[j] + '</b><span>' + esc(x.k) + '</span></div>'; }).join("");
    $("score").textContent = sc + "/100";
    var col = sc >= 85 ? "var(--pass)" : sc >= 60 ? "var(--warn)" : "var(--fail)";
    $("score").style.color = col; $("ring").style.setProperty("--c", col); $("ring").style.setProperty("--p", sc);
    $("verdict").textContent = data.verdict;
    $("checks").innerHTML = c.map(function (x) { return '<div class="row"><div><b>' + esc(x.k) + '</b><small>Weight ' + x.w + '</small></div><div><span class="pill ' + x.status + '">' + LABEL[x.status] + '</span></div><div>' + esc(x.detail) + (x.fix ? '<small>' + esc(x.fix) + '</small>' : "") + '</div></div>'; }).join("");
    $("deps").innerHTML = data.deps.length ? '<tr><th>Host</th><th>IPv6</th><th>Impact</th></tr>' + data.deps.map(function (x) {
      var st = x.v6 ? "pass" : x.v4 ? "fail" : "info", t = x.v6 ? "Reachable" : x.v4 ? "IPv4 only" : "No address";
      return '<tr><td class="mono">' + esc(x.host) + '</td><td><span class="pill ' + st + '">' + t + '</span></td><td>' + (st === "fail" ? "IPv6-only visitors may see slow or broken loads" : "None") + '</td></tr>';
    }).join("") : '<tr><td>No third-party hosts were found on the home page.</td></tr>';
    var fx = c.filter(function (x) { return x.status === "warn" || x.status === "fail"; }).sort(function (a, b) { return b.w * (b.status === "fail" ? 1 : .5) - a.w * (a.status === "fail" ? 1 : .5); });
    $("fixes").innerHTML = fx.length ? fx.slice(0, 4).map(function (x) { return '<div class="row"><div><b>' + esc(x.k) + '</b></div><div><span class="pill ' + x.status + '">' + LABEL[x.status] + '</span></div><div>' + esc(x.fix) + '</div></div>'; }).join("") : '<div class="row"><div><b>No action needed</b></div><div></div><div>No failing checks.</div></div>';
    $("result").style.display = "block";
    $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function showError(msg) {
    $("result").style.display = "block"; $("target").textContent = msg;
    ["addr", "checks", "deps", "fixes", "score", "verdict"].forEach(function (i) { $(i).innerHTML = ""; });
  }

  async function audit() {
    var d = host($("dom").value);
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) { $("dom").style.borderColor = "var(--fail)"; showError("Enter a valid domain such as example.org"); return; }
    $("dom").style.borderColor = "";
    $("go").disabled = true; $("go").textContent = "Auditing\u2026";
    try {
      var data;
      try {
        var r = await fetch("/api/audit?domain=" + encodeURIComponent(d));
        var j = await r.json();
        if (r.status === 400) { showError(j.error); return; }
        if (!r.ok || !j.checks) throw new Error("backend");
        data = j;
      } catch (e) { data = demo(d); }
      render(data);
    } finally { $("go").disabled = false; $("go").textContent = "Run audit"; }
  }

  $("go").addEventListener("click", audit);
  $("pr").addEventListener("click", function () { window.print(); });
  $("dom").addEventListener("keydown", function (e) { if (e.key === "Enter") audit(); });
  document.querySelectorAll("[data-d]").forEach(function (b) { b.addEventListener("click", function () { $("dom").value = b.getAttribute("data-d"); audit(); }); });
})();
