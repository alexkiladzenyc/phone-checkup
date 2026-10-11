"use strict";

// Everything shown here came from a phone, so it is untrusted text: it is only
// ever put on the page with textContent, never as HTML.

const token = document.querySelector('meta[name="phonecheck-token"]').content;
const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

let busy = false;

function setStatus(message, kind) {
  const status = $("status");
  status.textContent = message || "";
  status.className = kind || "";
}

function setBusy(value) {
  busy = value;
  $("scan").disabled = value;
  updateRemoveButton();
}

async function api(path, body) {
  const options = { headers: { "X-Phonecheck-Token": token } };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = {};
  try {
    data = await response.json();
  } catch (_) {
    /* leave data empty; the status text below covers it */
  }
  if (!response.ok) throw new Error(data.error || "Request failed (" + response.status + ")");
  return data;
}

function selectedPackages() {
  return Array.from(document.querySelectorAll('#findings input[type="checkbox"]:checked')).map((box) => box.value);
}

function updateRemoveButton() {
  const count = selectedPackages().length;
  $("remove").disabled = busy || count === 0;
  $("selected-count").textContent = count === 0 ? "Nothing selected" : count + (count === 1 ? " app selected" : " apps selected");
}

function plural(count, one, many) {
  return count + " " + (count === 1 ? one : many);
}

function card(finding) {
  const high = finding.level === "high";
  const section = el("section", "card");

  const label = el("label", "pick");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.value = finding.package;
  box.addEventListener("change", updateRemoveButton);
  label.append(box, el("span", "tag " + (high ? "high" : "med"), high ? "Likely junk" : "Worth a look"), el("span", "pkg", finding.package));
  section.append(label);

  const meta = [];
  if (finding.version) meta.push("version " + finding.version);
  if (finding.installed) meta.push("installed " + finding.installed);
  meta.push("from " + (finding.installer || "a file or a computer"));
  section.append(el("p", "meta", meta.join(" · ")));

  const reasons = el("ul");
  for (const signal of finding.signals) reasons.append(el("li", null, signal.reason));
  section.append(reasons);

  if (finding.removal_note) section.append(el("p", "note", finding.removal_note));
  return section;
}

function renderReport(report) {
  const high = report.findings.filter((f) => f.level === "high");
  const medium = report.findings.filter((f) => f.level === "medium");
  const device = report.device;

  const facts = [device.manufacturer + " " + device.model, "Android " + device.android];
  if (device.battery_level !== null) facts.push("Battery " + device.battery_level + "%");
  if (device.storage_used_pct !== null) facts.push("Storage " + device.storage_used_pct + "% full");
  facts.push(plural(report.scanned_apps, "app", "apps") + " checked");

  let kind = "ok";
  let headline = "Nothing suspicious found";
  if (high.length) {
    kind = "high";
    headline = plural(high.length, "app", "apps") + " very likely to be junk";
  } else if (medium.length) {
    kind = "med";
    headline = plural(medium.length, "app", "apps") + " worth a closer look";
  }

  const summary = $("summary");
  summary.replaceChildren(el("p", "sub", facts.join(" · ")), el("div", "banner " + kind, headline));
  if (report.findings.length === 0) {
    summary.append(
      el("p", null, "That is not proof the phone is clean: this check only sees the app details Android will share over USB.")
    );
  }
  summary.hidden = false;

  const findings = $("findings");
  findings.replaceChildren();
  for (const [title, group] of [["Likely junk", high], ["Worth a look", medium]]) {
    if (group.length === 0) continue;
    findings.append(el("h2", null, title));
    for (const finding of group) findings.append(card(finding));
  }

  const notes = $("notes");
  notes.replaceChildren();
  if (report.device_notes.length > 0) {
    const list = el("ul");
    for (const note of report.device_notes) list.append(el("li", null, note));
    notes.append(el("h2", null, "About the phone"), list);
  }
  notes.hidden = report.device_notes.length === 0;

  $("removebar").hidden = report.findings.length === 0;
  updateRemoveButton();
}

function renderResults(results) {
  const box = $("results");
  box.replaceChildren(el("h2", null, "Removal results"));
  const list = el("ul");
  for (const result of results) {
    const item = el("li", result.ok ? "ok" : "bad", (result.ok ? "Removed " : "Could not remove ") + result.package);
    if (!result.ok) {
      item.append(el("div", "note", result.hint || result.message));
    }
    list.append(item);
  }
  box.append(list);
  box.hidden = false;
}

async function scan() {
  setBusy(true);
  setStatus("Reading the phone. This can take a minute on a phone with many apps…");
  $("results").hidden = true;
  try {
    const report = await api("/api/scan", {});
    renderReport(report);
    setStatus(report.saved_as ? "Scan finished and saved to history as scan #" + report.saved_as + "." : "Scan finished.", "ok");
  } catch (error) {
    setStatus(error.message, "bad");
  } finally {
    setBusy(false);
  }
}

async function removeSelected() {
  const packages = selectedPackages();
  if (packages.length === 0) return;
  const question = "Remove " + plural(packages.length, "app", "apps") + " from this phone?\n\n" + packages.join("\n");
  if (!window.confirm(question)) return;

  setBusy(true);
  setStatus("Removing…");
  try {
    const outcome = await api("/api/remove", { packages: packages, confirm: "remove" });
    renderResults(outcome.results);
    renderReport(outcome.report);
    setStatus(outcome.results.every((r) => r.ok) ? "Done. The phone was scanned again." : "Some apps could not be removed.", outcome.results.every((r) => r.ok) ? "ok" : "bad");
  } catch (error) {
    setStatus(error.message, "bad");
  } finally {
    setBusy(false);
  }
}

async function start() {
  $("scan").addEventListener("click", scan);
  $("remove").addEventListener("click", removeSelected);
  try {
    const status = await api("/api/status");
    let line = "Using: " + status.source;
    if (status.phones.length > 0) {
      line += " · " + status.phones.map((p) => p.serial + " (" + p.state + ")").join(", ");
    }
    $("source").textContent = line;
    $("simulated").hidden = !status.simulated;
    if (status.note) setStatus(status.note, "bad");
  } catch (error) {
    $("source").textContent = "";
    setStatus(error.message, "bad");
  }
}

start();
