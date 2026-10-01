import { loadAll } from "./data.js";
import { h, mount, replaceContent } from "./dom.js";
import { formatDate } from "./model.js";
import { renderVerdicts } from "./verdicts.js";
import { createViewer } from "./viewer.js";
import { renderIndeterminate } from "./indeterminate.js";
import { renderTimeline } from "./timeline.js";
import { renderMigration } from "./migration.js";
import { renderLifecycle } from "./lifecycle.js";

function bind(name, value) {
  for (const el of document.querySelectorAll(`[data-bind="${name}"]`)) {
    el.textContent = String(value);
  }
}

function showError(error) {
  console.error("sentinel showcase: could not load scan data", error);
  for (const name of ["verdicts", "indeterminate", "timeline", "migration", "lifecycle"]) {
    try {
      replaceContent(mount(name), h("p", { class: "load-error", text: `Could not load the scan data (${error.message}). The raw JSON is in site/data.` }));
    } catch {
      /* a missing mount is reported by the first failure already */
    }
  }
}

async function start() {
  let data;
  try {
    data = await loadAll();
  } catch (error) {
    showError(error);
    return;
  }
  bind("spec", data.nonconformant.specRevision);
  bind("version", data.version.trim().split(" (")[0]);
  bind("asOf", formatDate(data.meta.asOf));
  for (const el of document.querySelectorAll('time[data-bind="asOf"]')) el.setAttribute("datetime", data.meta.asOf);
  bind("ruleCount", data.nonconformant.findings.length);

  const viewer = createViewer(data);
  renderVerdicts(data, (key) => viewer.show(key));
  renderIndeterminate(data);
  renderTimeline(data);
  renderMigration(data);
  renderLifecycle(data);
}

start();
