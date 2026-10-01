/** §4: each deprecated feature on a shared time axis, ending at its removal window. */
import { h, mount, replaceContent, safeHref } from "./dom.js";
import { formatDate } from "./model.js";

const DOMAIN_START = Date.UTC(2025, 0, 1);
const DOMAIN_END = Date.UTC(2028, 0, 1);
const YEARS = [2025, 2026, 2027, 2028];

const toMs = (iso) => Date.parse(`${iso}T00:00:00Z`);
const pct = (ms) => `${(((ms - DOMAIN_START) / (DOMAIN_END - DOMAIN_START)) * 100).toFixed(3)}%`;

function removalText(removal) {
  if (removal.kind === "fixed_revision") {
    const left = removal.monthsRemaining;
    return `removable on or after ${formatDate(removal.onOrAfter)}${left === null ? "" : ` · ${left} month${left === 1 ? "" : "s"} from the scan`}`;
  }
  return `removable ${removal.condition}`;
}

function track(feature, asOf) {
  const start = toMs(feature.deprecatedOn);
  const fixed = feature.removal.kind === "fixed_revision";
  const end = fixed ? toMs(feature.removal.onOrAfter) : DOMAIN_END;
  return h("div", { class: "track", attrs: { "aria-hidden": "true" } },
    YEARS.map((y) => h("span", { class: "track__tick", vars: { "--x": pct(Date.UTC(y, 0, 1)) } })),
    h("span", {
      class: `track__span ${fixed ? "" : "track__span--open"}`,
      vars: { "--from": pct(start), "--to": pct(end) },
    }),
    h("span", { class: "track__dot", vars: { "--x": pct(start) } }),
    fixed ? h("span", { class: "track__end", vars: { "--x": pct(end) } }) : null,
    h("span", { class: "track__now", vars: { "--x": pct(toMs(asOf)) } }),
  );
}

function status(label, detection) {
  const used = detection?.inUse;
  return h("div", { class: `usage ${used ? "usage--in" : "usage--out"}` },
    h("dt", { text: label }),
    h("dd", {},
      h("span", { class: `tag ${used ? "tag--fail" : "tag--pass"}`, text: used ? "In use" : "Not in use" }),
      h("span", { class: "usage__conf", text: detection ? detection.confidence : "not scanned" }),
      detection ? h("span", { class: "usage__evidence", text: detection.evidence }) : null,
    ),
  );
}

export function renderTimeline(data) {
  const fixture = data.depFixture;
  const broker = new Map(data.depBroker.features.map((f) => [f.id, f]));
  const inUse = fixture.features.filter((f) => f.inUse).length;
  const brokerInUse = data.depBroker.features.filter((f) => f.inUse).length;

  const axisTrack = h("div", { class: "axis" },
    YEARS.map((y) => h("span", { class: "axis__year", vars: { "--x": pct(Date.UTC(y, 0, 1)) }, text: y })),
    h("span", { class: "axis__now", vars: { "--x": pct(toMs(fixture.asOf)) }, text: `scan ${formatDate(fixture.asOf)}` }),
  );
  const axis = h("div", { class: "dep dep--axis", attrs: { "aria-hidden": "true" } }, h("span"), axisTrack, h("span"));

  const rows = fixture.features.map((f) => {
    const href = safeHref(f.citation);
    return h("li", { class: "dep" },
      h("div", { class: "dep__name" },
        h("h3", { text: f.name }),
        h("p", { class: "dep__meta" },
          f.sep ? `${f.sep} · ` : "",
          `deprecated ${formatDate(f.deprecatedOn)}`,
        ),
      ),
      h("div", { class: "dep__time" },
        track(f, fixture.asOf),
        h("p", { class: "dep__removal", text: removalText(f.removal) }),
        h("p", { class: "dep__replace" }, h("span", { class: "muted", text: "replace with " }), f.replacement),
        href ? h("p", { class: "dep__cite" }, h("a", { attrs: { href, rel: "noopener" }, text: "spec changelog" })) : null,
      ),
      h("dl", { class: "dep__usage" },
        status("Unmigrated", f),
        status("Broker", broker.get(f.id)),
      ),
    );
  });

  replaceContent(mount("timeline"),
    h("p", { class: "dep__headline" },
      h("span", { class: "figure", text: inUse }),
      h("span", {}, ` of ${fixture.features.length} deprecated features are in use by the unmigrated server. The broker uses `,
        h("strong", { text: brokerInUse }), "."),
    ),
    h("p", { class: "dep__legend" },
      h("span", { class: "legend legend--dot", text: "deprecated" }),
      h("span", { class: "legend legend--span", text: "notice window" }),
      h("span", { class: "legend legend--end", text: "earliest removal" }),
      h("span", { class: "legend legend--open", text: "event-relative removal" }),
      h("span", { class: "legend legend--now", text: "date of scan" }),
    ),
    h("div", { class: "deps" }, axis, h("ol", { class: "deps__list" }, rows)),
    h("p", { class: "cite", text: `Inventory as of ${fixture.asOf}. Minimum notice: ${fixture.minimumNoticeMonths} months. Source: data/nonconformant.deprecations.json and data/broker.deprecations.json.` }),
  );
}
