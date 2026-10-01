/** Loads the JSON that `site/data/regenerate.sh` wrote. Paths are relative. */

const FILES = {
  meta: "data/meta.json",
  broker: "data/broker.scan.json",
  nonconformant: "data/nonconformant.scan.json",
  conformant: "data/conformant.scan.json",
  replay: "data/nonconformant.with-deprecated-rules.scan.json",
  depFixture: "data/nonconformant.deprecations.json",
  depBroker: "data/broker.deprecations.json",
  migrate: "data/nonconformant.migrate.json",
  version: "data/sentinel-version.txt",
};

async function load(path) {
  const res = await fetch(path, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return path.endsWith(".json") ? res.json() : res.text();
}

function assertScan(name, scan) {
  if (!scan || scan.schemaVersion !== 1 || !Array.isArray(scan.findings)) {
    throw new Error(`${name} is not a schemaVersion 1 sentinel scan report`);
  }
}

export async function loadAll() {
  const entries = await Promise.all(
    Object.entries(FILES).map(async ([key, path]) => [key, await load(path)]),
  );
  const data = Object.fromEntries(entries);
  for (const key of ["broker", "nonconformant", "conformant", "replay"]) assertScan(key, data[key]);
  return data;
}
