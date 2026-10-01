/**
 * The one DOM helper. Every string from a report goes through a text node, so
 * nothing the scanned server said can become markup on this page.
 */
export function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  const { class: className, text, attrs, on, dataset, vars } = props;
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (attrs) {
    for (const [name, value] of Object.entries(attrs)) {
      if (value === false || value === null || value === undefined) continue;
      el.setAttribute(name, value === true ? "" : String(value));
    }
  }
  if (dataset) Object.assign(el.dataset, dataset);
  // Custom properties go through the CSSOM: the page's CSP forbids style attributes.
  if (vars) for (const [name, value] of Object.entries(vars)) el.style.setProperty(name, value);
  if (on) for (const [type, fn] of Object.entries(on)) el.addEventListener(type, fn);
  append(el, children);
  return el;
}

export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

export function mount(name) {
  const el = document.querySelector(`[data-mount="${name}"]`);
  if (!el) throw new Error(`missing mount point: ${name}`);
  return el;
}

export function replaceContent(el, ...children) {
  el.replaceChildren();
  return append(el, children);
}

/** Only http(s) URLs become links; anything else renders as text. */
export function safeHref(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : null;
  } catch {
    return null;
  }
}
