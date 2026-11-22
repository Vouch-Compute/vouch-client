// Shared by the UI tests: loads i18n.js and the locale files, and evaluates a marked section of app.js with the
// i18n functions it uses (t, rich, fmt, activeLocale). Not a test itself.
const fs = require("fs");
const path = require("path");

const UI = path.join(__dirname, "..", "ui");
const NATIVE = path.join(__dirname, "..", "src-tauri", "locales");
const I18N = require(path.join(UI, "i18n.js"));
const APP_JS = fs.readFileSync(path.join(UI, "app.js"), "utf8");

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const uiMessages = (code) => readJson(path.join(UI, "locales", `${code}.json`));
const nativeMessages = (code) => readJson(path.join(NATIVE, `${code}.json`));

function useLocale(code) {
  return I18N.use(code, uiMessages(code), uiMessages(I18N.DEFAULT));
}

// Evaluate the app.js text between two markers and return the named bindings. `extra` adds parameters.
function loadSection(startMarker, endMarker, names, extra) {
  const start = APP_JS.indexOf(startMarker);
  const end = APP_JS.indexOf(endMarker);
  if (start < 0 || end < 0) throw new Error(`markers missing in app.js: ${startMarker} / ${endMarker}`);
  const params = { t: I18N.t, rich: I18N.rich, fmt: I18N.fmt, activeLocale: I18N.locale, ...(extra || {}) };
  const body = APP_JS.slice(start, end) + `; return { ${names.join(", ")} };`;
  return new Function(...Object.keys(params), body)(...Object.values(params));
}

module.exports = { I18N, APP_JS, UI, NATIVE, uiMessages, nativeMessages, useLocale, loadSection };
