// Bascule de thème : système → clair → sombre → système.
//
// Sans JavaScript, le thème suit le système et le bouton reste masqué. Le choix est
// mémorisé dans localStorage et dans un cookie que le serveur lit pour rendre
// data-theme dès la première peinture, sans script en ligne (CSP stricte). Les libellés
// arrivent traduits dans les attributs data-label-*.

const STORAGE_KEY = "ogsbom.theme";
const COOKIE = "ogsbom_theme";
const ORDER = ["system", "light", "dark"];

function readStored() {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStored(theme) {
  try {
    if (theme === "system") {
      localStorage.removeItem(STORAGE_KEY);
    } else {
      localStorage.setItem(STORAGE_KEY, theme);
    }
  } catch {
    // Stockage indisponible (navigation privée, quota) : le cookie suffit.
  }
}

function writeCookie(theme) {
  const secure = location.protocol === "https:" ? "; Secure" : "";
  document.cookie = theme === "system"
    ? `${COOKIE}=; Path=/; Max-Age=0; SameSite=Lax${secure}`
    : `${COOKIE}=${theme}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
}

function current() {
  const theme = document.documentElement.dataset.theme;
  return theme === "light" || theme === "dark" ? theme : "system";
}

function apply(theme) {
  const root = document.documentElement;
  if (theme === "light" || theme === "dark") {
    root.dataset.theme = theme;
  } else {
    delete root.dataset.theme;
  }
}

function labelFor(button, theme) {
  const key = "label" + theme.charAt(0).toUpperCase() + theme.slice(1);
  return button.dataset[key] ?? button.textContent;
}

// Le cookie a pu disparaître alors que localStorage garde le choix : on resynchronise.
const stored = readStored();
if ((stored === "light" || stored === "dark") && stored !== current()) {
  apply(stored);
  writeCookie(stored);
}

const buttons = document.querySelectorAll("[data-theme-toggle]");

function refresh() {
  for (const button of buttons) {
    button.textContent = labelFor(button, current());
  }
}

for (const button of buttons) {
  button.hidden = false;
  button.addEventListener("click", () => {
    const next = ORDER[(ORDER.indexOf(current()) + 1) % ORDER.length];
    apply(next);
    writeStored(next);
    writeCookie(next);
    refresh();
  });
}
refresh();
