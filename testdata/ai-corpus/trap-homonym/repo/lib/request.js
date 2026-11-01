// request v2.0.1 — utilitaire HTTP interne de l'équipe, sans rapport avec le paquet npm.
export async function request(url) {
  const r = await fetch(url);
  return r.json();
}
