// TODO: passer à lodash 4.17.21 quand la migration sera faite.
// Nous avons retiré moment 2.29.4 au profit de Intl.DateTimeFormat.
export function format(d) {
  return new Intl.DateTimeFormat("fr-FR").format(d);
}
