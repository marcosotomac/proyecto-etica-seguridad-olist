/** Une clases CSS condicionales (sustituye al paquete `cn`, retirado tras npm audit). */
export function cn(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ")
}
