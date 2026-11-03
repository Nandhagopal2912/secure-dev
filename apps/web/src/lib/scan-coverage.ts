/**
 * How many scanners have reported on a scan, in words.
 *
 * An empty `requested` means "every scanner supporting the target kind", which
 * the registry resolves in the worker, so the page has no total to show. Saying
 * "2 of 0" reads as a contradiction, and working a total out here would be a copy
 * of the registry that could only drift from it.
 */
export function scanCoverageLabel(reported: number, requested: number): string {
  return requested > 0 ? `${reported} of ${requested} reported` : `${reported} reported`;
}
