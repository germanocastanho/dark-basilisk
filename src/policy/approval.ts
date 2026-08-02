/*
 * Copyleft 🄯 2026 Germano Castanho
 * Software licensed under GNU GPL v3
 * No gods, no masters, no copyrights
 */

/**
 * Non-interactive approval gate: denies every risky action outright. Used by
 * headless runs (`basilisk -p`), where no operator is present to say yes — an
 * autonomous run must never green-light a target-touching or state-changing tool
 * on its own. Read-only tools (public DNS/NVD lookups, local file scans) are not
 * risky and still run, so unattended recon works.
 */
export async function denyAll(_description: string): Promise<boolean> {
  return false;
}
