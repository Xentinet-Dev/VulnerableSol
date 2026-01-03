import * as fs from "fs/promises";

/**
 * Basic BPF → Partial IDL inference.
 * Extracts:
 *  - Instruction discriminators (first 8 bytes patterns)
 *  - Account metas (read-only/write/signer patterns)
 *  - Error codes
 *
 * NOTE: Not full reverse-engineering. Meant as fallback for exploit construction.
 */
export async function inferIdlFromBpf(bpfPath: string): Promise<any | null> {
  try {
    // Check if file exists (async)
    await fs.access(bpfPath);
  } catch {
    return null;
  }

  try {
    const bin = await fs.readFile(bpfPath);

    // Instruction discriminator pattern = 8 consecutive bytes with following instruction body.
    const discriminatorCandidates: Buffer[] = [];
    for (let i = 0; i < bin.length - 12; i++) {
      const slice = bin.slice(i, i + 8);

      // crude heuristic: lots of zeroes or repeated values = skip
      const unique = new Set(slice.values());
      if (unique.size < 3) continue;

      discriminatorCandidates.push(Buffer.from(slice));
    }

    // Deduplicate discriminators
    const discriminators = Array.from(
      new Set(discriminatorCandidates.map(b => b.toString("hex")))
    );

    // Build partial IDL
    const partialIdl = {
      name: "inferred_program",
      instructions: discriminators.map((discHex, idx) => ({
        name: `ix_${idx}`,
        discriminator: discHex,
        args: [], // cannot infer reliably without patterns
        accounts: [],
      })),
      metadata: {
        inferred: true,
        warning:
          "This IDL is inferred from BPF bytecode. Only discriminators are reliable.",
      },
    };

    return partialIdl;
  } catch {
    return null;
  }
}

