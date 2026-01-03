import { PublicKey, Connection } from "@solana/web3.js";

/**
 * Anchor IDL PDA = seeds: ["anchor:idl", programId]
 */
function anchorIdlAddress(programId: PublicKey): PublicKey {
  const [addr] = PublicKey.findProgramAddressSync(
    [Buffer.from("anchor:idl"), programId.toBuffer()],
    programId
  );
  return addr;
}

export async function fetchIdlFromChain(
  programId: string,
  connection: Connection
): Promise<any | null> {
  try {
    const pid = new PublicKey(programId);
    const idlPda = anchorIdlAddress(pid);

    const accountInfo = await connection.getAccountInfo(idlPda);

    if (!accountInfo) return null;

    // Anchor IDL format includes an 8-byte discriminator prefix
    const data = accountInfo.data;
    const jsonString = data.slice(8).toString(); // skip discriminator

    return JSON.parse(jsonString);
  } catch (err) {
    return null;
  }
}

