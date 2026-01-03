import * as fs from "fs/promises";
import * as path from "path";

export async function fetchIdlFromRepo(repoPath: string): Promise<any | null> {
  const idlDir = path.join(repoPath, "target/idl");

  try {
    // Check if directory exists (async)
    await fs.access(idlDir);
  } catch {
    return null;
  }

  try {
    const files = await fs.readdir(idlDir);
    const idlFiles = files.filter(f => f.endsWith(".json"));
    
    if (idlFiles.length === 0) return null;

    const idlPath = path.join(idlDir, idlFiles[0]);
    const raw = await fs.readFile(idlPath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

