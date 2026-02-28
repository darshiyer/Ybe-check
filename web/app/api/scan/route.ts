import { NextRequest, NextResponse } from "next/server";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

const A2K2_DIR = path.resolve(process.cwd(), "..", "A2K2");
const CLI_PATH = path.join(A2K2_DIR, "cli.py");

function normalizeGitUrl(url: string): string {
  let u = url.trim();
  if (!u.startsWith("http") && !u.startsWith("git@")) {
    u = `https://github.com/${u.replace(/^\/+/, "")}`;
  }
  if (!u.endsWith(".git")) {
    u = u.replace(/\/$/, "") + ".git";
  }
  return u;
}

export async function POST(request: NextRequest) {
  let tempDir: string | null = null;

  try {
    const body = await request.json();
    const rawUrl = body?.url;
    if (!rawUrl || typeof rawUrl !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid 'url' in request body" },
        { status: 400 }
      );
    }

    const repoUrl = normalizeGitUrl(rawUrl);

    if (!fs.existsSync(CLI_PATH)) {
      return NextResponse.json(
        { error: `CLI not found at ${CLI_PATH}` },
        { status: 500 }
      );
    }

    tempDir = path.join(os.tmpdir(), `ybe-scan-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.mkdirSync(tempDir, { recursive: true });

    execSync(`git clone --depth 1 ${repoUrl} "${tempDir}"`, {
      stdio: "pipe",
      timeout: 60_000,
    });

    const output = execSync(
      `python3 "${CLI_PATH}" "${tempDir}" --json`,
      {
        cwd: A2K2_DIR,
        encoding: "utf-8",
        timeout: 120_000,
      }
    );

    const report = JSON.parse(output.trim());
    return NextResponse.json(report);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("fatal:") || message.includes("Repository not found")) {
      return NextResponse.json(
        { error: "Could not clone repository. Check the URL and try again." },
        { status: 400 }
      );
    }
    return NextResponse.json(
      { error: message || "Scan failed" },
      { status: 500 }
    );
  } finally {
    if (tempDir && fs.existsSync(tempDir)) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
  }
}
