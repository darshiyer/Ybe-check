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
    const mode = body?.mode || "static"; // Default to static

    if (!rawUrl || typeof rawUrl !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid 'url' in request body" },
        { status: 400 }
      );
    }

    if (!fs.existsSync(CLI_PATH)) {
      return NextResponse.json(
        { error: `CLI not found at ${CLI_PATH}` },
        { status: 500 }
      );
    }

    tempDir = path.join(os.tmpdir(), `ybe-scan-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.mkdirSync(tempDir, { recursive: true });

    let cliArgs = `python3 "${CLI_PATH}" "${tempDir}" --json`;
    const env = { ...process.env };

    if (mode === "dynamic") {
      // DYNAMIC MODE: Validate as website URL, skip clone
      const isGithub = /github\.com\//.test(rawUrl) || (!rawUrl.startsWith("http") && rawUrl.includes("/"));
      if (isGithub) {
        return NextResponse.json(
          { error: "Dynamic analysis requires a live website URL (e.g., https://example.com), not a GitHub repository link." },
          { status: 400 }
        );
      }
      if (!rawUrl.startsWith("http")) {
        return NextResponse.json(
          { error: "Dynamic analysis requires a valid website URL (starting with http:// or https://)" },
          { status: 400 }
        );
      }
      env.YBECK_TARGET_URL = rawUrl;
      cliArgs += " --dynamic";
    } else {
      // STATIC MODE
      const isWebsite = rawUrl.startsWith("http") && !/github\.com\//.test(rawUrl);
      if (isWebsite) {
        return NextResponse.json(
          { error: "Static analysis requires a GitHub repository, not a live website URL. Please use Dynamic mode for websites." },
          { status: 400 }
        );
      }
      // Clone repository
      const repoUrl = normalizeGitUrl(rawUrl);
      execSync(`git clone --depth 1 ${repoUrl} "${tempDir}"`, {
        stdio: "pipe",
        timeout: 60_000,
      });
      cliArgs += " --static";
    }

    const output = execSync(cliArgs, {
      cwd: A2K2_DIR,
      encoding: "utf-8",
      timeout: 300_000, // Increase timeout for dynamic scans (ZAP/DOCKER take time)
      env,
    });

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
