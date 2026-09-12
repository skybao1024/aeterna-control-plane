#!/usr/bin/env node

const chunks = [];

for await (const chunk of process.stdin) {
  chunks.push(chunk);
}

function deny(reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: reason,
      },
    }),
  );
}

function isProtectedEnvPath(value) {
  const normalized = value.replaceAll("\\", "/").replace(/^\.\//, "");
  const basename = normalized.split("/").at(-1) ?? "";

  if (basename === ".env.example") {
    return false;
  }

  if (
    (normalized === "frontend/.env.dev" ||
      normalized === "frontend/.env.prod") &&
    !value.startsWith("/")
  ) {
    return false;
  }

  return /^\.env(?:\..+)?$/.test(basename);
}

function protectedEnvReference(text) {
  const candidates = text.match(
    /(?:^|[\s"'`=:(])([^\s"'`;,|&<>()[\]{}]*\.env(?:\.[A-Za-z0-9_-]+)?)/g,
  );

  if (!candidates) {
    return null;
  }

  for (const candidate of candidates) {
    const path = candidate.trim().replace(/^["'`=:(]+/, "");
    if (isProtectedEnvPath(path)) {
      return path;
    }
  }

  return null;
}

function patchPaths(patch) {
  return [...patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)].map(
    (match) => match[1].trim(),
  );
}

let event;

try {
  event = JSON.parse(chunks.join(""));
} catch {
  deny("Safety hook could not parse the tool request; retry with valid tool input.");
  process.exit(0);
}

const toolName = event.tool_name ?? "";
const input = event.tool_input ?? {};

if (toolName === "apply_patch") {
  const protectedPath = patchPaths(
    String(input.command ?? input.patch ?? input.input ?? ""),
  ).find(isProtectedEnvPath);
  if (protectedPath) {
    deny(`Refusing to modify protected environment file: ${protectedPath}`);
  }
  process.exit(0);
}

if (toolName === "Edit" || toolName === "Write") {
  const path = String(input.file_path ?? input.path ?? "");
  if (isProtectedEnvPath(path)) {
    deny(`Refusing to modify protected environment file: ${path}`);
  }
  process.exit(0);
}

if (toolName === "Bash") {
  const command = String(input.command ?? input.cmd ?? "");
  const protectedPath = protectedEnvReference(command);

  if (protectedPath) {
    deny(
      `Refusing a command that references protected environment file ${protectedPath}. Use .env.example and sanitized diagnostics.`,
    );
    process.exit(0);
  }

  if (/\bgit\s+reset\s+--hard\b/.test(command)) {
    deny("Refusing destructive git reset --hard; use a recoverable, scoped operation.");
    process.exit(0);
  }

  if (/\bgit\s+checkout\s+--(?:\s|$)/.test(command)) {
    deny("Refusing destructive git checkout --; preserve existing user changes.");
    process.exit(0);
  }

  const rmSegment = command.match(/\brm\b[^\n;&|]*/)?.[0] ?? "";
  const recursiveForce =
    /\s-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*(?:\s|$)/.test(rmSegment) ||
    /\s-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*(?:\s|$)/.test(rmSegment) ||
    (/\s--recursive(?:\s|$)/.test(rmSegment) &&
      /\s--force(?:\s|$)/.test(rmSegment));

  if (recursiveForce) {
    deny("Refusing recursive forced deletion; resolve and validate an exact target first.");
    process.exit(0);
  }

  const hostMain =
    /\b(?:python(?:3(?:\.\d+)?)?|uv\s+run\s+python)\s+(?:[^\s]+\/)?main\.py\b/.test(
      command,
    );
  const dockerMain =
    /\bdocker\s+compose\b[^\n;&|]*\b(?:exec|run)\b[^\n;&|]*\bpython\b[^\n;&|]*\bmain\.py\b/.test(
      command,
    );

  if (hostMain && !dockerMain) {
    deny("Refusing host python main.py startup; use the repository Docker workflow.");
  }
}
