import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { loadConfig, type OpenClawConfig } from "../../config/config.js";
import { startBrowserBridgeServer, stopBrowserBridgeServer } from "../../browser/bridge-server.js";
import { type ResolvedBrowserConfig, resolveProfile } from "../../browser/config.js";
import {
  DEFAULT_BROWSER_EVALUATE_ENABLED,
  DEFAULT_OPENCLAW_BROWSER_COLOR,
  DEFAULT_OPENCLAW_BROWSER_PROFILE_NAME,
} from "../../browser/constants.js";
import { deriveDefaultBrowserCdpPortRange } from "../../config/port-defaults.js";
import { defaultRuntime } from "../../runtime.js";
import { normalizeAgentId } from "../../routing/session-key.js";
import { BROWSER_BRIDGES } from "./browser-bridges.js";
import { computeSandboxBrowserConfigHash } from "./config-hash.js";
import { resolveSandboxBrowserDockerCreateConfig, resolveSandboxConfigForAgent } from "./config.js";
import { DEFAULT_SANDBOX_BROWSER_IMAGE, SANDBOX_BROWSER_SECURITY_HASH_EPOCH } from "./constants.js";
import {
  buildSandboxCreateArgs,
  dockerContainerState,
  execDocker,
  readDockerContainerEnvVar,
  readDockerContainerLabel,
  readDockerPort,
} from "./docker.js";
import {
  buildNoVncObserverTokenUrl,
  consumeNoVncObserverToken,
  generateNoVncPassword,
  isNoVncEnabled,
  NOVNC_PASSWORD_ENV_KEY,
  issueNoVncObserverToken,
} from "./novnc-auth.js";
import {
  readBrowserRegistry,
  removeBrowserRegistryEntry,
  updateBrowserRegistry,
  type SandboxBrowserRegistryEntry,
} from "./registry.js";
import {
  resolveSandboxAgentId,
  resolveSandboxBrowserOwnerKey,
  resolveSandboxBrowserStateDir,
  slugifySessionKey,
} from "./shared.js";
import { isToolAllowed } from "./tool-policy.js";
import type { SandboxBrowserContext, SandboxConfig } from "./types.js";
import { validateNetworkMode } from "./validate-sandbox-security.js";

const HOT_BROWSER_WINDOW_MS = 5 * 60 * 1000;
const BROWSER_SWEEP_INTERVAL_MS = 60_000;
const BROWSER_STATE_CONTAINER_ROOT = "/state";
const BROWSER_HOME_ENV_KEY = "OPENCLAW_BROWSER_HOME";
const BROWSER_USER_DATA_DIR_ENV_KEY = "OPENCLAW_BROWSER_USER_DATA_DIR";
const DEFAULT_BROWSER_HOME = `${BROWSER_STATE_CONTAINER_ROOT}/home`;
const DEFAULT_BROWSER_USER_DATA_DIR = `${DEFAULT_BROWSER_HOME}/.chrome`;
const CDP_SOURCE_RANGE_ENV_KEY = "OPENCLAW_BROWSER_CDP_SOURCE_RANGE";

const BROWSER_LIFECYCLE_LOCKS = new Map<string, Promise<void>>();
let browserSweeperStarted = false;

async function waitForSandboxCdp(params: { cdpPort: number; timeoutMs: number }): Promise<boolean> {
  const deadline = Date.now() + Math.max(0, params.timeoutMs);
  const url = `http://127.0.0.1:${params.cdpPort}/json/version`;
  while (Date.now() < deadline) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(ctrl.abort.bind(ctrl), 1000);
      try {
        const res = await fetch(url, { signal: ctrl.signal });
        if (res.ok) {
          return true;
        }
      } finally {
        clearTimeout(t);
      }
    } catch {
      // ignore
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

function buildSandboxBrowserResolvedConfig(params: {
  controlPort: number;
  cdpPort: number;
  headless: boolean;
  evaluateEnabled: boolean;
}): ResolvedBrowserConfig {
  const cdpHost = "127.0.0.1";
  const cdpPortRange = deriveDefaultBrowserCdpPortRange(params.controlPort);
  return {
    enabled: true,
    evaluateEnabled: params.evaluateEnabled,
    controlPort: params.controlPort,
    cdpProtocol: "http",
    cdpHost,
    cdpIsLoopback: true,
    cdpPortRangeStart: cdpPortRange.start,
    cdpPortRangeEnd: cdpPortRange.end,
    remoteCdpTimeoutMs: 1500,
    remoteCdpHandshakeTimeoutMs: 3000,
    color: DEFAULT_OPENCLAW_BROWSER_COLOR,
    executablePath: undefined,
    headless: params.headless,
    noSandbox: false,
    attachOnly: true,
    defaultProfile: DEFAULT_OPENCLAW_BROWSER_PROFILE_NAME,
    extraArgs: [],
    profiles: {
      [DEFAULT_OPENCLAW_BROWSER_PROFILE_NAME]: {
        cdpPort: params.cdpPort,
        color: DEFAULT_OPENCLAW_BROWSER_COLOR,
      },
    },
  };
}

async function ensureSandboxBrowserImage(image: string) {
  const result = await execDocker(["image", "inspect", image], {
    allowFailure: true,
  });
  if (result.code === 0) {
    return;
  }
  throw new Error(
    `Sandbox browser image not found: ${image}. Build it with scripts/sandbox-browser-setup.sh.`,
  );
}

async function ensureDockerNetwork(
  network: string,
  opts?: { allowContainerNamespaceJoin?: boolean },
) {
  validateNetworkMode(network, {
    allowContainerNamespaceJoin: opts?.allowContainerNamespaceJoin === true,
  });
  const normalized = network.trim().toLowerCase();
  if (!normalized || normalized === "bridge" || normalized === "none") {
    return;
  }
  const inspect = await execDocker(["network", "inspect", network], { allowFailure: true });
  if (inspect.code === 0) {
    return;
  }
  await execDocker(["network", "create", "--driver", "bridge", network]);
}

function parseDockerUserUidGid(user?: string): { uid: number; gid: number } | null {
  const trimmed = user?.trim();
  if (!trimmed) {
    return null;
  }
  const match = /^(\d+)(?::(\d+))?$/.exec(trimmed);
  if (!match) {
    return null;
  }
  const uid = Number.parseInt(match[1] ?? "", 10);
  const gid = Number.parseInt(match[2] ?? match[1] ?? "", 10);
  if (!Number.isFinite(uid) || !Number.isFinite(gid) || uid < 0 || gid < 0) {
    return null;
  }
  return { uid, gid };
}

async function ensureStatePathPermissions(
  targetPath: string,
  owner: { uid: number; gid: number } | null,
) {
  await fs.mkdir(targetPath, { recursive: true, mode: 0o700 });
  await fs.chmod(targetPath, 0o700).catch(() => undefined);
  if (owner) {
    await fs.chown(targetPath, owner.uid, owner.gid).catch(() => undefined);
  }
}

async function ensureSandboxBrowserState(params: {
  cfg: SandboxConfig;
  ownerKey: string;
}): Promise<{ stateDir: string; homeDir: string; userDataDir: string } | null> {
  if (!params.cfg.browser.state.enabled) {
    return null;
  }
  const agentId = resolveSandboxAgentId(params.ownerKey) ?? "main";
  const stateDir = resolveSandboxBrowserStateDir(params.cfg.browser.state.root, agentId);
  const homeDir = path.join(stateDir, "home");
  const userDataDir = path.join(homeDir, ".chrome");
  const owner = parseDockerUserUidGid(params.cfg.docker.user);
  await ensureStatePathPermissions(stateDir, owner);
  await ensureStatePathPermissions(homeDir, owner);
  await ensureStatePathPermissions(userDataDir, owner);
  return { stateDir, homeDir, userDataDir };
}

async function touchBrowserStateDir(stateDir?: string, atMs = Date.now()) {
  if (!stateDir) {
    return;
  }
  const when = new Date(atMs);
  await fs.utimes(stateDir, when, when).catch(() => undefined);
}

async function withBrowserLifecycleLock<T>(ownerKey: string, fn: () => Promise<T>): Promise<T> {
  const previous = BROWSER_LIFECYCLE_LOCKS.get(ownerKey) ?? Promise.resolve();
  let releaseCurrent!: () => void;
  const current = new Promise<void>((resolve) => {
    releaseCurrent = resolve;
  });
  BROWSER_LIFECYCLE_LOCKS.set(ownerKey, current);
  await previous.catch(() => undefined);
  try {
    return await fn();
  } finally {
    releaseCurrent();
    if (BROWSER_LIFECYCLE_LOCKS.get(ownerKey) === current) {
      BROWSER_LIFECYCLE_LOCKS.delete(ownerKey);
    }
  }
}

async function stopTrackedBrowserBridge(ownerKey: string, containerName?: string) {
  const tracked = BROWSER_BRIDGES.get(ownerKey);
  if (!tracked) {
    return;
  }
  if (containerName && tracked.containerName !== containerName) {
    return;
  }
  await stopBrowserBridgeServer(tracked.bridge.server).catch(() => undefined);
  BROWSER_BRIDGES.delete(ownerKey);
}

async function writeBrowserRegistryEntry(entry: SandboxBrowserRegistryEntry) {
  await updateBrowserRegistry(entry);
  await touchBrowserStateDir(entry.stateDir, entry.lastUsedAtMs);
}

async function touchBrowserUsage(params: {
  ownerKey: string;
  containerName: string;
  image: string;
  configHash?: string;
  cdpPort: number;
  noVncPort?: number;
  stateDir?: string;
}) {
  const now = Date.now();
  const tracked = BROWSER_BRIDGES.get(params.ownerKey);
  if (tracked) {
    tracked.lastUsedAtMs = now;
  }
  await writeBrowserRegistryEntry({
    containerName: params.containerName,
    sessionKey: params.ownerKey,
    createdAtMs: now,
    lastUsedAtMs: now,
    image: params.image,
    configHash: params.configHash,
    cdpPort: params.cdpPort,
    noVncPort: params.noVncPort,
    stateDir: params.stateDir,
    status: "running",
    stoppedAtMs: undefined,
    lastBridgeAtMs: now,
  });
}

async function sweepSandboxBrowserEntry(params: {
  cfg: OpenClawConfig;
  ownerKey: string;
  entry: SandboxBrowserRegistryEntry;
  now: number;
}) {
  await withBrowserLifecycleLock(params.ownerKey, async () => {
    const agentId = resolveSandboxAgentId(params.ownerKey);
    const sandboxCfg = resolveSandboxConfigForAgent(params.cfg, agentId);
    if (!sandboxCfg.browser.enabled) {
      await stopTrackedBrowserBridge(params.ownerKey, params.entry.containerName);
      await execDocker(["rm", "-f", params.entry.containerName], { allowFailure: true });
      await removeBrowserRegistryEntry(params.entry.containerName);
      return;
    }

    const state = await dockerContainerState(params.entry.containerName);
    const tracked = BROWSER_BRIDGES.get(params.ownerKey);
    const lastUsedAtMs = tracked?.lastUsedAtMs ?? params.entry.lastUsedAtMs;

    if (!state.exists) {
      await stopTrackedBrowserBridge(params.ownerKey, params.entry.containerName);
      await removeBrowserRegistryEntry(params.entry.containerName);
      return;
    }

    if (
      state.running &&
      sandboxCfg.browser.idleStopAfterMs > 0 &&
      params.now - lastUsedAtMs >= sandboxCfg.browser.idleStopAfterMs
    ) {
      if ((tracked?.activeRequests ?? 0) > 0) {
        return;
      }
      await stopTrackedBrowserBridge(params.ownerKey, params.entry.containerName);
      await execDocker(["stop", params.entry.containerName], { allowFailure: true });
      await writeBrowserRegistryEntry({
        ...params.entry,
        sessionKey: params.ownerKey,
        lastUsedAtMs,
        stateDir: params.entry.stateDir,
        status: "stopped",
        stoppedAtMs: params.now,
      });
      return;
    }

    if (
      !state.running &&
      sandboxCfg.browser.removeStoppedAfterMs > 0 &&
      params.now - (params.entry.stoppedAtMs ?? lastUsedAtMs) >= sandboxCfg.browser.removeStoppedAfterMs
    ) {
      await stopTrackedBrowserBridge(params.ownerKey, params.entry.containerName);
      await execDocker(["rm", params.entry.containerName], { allowFailure: true });
      await removeBrowserRegistryEntry(params.entry.containerName);
    }
  });
}

async function gcSandboxBrowserStateDirs(cfg: OpenClawConfig) {
  const registry = await readBrowserRegistry();
  const activeStateDirs = new Set(
    registry.entries.map((entry) => path.resolve(entry.stateDir ?? "")).filter(Boolean),
  );
  const configuredAgentIds = new Set<string>(["main"]);
  for (const entry of cfg.agents?.list ?? []) {
    if (typeof entry.id === "string" && entry.id.trim()) {
      configuredAgentIds.add(normalizeAgentId(entry.id));
    }
  }

  for (const agentId of configuredAgentIds) {
    const browserCfg = resolveSandboxConfigForAgent(cfg, agentId).browser;
    if (!browserCfg.state.enabled || browserCfg.state.retainAfterMs <= 0) {
      continue;
    }
    const agentsRoot = path.join(browserCfg.state.root, "agents");
    const stateDir = resolveSandboxBrowserStateDir(browserCfg.state.root, agentId);
    if (activeStateDirs.has(path.resolve(stateDir))) {
      continue;
    }
    try {
      const stat = await fs.stat(stateDir);
      if (!stat.isDirectory()) {
        continue;
      }
      if (Date.now() - stat.mtimeMs < browserCfg.state.retainAfterMs) {
        continue;
      }
      await fs.rm(stateDir, { recursive: true, force: true });
      try {
        const remaining = await fs.readdir(agentsRoot);
        if (remaining.length === 0) {
          await fs.rmdir(agentsRoot).catch(() => undefined);
        }
      } catch {
        // ignore
      }
    } catch {
      // ignore missing/invalid state dirs
    }
  }
}

export async function sweepSandboxBrowsers(params?: { cfg?: OpenClawConfig }) {
  const cfg = params?.cfg ?? loadConfig();
  const registry = await readBrowserRegistry();
  const now = Date.now();
  for (const entry of registry.entries) {
    await sweepSandboxBrowserEntry({
      cfg,
      ownerKey: resolveSandboxBrowserOwnerKey({ sessionKey: entry.sessionKey }),
      entry,
      now,
    });
  }
  await gcSandboxBrowserStateDirs(cfg);
}

function ensureSandboxBrowserSweeperStarted() {
  if (browserSweeperStarted) {
    return;
  }
  browserSweeperStarted = true;
  const timer = setInterval(() => {
    void sweepSandboxBrowsers().catch((error) => {
      const message = error instanceof Error ? error.message : JSON.stringify(error);
      defaultRuntime.error?.(`Sandbox browser sweep failed: ${message}`);
    });
  }, BROWSER_SWEEP_INTERVAL_MS);
  timer.unref?.();
}

export async function ensureSandboxBrowser(params: {
  ownerKey?: string;
  agentId?: string;
  sessionKey?: string;
  workspaceDir: string;
  agentWorkspaceDir: string;
  cfg: SandboxConfig;
  evaluateEnabled?: boolean;
  bridgeAuth?: { token?: string; password?: string };
}): Promise<SandboxBrowserContext | null> {
  if (!params.cfg.browser.enabled) {
    return null;
  }
  if (!isToolAllowed(params.cfg.tools, "browser")) {
    return null;
  }

  ensureSandboxBrowserSweeperStarted();

  const ownerKey = resolveSandboxBrowserOwnerKey({
    sessionKey: params.sessionKey,
    agentId: params.agentId,
  });

  return await withBrowserLifecycleLock(ownerKey, async () => {
    const slug = slugifySessionKey(ownerKey);
    const containerName = `${params.cfg.browser.containerPrefix}${slug}`.slice(0, 63);
    const browserImage = params.cfg.browser.image ?? DEFAULT_SANDBOX_BROWSER_IMAGE;
    const cdpSourceRange = params.cfg.browser.cdpSourceRange?.trim() || undefined;
    const browserState = await ensureSandboxBrowserState({ cfg: params.cfg, ownerKey });
    const stateDir = browserState?.stateDir;
    const browserDockerCfg = resolveSandboxBrowserDockerCreateConfig({
      docker: params.cfg.docker,
      browser: { ...params.cfg.browser, image: browserImage },
    });
    const expectedHash = computeSandboxBrowserConfigHash({
      docker: browserDockerCfg,
      browser: {
        cdpPort: params.cfg.browser.cdpPort,
        vncPort: params.cfg.browser.vncPort,
        noVncPort: params.cfg.browser.noVncPort,
        headless: params.cfg.browser.headless,
        enableNoVnc: params.cfg.browser.enableNoVnc,
        cdpSourceRange,
      },
      securityEpoch: SANDBOX_BROWSER_SECURITY_HASH_EPOCH,
      workspaceAccess: params.cfg.workspaceAccess,
      workspaceDir: params.workspaceDir,
      agentWorkspaceDir: params.agentWorkspaceDir,
      stateDir,
      stateEnabled: params.cfg.browser.state.enabled,
    });

    const now = Date.now();
    const noVncEnabled = isNoVncEnabled(params.cfg.browser);
    const containerState = await dockerContainerState(containerName);
    let hasContainer = containerState.exists;
    let running = containerState.running;
    let currentHash: string | null = null;
    let hashMismatch = false;
    let noVncPassword: string | undefined;

    if (hasContainer) {
      if (noVncEnabled) {
        noVncPassword =
          (await readDockerContainerEnvVar(containerName, NOVNC_PASSWORD_ENV_KEY)) ?? undefined;
      }
      const registry = await readBrowserRegistry();
      const registryEntry = registry.entries.find((entry) => entry.containerName === containerName);
      currentHash = await readDockerContainerLabel(containerName, "openclaw.configHash");
      hashMismatch = !currentHash || currentHash !== expectedHash;
      if (!currentHash) {
        currentHash = registryEntry?.configHash ?? null;
        hashMismatch = !currentHash || currentHash !== expectedHash;
      }
      if (hashMismatch) {
        const lastUsedAtMs = registryEntry?.lastUsedAtMs;
        const isHot =
          running && (typeof lastUsedAtMs !== "number" || now - lastUsedAtMs < HOT_BROWSER_WINDOW_MS);
        if (isHot) {
          const hint = (() => {
            const agentId = resolveSandboxAgentId(ownerKey) ?? "main";
            return `openclaw sandbox recreate --browser --agent ${agentId}`;
          })();
          defaultRuntime.log(
            `Sandbox browser config changed for ${containerName} (recently used). Recreate to apply: ${hint}`,
          );
        } else {
          await stopTrackedBrowserBridge(ownerKey, containerName);
          await execDocker(["rm", "-f", containerName], { allowFailure: true });
          hasContainer = false;
          running = false;
        }
      }
    }

    if (!hasContainer) {
      if (noVncEnabled) {
        noVncPassword = generateNoVncPassword();
      }
      await ensureDockerNetwork(browserDockerCfg.network, {
        allowContainerNamespaceJoin: browserDockerCfg.dangerouslyAllowContainerNamespaceJoin === true,
      });
      await ensureSandboxBrowserImage(browserImage);
      const args = buildSandboxCreateArgs({
        name: containerName,
        cfg: browserDockerCfg,
        scopeKey: ownerKey,
        labels: {
          "openclaw.sandboxBrowser": "1",
          "openclaw.browserConfigEpoch": SANDBOX_BROWSER_SECURITY_HASH_EPOCH,
        },
        configHash: expectedHash,
        includeBinds: false,
        bindSourceRoots: stateDir
          ? [params.workspaceDir, params.agentWorkspaceDir, stateDir]
          : [params.workspaceDir, params.agentWorkspaceDir],
      });
      if (stateDir) {
        args.push("-v", `${stateDir}:${BROWSER_STATE_CONTAINER_ROOT}`);
      }
      if (browserDockerCfg.binds?.length) {
        for (const bind of browserDockerCfg.binds) {
          args.push("-v", bind);
        }
      }
      args.push("-p", `127.0.0.1::${params.cfg.browser.cdpPort}`);
      if (noVncEnabled) {
        args.push("-p", `127.0.0.1::${params.cfg.browser.noVncPort}`);
      }
      args.push("-e", `OPENCLAW_BROWSER_HEADLESS=${params.cfg.browser.headless ? "1" : "0"}`);
      args.push(
        "-e",
        `OPENCLAW_BROWSER_ENABLE_NOVNC=${params.cfg.browser.enableNoVnc ? "1" : "0"}`,
      );
      args.push("-e", `OPENCLAW_BROWSER_CDP_PORT=${params.cfg.browser.cdpPort}`);
      if (cdpSourceRange) {
        args.push("-e", `${CDP_SOURCE_RANGE_ENV_KEY}=${cdpSourceRange}`);
      }
      args.push("-e", `OPENCLAW_BROWSER_VNC_PORT=${params.cfg.browser.vncPort}`);
      args.push("-e", `OPENCLAW_BROWSER_NOVNC_PORT=${params.cfg.browser.noVncPort}`);
      args.push("-e", "OPENCLAW_BROWSER_NO_SANDBOX=1");
      if (stateDir) {
        args.push("-e", `${BROWSER_HOME_ENV_KEY}=${DEFAULT_BROWSER_HOME}`);
        args.push("-e", `${BROWSER_USER_DATA_DIR_ENV_KEY}=${DEFAULT_BROWSER_USER_DATA_DIR}`);
      }
      if (noVncEnabled && noVncPassword) {
        args.push("-e", `${NOVNC_PASSWORD_ENV_KEY}=${noVncPassword}`);
      }
      args.push(browserImage);
      await execDocker(args);
      await execDocker(["start", containerName]);
      hasContainer = true;
      running = true;
    } else if (!running) {
      await execDocker(["start", containerName]);
      running = true;
    }

    const mappedCdp = await readDockerPort(containerName, params.cfg.browser.cdpPort);
    if (!mappedCdp) {
      throw new Error(`Failed to resolve CDP port mapping for ${containerName}.`);
    }

    const mappedNoVnc = noVncEnabled
      ? await readDockerPort(containerName, params.cfg.browser.noVncPort)
      : null;
    if (noVncEnabled && !noVncPassword) {
      noVncPassword =
        (await readDockerContainerEnvVar(containerName, NOVNC_PASSWORD_ENV_KEY)) ?? undefined;
    }

    const existing = BROWSER_BRIDGES.get(ownerKey);
    const existingProfile = existing
      ? resolveProfile(existing.bridge.state.resolved, DEFAULT_OPENCLAW_BROWSER_PROFILE_NAME)
      : null;

    let desiredAuthToken = params.bridgeAuth?.token?.trim() || undefined;
    let desiredAuthPassword = params.bridgeAuth?.password?.trim() || undefined;
    if (!desiredAuthToken && !desiredAuthPassword) {
      desiredAuthToken = existing?.authToken;
      desiredAuthPassword = existing?.authPassword;
      if (!desiredAuthToken && !desiredAuthPassword) {
        desiredAuthToken = crypto.randomBytes(24).toString("hex");
      }
    }

    const shouldReuse =
      existing && existing.containerName === containerName && existingProfile?.cdpPort === mappedCdp;
    const authMatches =
      !existing ||
      (existing.authToken === desiredAuthToken && existing.authPassword === desiredAuthPassword);
    if (existing && (!shouldReuse || !authMatches)) {
      await stopTrackedBrowserBridge(ownerKey, containerName);
    }

    const reusableBridge =
      shouldReuse && authMatches ? BROWSER_BRIDGES.get(ownerKey)?.bridge ?? null : null;

    const ensureBridge = async () => {
      if (reusableBridge) {
        return reusableBridge;
      }

      const onEnsureAttachTarget = params.cfg.browser.autoStart
        ? async () => {
            const currentState = await dockerContainerState(containerName);
            if (currentState.exists && !currentState.running) {
              await execDocker(["start", containerName]);
            }
            const ok = await waitForSandboxCdp({
              cdpPort: mappedCdp,
              timeoutMs: params.cfg.browser.autoStartTimeoutMs,
            });
            if (!ok) {
              throw new Error(
                `Sandbox browser CDP did not become reachable on 127.0.0.1:${mappedCdp} within ${params.cfg.browser.autoStartTimeoutMs}ms.`,
              );
            }
          }
        : undefined;

      return await startBrowserBridgeServer({
        resolved: buildSandboxBrowserResolvedConfig({
          controlPort: 0,
          cdpPort: mappedCdp,
          headless: params.cfg.browser.headless,
          evaluateEnabled: params.evaluateEnabled ?? DEFAULT_BROWSER_EVALUATE_ENABLED,
        }),
        authToken: desiredAuthToken,
        authPassword: desiredAuthPassword,
        onEnsureAttachTarget,
        onRequestStart: async () => {
          const tracked = BROWSER_BRIDGES.get(ownerKey);
          if (tracked) {
            tracked.activeRequests += 1;
          }
          await touchBrowserUsage({
            ownerKey,
            containerName,
            image: browserImage,
            configHash: hashMismatch && running ? (currentHash ?? undefined) : expectedHash,
            cdpPort: mappedCdp,
            noVncPort: mappedNoVnc ?? undefined,
            stateDir,
          });
        },
        onRequestEnd: () => {
          const tracked = BROWSER_BRIDGES.get(ownerKey);
          if (tracked) {
            tracked.activeRequests = Math.max(0, tracked.activeRequests - 1);
          }
        },
        resolveSandboxNoVncToken: consumeNoVncObserverToken,
      });
    };

    const resolvedBridge = await ensureBridge();
    if (!reusableBridge) {
      BROWSER_BRIDGES.set(ownerKey, {
        bridge: resolvedBridge,
        containerName,
        ownerKey,
        stateDir,
        authToken: desiredAuthToken,
        authPassword: desiredAuthPassword,
        activeRequests: 0,
        lastUsedAtMs: now,
      });
    } else if (existing) {
      existing.lastUsedAtMs = now;
      existing.stateDir = stateDir;
    }

    await writeBrowserRegistryEntry({
      containerName,
      sessionKey: ownerKey,
      createdAtMs: now,
      lastUsedAtMs: now,
      image: browserImage,
      configHash: hashMismatch && running ? (currentHash ?? undefined) : expectedHash,
      cdpPort: mappedCdp,
      noVncPort: mappedNoVnc ?? undefined,
      stateDir,
      status: "running",
      stoppedAtMs: undefined,
      lastBridgeAtMs: now,
    });

    const noVncUrl =
      mappedNoVnc && noVncEnabled
        ? (() => {
            const token = issueNoVncObserverToken({
              noVncPort: mappedNoVnc,
              password: noVncPassword,
            });
            return buildNoVncObserverTokenUrl(resolvedBridge.baseUrl, token);
          })()
        : undefined;

    return {
      bridgeUrl: resolvedBridge.baseUrl,
      noVncUrl,
      containerName,
      ownerKey,
      stateDir,
    };
  });
}
