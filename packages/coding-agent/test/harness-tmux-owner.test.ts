import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { planTmuxOwnerIsolation } from "../src/gjc-runtime/tmux-owner-isolation";
import { readLease } from "../src/harness-control-plane/session-lease";
import { createHarnessCliEnv, type HarnessCliEnv } from "./harness-control-plane/cli-workspace-env";

const repoRoot = path.resolve(import.meta.dir, "..", "..", "..");
const cliEntry = path.join(repoRoot, "packages", "coding-agent", "src", "cli.ts");
const fakeRpc = path.join(import.meta.dir, "harness-control-plane", "fixtures", "fake-rpc.ts");
const sessionId = "tmux-owner-test";

let root: string;
let workspace: string;
let cliEnv: HarnessCliEnv;

async function createUnverifiableTmux(): Promise<{ command: string; log: string }> {
	const bin = path.join(root, "bin");
	const command = path.join(bin, "tmux");
	const log = path.join(root, "tmux.log");
	await mkdir(bin, { recursive: true });
	await writeFile(
		command,
		`#!/usr/bin/env bash
	echo "$@" >> ${JSON.stringify(log)}
	[ "${"$"}{1:-}" = "-L" ] || exit 9
	[ "${"$"}#" -ge 3 ] || exit 9
	case "${"$"}2" in ""|default) exit 9 ;; esac
	shift 2
	if [ "${"$"}1" = "display-message" ]; then
	  echo unexpected-probe-failure >&2
	  exit 9
	fi
	exit 99
	`,
	);
	await chmod(command, 0o755);
	return { command, log };
}

async function createScopedHarnessSeam(): Promise<{
	tmuxCommand: string;
	path: string;
	log: string;
	serverStateDir: string;
}> {
	const bin = path.join(root, "scoped-bin");
	const tmuxCommand = path.join(bin, "tmux");
	const serverStateDir = path.join(root, "scoped-servers");
	const log = path.join(root, "scoped-tmux.log");
	await mkdir(bin, { recursive: true });
	await mkdir(serverStateDir, { recursive: true });
	await writeFile(
		tmuxCommand,
		`#!/usr/bin/env bash
	printf '%s\\n' "$*" >> ${JSON.stringify(log)}
	[ "${"$"}{1:-}" = "-L" ] || exit 9
	[ "${"$"}#" -ge 3 ] || exit 9
	socket="${"$"}2"
	case "$socket" in ""|default) exit 9 ;; esac
	shift 2
	state=${JSON.stringify(serverStateDir)}/"$socket.pid"
	case "${"$"}{1:-}" in
	  display-message)
	    if [ ! -f "$state" ] && [ "\${GJC_HARNESS_TEST_SWAP_SERVER:-}" = "1" ]; then sleep 1000 & printf '%s\\n' "$!" > "$state"; fi
	    if [ -f "$state" ]; then
	      pid="$(cat "$state")"
	      if kill -0 "$pid" 2>/dev/null; then printf '%s\\n' "$pid"; exit 0; fi
	    fi
	    printf '%s\\n' 'no server running on private test socket' >&2; exit 1 ;;
	  new-session)
	    [ -f "$state" ] && kill "$(cat "$state")" 2>/dev/null || true
	    command="${"$"}{!#}"
	    bash -c "$command" >/dev/null 2>&1 &
	    printf '%s\\n' "$!" > "$state"
	    exit 0 ;;
	  kill-session)
	    [ -f "$state" ] && kill "$(cat "$state")" 2>/dev/null || true
	    exit 0 ;;
	  *) exit 0 ;;
	esac
	`,
	);
	await chmod(tmuxCommand, 0o755);
	await writeFile(
		path.join(bin, "systemd-run"),
		`#!/usr/bin/env bash
		request=""
		IFS= read -r request
		bun -e 'const request = JSON.parse(process.argv[2]); const result = Bun.spawnSync(request.tmux_argv, { stdout: "ignore", stderr: "ignore" }); process.exit(result.exitCode ?? 1)' -- "$request" || exit $?
		printf '%s\\n' "\${GJC_HARNESS_TEST_BOOTSTRAP_RECEIPT:-{\\"schema_version\\":1,\\"ok\\":true,\\"code\\":\\"bootstrapped\\"}}"
		`,
	);
	await chmod(path.join(bin, "systemd-run"), 0o755);
	return { tmuxCommand, path: bin, log, serverStateDir };
}

async function runHarness(
	tmuxCommand: string,
	expectedExitCode = 0,
	env: NodeJS.ProcessEnv = {},
): Promise<Record<string, unknown>> {
	const proc = Bun.spawn(
		[
			"bun",
			cliEntry,
			"harness",
			"start",
			"--input",
			JSON.stringify({ harness: "gajae-code", workspace, sessionId, detach: true }),
		],
		{
			cwd: workspace,
			env: {
				...cliEnv.env,
				GJC_HARNESS_STATE_ROOT: root,
				GJC_HARNESS_RPC_COMMAND: JSON.stringify(["bun", fakeRpc]),
				GJC_TMUX_COMMAND: tmuxCommand,
				...env,
			},
			stdout: "pipe",
			stderr: "pipe",
		},
	);
	const [output, stderr, exitCode] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	if (exitCode !== expectedExitCode) throw new Error(`harness exit ${exitCode}: ${stderr || output}`);
	return JSON.parse(output) as Record<string, unknown>;
}

beforeEach(async () => {
	root = await mkdtemp(path.join(tmpdir(), "harness-tmux-owner-"));
	workspace = await mkdtemp(path.join(tmpdir(), "harness-tmux-workspace-"));
	cliEnv = createHarnessCliEnv(repoRoot);
});

afterEach(async () => {
	const lease = await readLease(root, sessionId).catch(error => {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw error;
	});
	if (lease?.pid) {
		try {
			process.kill(lease.pid, "SIGTERM");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
		}
	}
	cliEnv.cleanup();
	await rm(root, { recursive: true, force: true });
	await rm(workspace, { recursive: true, force: true });
});

describe("HarnessCommand tmux-resident owner startup", () => {
	it("uses the canonical owner-isolation plan route for a safe tmux server", async () => {
		const argv = [
			"tmux-test",
			"-L",
			"private-test-socket",
			"new-session",
			"-d",
			"-s",
			"gajae_code_harness_tmux-owner-test",
			"-c",
			"/work",
			"owner",
		];
		const plan = await planTmuxOwnerIsolation(
			{
				schema_version: 1,
				op: "plan",
				platform: process.platform,
				session_id: sessionId,
				owner_generation: "generation",
				cwd: "/work",
				state_dir: "/state/owner-isolation",
				socket_key: "private-test-socket",
				tmux_argv: argv,
			},
			{
				readCallerCgroup: async () => null,
				probeServer: async () => ({ state: "safe", pid: 1, startTime: "1", cgroup: { classification: "safe" } }),
			},
		);

		const unsafePlan = await planTmuxOwnerIsolation(
			{
				schema_version: 1,
				op: "plan",
				platform: process.platform,
				session_id: sessionId,
				owner_generation: "generation",
				cwd: "/work",
				state_dir: "/state/owner-isolation",
				socket_key: "private-test-socket",
				tmux_argv: argv,
			},
			{
				readCallerCgroup: async () => null,
				probeServer: async () => ({ state: "unsafe" }),
			},
		);
		expect(unsafePlan).toMatchObject({ ok: false, code: "server_unsafe" });

		expect(plan).toMatchObject({ ok: true, code: "not_required", server_state: "safe" });
		if (plan.ok)
			expect(plan.execution).toMatchObject({
				mode: "direct",
				argv,
				attempt_session: "gajae_code_harness_tmux-owner-test",
				server_key: "private-test-socket",
				server_absent_before: false,
				server_pid: 1,
				server_start_time: "1",
			});
	});

	it("fails closed for an unknown nonzero tmux probe without dispatching new-session", async () => {
		const { command, log } = await createUnverifiableTmux();
		const result = await runHarness(command, 1);
		const evidence = result.evidence as Record<string, unknown>;

		expect(evidence.ownerRuntime).toBe("manual");
		expect(evidence.ownerFallbackReason).toBe("tmux-owner-server_unverifiable");
		expect(evidence.reason).toBe("tmux-owner-isolation-failed");
		expect(await readFile(log, "utf8")).toContain("display-message -p #{pid}");
		expect(await readFile(log, "utf8")).not.toContain("new-session");
		const lifecycle = path.join(root, sessionId, "owner-lifecycle");
		const generation = JSON.parse(await readFile(path.join(lifecycle, "generation.json"), "utf8")) as {
			generation: string;
			session_id: string;
		};
		expect(generation.session_id).toBe(sessionId);
		expect(generation.generation).toMatch(/^[0-9a-f-]+$/);
	});

	it("proves a private tmux owner through the HarnessCommand path", async () => {
		const seam = await createScopedHarnessSeam();
		const result = await runHarness(seam.tmuxCommand, 0, {
			GJC_HARNESS_TEST_CALLER_CGROUP: "/\n",
			GJC_HARNESS_TEST_SERVER_CGROUP: process.platform === "linux" ? "/gjc-owner-test.scope\n" : "",
			GJC_HARNESS_TEST_SERVER_START_TIME: "1",
			PATH: `${seam.path}:${process.env.PATH ?? ""}`,
		});
		const evidence = result.evidence as Record<string, unknown>;
		const tmuxLog = await readFile(seam.log, "utf8");
		expect(evidence.ownerRuntime).toBe("tmux");
		expect(evidence.tmuxOwnerSocketKey).toBeUndefined();
		const calls = tmuxLog.trim().split("\n").filter(Boolean);
		const routedCalls = calls.filter(call => call !== "-V" && call !== "--version");
		expect(routedCalls).not.toHaveLength(0);
		const socket = routedCalls.map(call => call.match(/(?:^|\s)-L\s+(\S+)/)?.[1]).find(Boolean);
		expect(socket).toMatch(/^gjc-owner-[0-9a-f]{48}$/);
		expect(routedCalls.filter(call => !call.startsWith(`-L ${socket} `))).toEqual([]);
		expect(calls).toContain(`-L ${socket} display-message -p #{pid}`);
		expect(
			calls.some(call => call.startsWith(`-L ${socket} new-session -d -s gajae_code_harness_tmux-owner-test`)),
		).toBe(true);
		expect((result.state as Record<string, unknown>).ownerLive).toBe(true);
	});

	it.each([
		["noise before receipt", 'noise\n{"schema_version":1,"ok":true,"code":"bootstrapped"}'],
		["extra receipt key", '{"schema_version":1,"ok":true,"code":"bootstrapped","detail":"unexpected"}'],
		["missing receipt key", '{"schema_version":1,"ok":true}'],
		["malformed JSON", '{"schema_version":1,"ok":true,"code":'],
		["wrong receipt schema", '{"schema_version":2,"ok":true,"code":"bootstrapped"}'],
	])("rejects a scoped bootstrap receipt with %s", async (_description, receipt) => {
		const seam = await createScopedHarnessSeam();
		const result = await runHarness(seam.tmuxCommand, 1, {
			GJC_HARNESS_TEST_CALLER_CGROUP: "0::/user.slice/user-1.service\n",
			GJC_HARNESS_TEST_SERVER_CGROUP: process.platform === "linux" ? "/gjc-owner-test.scope\n" : "",
			GJC_HARNESS_TEST_SERVER_START_TIME: "1",
			GJC_HARNESS_TEST_BOOTSTRAP_RECEIPT: receipt,
			PATH: `${seam.path}:${process.env.PATH ?? ""}`,
		});
		expect((result.evidence as Record<string, unknown>).ownerFallbackReason).toBe(
			"tmux-owner-scope_bootstrap_failed",
		);
	});

	it("refuses a pre-existing private server swap without mutating the replacement", async () => {
		const seam = await createScopedHarnessSeam();
		const result = await runHarness(seam.tmuxCommand, 1, {
			GJC_HARNESS_TEST_SWAP_SERVER: "1",
			GJC_HARNESS_TEST_CALLER_CGROUP: "/\n",
			GJC_HARNESS_TEST_SERVER_CGROUP: process.platform === "linux" ? "/gjc-owner-test.scope\n" : "",
			GJC_HARNESS_TEST_SERVER_START_TIME: "1",
			PATH: `${seam.path}:${process.env.PATH ?? ""}`,
		});
		const evidence = result.evidence as Record<string, unknown>;
		const calls = (await readFile(seam.log, "utf8")).trim().split("\n").filter(Boolean);
		const socket = calls
			.map(call => call.match(/(?:^|\s)-L\s+(\S+)/)?.[1])
			.find((value): value is string => Boolean(value));

		expect(evidence.ownerRuntime).toBe("manual");
		expect(evidence.ownerFallbackReason).toBe("tmux-owner-server_race");
		expect(calls.some(call => call.includes("kill-session"))).toBe(false);
		if (socket) {
			const pid = Number((await readFile(path.join(seam.serverStateDir, `${socket}.pid`), "utf8")).trim());
			if (Number.isSafeInteger(pid) && pid > 0) {
				try {
					process.kill(pid, "SIGTERM");
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
				}
			}
		}
	});

	it("preserves the direct detached-owner fallback when tmux is unavailable", async () => {
		const result = await runHarness(path.join(root, "missing-tmux"));
		const evidence = result.evidence as Record<string, unknown>;

		expect(evidence.ownerRuntime).toBe("detached");
		expect(evidence.ownerFallbackReason).toBe("tmux-unavailable");
		expect((result.state as Record<string, unknown>).ownerLive).toBe(true);
		await expect(access(path.join(root, sessionId, "owner-lifecycle", "generation.json"))).rejects.toThrow();
	});
});
