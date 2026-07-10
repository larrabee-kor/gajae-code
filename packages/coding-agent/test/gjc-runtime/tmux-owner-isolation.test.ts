import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	type BootstrapRequest,
	bootstrapTmuxOwnerIsolation,
	classifyCgroup,
	closeExactTmuxOwner,
	createOwnerIntent,
	executeTmuxOwnerIsolationPlanSync,
	isExactScopedBootstrapSuccessReceipt,
	lifecyclePaths,
	observeOwnerTerminal,
	ownerProcessStartTime,
	type PlanRequest,
	parseOwnerIsolationRequest,
	planTmuxOwnerIsolation,
	planTmuxOwnerIsolationSync,
	replaceOwnerGeneration,
	TMUX_OWNER_ISOLATION_MAX_LINE_BYTES,
	tmuxOwnerIsolationBootstrapArgv,
} from "@gajae-code/coding-agent/gjc-runtime/tmux-owner-isolation";
import { isTmuxOwnerIsolationCliArgv } from "@gajae-code/coding-agent/gjc-runtime/tmux-owner-isolation-cli";

const repoRoot = path.resolve(import.meta.dir, "..", "..", "..", "..");
const ownerIsolationCliEntry = path.join(repoRoot, "packages", "coding-agent", "src", "cli.ts");
const packagedGjcEntry = path.join(repoRoot, "packages", "coding-agent", "bin", "gjc.js");
const mainEntry = path.join(repoRoot, "packages", "coding-agent", "src", "main.ts");
const ownerIsolationFlag = "--internal-tmux-owner-isolation";
const invalidJsonLineResponse =
	'{"schema_version":1,"ok":false,"code":"scope_unavailable","diagnostic":"invalid_json_line"}\n';

it("accepts only the exact scoped bootstrap success receipt", () => {
	expect(
		isExactScopedBootstrapSuccessReceipt(
			'{"schema_version":1,"ok":true,"code":"bootstrapped","native_session_id":"$0"}\n',
		),
	).toBe(true);
	for (const value of [
		'{"schema_version":1,"ok":true,"code":"bootstrapped"}\nnoise',
		'{"schema_version":2,"ok":true,"code":"bootstrapped"}',
		'{"schema_version":1,"ok":true,"code":"bootstrapped","extra":true}',
		'{"ok":true,"code":"bootstrapped"}',
		"not-json",
	])
		expect(isExactScopedBootstrapSuccessReceipt(value)).toBe(false);
});

async function currentProcessStartTime(): Promise<string> {
	const stat = await fs.readFile(`/proc/${process.pid}/stat`, "utf8");
	return stat
		.slice(stat.lastIndexOf(")") + 2)
		.trim()
		.split(/\s+/)[19]!;
}
async function runOwnerIsolationEntry(
	command: string[],
	stdin: string,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	const proc = Bun.spawn(command, { cwd: repoRoot, stdin: "pipe", stdout: "pipe", stderr: "pipe" });
	proc.stdin.write(stdin);
	proc.stdin.end();
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	return { exitCode, stdout, stderr };
}

const ownerIsolationEntries: Array<[string, string[]]> = [
	["source CLI", [process.execPath, ownerIsolationCliEntry, ownerIsolationFlag]],
	["packaged CLI", [process.execPath, packagedGjcEntry, ownerIsolationFlag]],
	[
		"direct main entry",
		[
			process.execPath,
			"-e",
			`import { main } from ${JSON.stringify(mainEntry)}; await main([${JSON.stringify(ownerIsolationFlag)}]);`,
		],
	],
];

const request: PlanRequest = {
	schema_version: 1,
	op: "plan",
	platform: "linux",
	session_id: "session",
	owner_generation: "generation",
	cwd: "/work",
	state_dir: "/tmp/state",
	socket_key: "socket",
	tmux_argv: ["tmux", "new-session", "-d", "-s", "owned-session", "literal value"],
};

function probe(state: "absent" | "safe" | "unsafe" | "unverifiable", cgroup = "0::/unit.service") {
	return {
		readCallerCgroup: async () => cgroup,
		probeServer: async () =>
			state === "safe" ? { state, pid: 1, startTime: "1", cgroup: { classification: "safe" as const } } : { state },
	};
}

describe("tmux owner isolation", () => {
	it("recognizes only the exact owner-isolation argv", () => {
		expect(isTmuxOwnerIsolationCliArgv([ownerIsolationFlag])).toBe(true);
		for (const argv of [[], [ownerIsolationFlag, "extra"], ["extra", ownerIsolationFlag], ["--other"]]) {
			expect(isTmuxOwnerIsolationCliArgv(argv)).toBe(false);
		}
	});

	it("invokes a compiled bootstrap with only the internal flag", () => {
		const prior = process.env.PI_COMPILED;
		process.env.PI_COMPILED = "1";
		try {
			expect(tmuxOwnerIsolationBootstrapArgv()).toEqual([process.execPath, ownerIsolationFlag]);
		} finally {
			if (prior === undefined) delete process.env.PI_COMPILED;
			else process.env.PI_COMPILED = prior;
		}
	});

	it("uses a stable non-Linux owner start identity without proc metadata", () => {
		expect(ownerProcessStartTime("darwin", null)).toBe("not_applicable");
		expect(ownerProcessStartTime("win32", "malformed")).toBe("not_applicable");
	});

	it("fails closed on malformed Linux owner start metadata", () => {
		const fields = ["S", ...Array.from({ length: 18 }, () => "0"), "1234"];
		expect(ownerProcessStartTime("linux", `1 (owner) ${fields.join(" ")}`)).toBe("1234");
		expect(ownerProcessStartTime("linux", null)).toBeNull();
		expect(ownerProcessStartTime("linux", "malformed")).toBeNull();
	});

	it.each(ownerIsolationEntries)(
		"routes exact argv through %s as one bounded JSON line",
		async (_entry, command) => {
			const privateMarker = "private-payload-must-not-appear";
			const result = await runOwnerIsolationEntry(command, `{"private":"${privateMarker}"}\n`);
			expect(result).toEqual({ exitCode: 0, stdout: invalidJsonLineResponse, stderr: "" });
			expect(result.stdout.split("\n")).toEqual([invalidJsonLineResponse.trim(), ""]);
			expect(result.stdout).not.toContain(privateMarker);
		},
		20_000,
	);

	it.each(ownerIsolationEntries)(
		"routes a valid bounded terminal observation through %s",
		async (entry, command) => {
			const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-cli-observe-"));
			const sessionId = `session-${entry.replace(/\W+/g, "-")}`;
			const generation = `generation-${entry.replace(/\W+/g, "-")}`;
			try {
				await replaceOwnerGeneration(state, sessionId, generation);
				const request = {
					schema_version: 1,
					op: "observe_terminal",
					session_id: sessionId,
					owner_generation: generation,
					state_dir: state,
					socket_key: `socket-${sessionId}`,
					observer: "sidecar",
					observed_at: "2026-01-01T00:00:00.000Z",
					signal: "EXIT",
					exit_code: 0,
					exit_kind: "cleanup",
					reason: "test",
				};
				const result = await runOwnerIsolationEntry(command, `${JSON.stringify(request)}\n`);
				const response = JSON.parse(result.stdout) as Record<string, unknown>;
				expect(result.exitCode).toBe(0);
				expect(result.stderr).toBe("");
				expect(response).toMatchObject({
					schema_version: 1,
					generation,
					session_id: sessionId,
					server_key: request.socket_key,
					observer: "sidecar",
					signal: "EXIT",
					result: "cleanup",
					classification: "non_operator_cleanup",
				});
				expect(result.stdout).not.toContain(state);
			} finally {
				await fs.rm(state, { recursive: true, force: true });
			}
		},
		20_000,
	);

	it("rejects a multi-line owner-isolation request without entering an interactive path", async () => {
		const result = await runOwnerIsolationEntry(
			[process.execPath, ownerIsolationCliEntry, ownerIsolationFlag],
			'{"private":"private-payload-must-not-appear"}\nextra\n',
		);
		expect(result).toEqual({ exitCode: 0, stdout: invalidJsonLineResponse, stderr: "" });
		expect(result.stdout).not.toContain("private-payload-must-not-appear");
	}, 20_000);
	it("rejects an oversized owner-isolation stream at the canonical byte bound", async () => {
		const result = await runOwnerIsolationEntry(
			[process.execPath, ownerIsolationCliEntry, ownerIsolationFlag],
			`${"x".repeat(TMUX_OWNER_ISOLATION_MAX_LINE_BYTES + 1)}\n`,
		);
		expect(result).toEqual({ exitCode: 0, stdout: invalidJsonLineResponse, stderr: "" });
	}, 20_000);

	it("classifies cgroups and applies the target-server truth table", async () => {
		expect(classifyCgroup({ platform: "darwin" })).toEqual({ classification: "not_applicable" });
		expect(classifyCgroup({ platform: "linux", cgroupText: "0::/x.service" }).classification).toBe("unsafe_service");
		expect(classifyCgroup({ platform: "linux", cgroupText: "broken" }).classification).toBe("unverifiable");
		expect(classifyCgroup({ platform: "linux", cgroupText: "0::/" })).toEqual({ classification: "safe", scope: "/" });
		expect(classifyCgroup({ platform: "linux", cgroupText: "0::/app.slice/app-demo.scope" }).classification).toBe(
			"safe",
		);
		expect(
			(await planTmuxOwnerIsolation(request, { ...probe("safe"), probeServer: async () => ({ state: "safe" }) }))
				.code,
		).toBe("server_unverifiable");
		expect((await planTmuxOwnerIsolation(request, probe("safe"))).ok).toBe(true);
		expect((await planTmuxOwnerIsolation(request, probe("unsafe"))).code).toBe("server_unsafe");
		expect((await planTmuxOwnerIsolation(request, probe("unverifiable"))).code).toBe("server_unverifiable");
	});

	it("accepts only structurally safe non-Linux not-applicable server proofs", async () => {
		const nonLinux = { ...request, platform: "darwin" as const };
		const safeProof = {
			state: "safe" as const,
			pid: 1,
			startTime: "1",
			cgroup: { classification: "not_applicable" as const },
		};
		const planned = await planTmuxOwnerIsolation(nonLinux, {
			...probe("absent"),
			probeServer: async () => safeProof,
		});
		expect(planned).toMatchObject({ ok: true, server_state: "safe" });
		expect(
			executeTmuxOwnerIsolationPlanSync(planned, {
				socketKey: "socket",
				spawn: () => ({ exitCode: 0 }),
				probeServer: () => safeProof,
			}),
		).toMatchObject({ ok: true });
		expect(
			await planTmuxOwnerIsolation(request, { ...probe("absent"), probeServer: async () => safeProof }),
		).toMatchObject({
			ok: false,
			code: "server_unverifiable",
		});
	});

	it("preserves argv literally and bounds the JSON-line protocol", async () => {
		const result = await planTmuxOwnerIsolation(
			{ ...request, platform: "darwin" },
			probe("absent", null as unknown as string),
		);
		expect(result.ok && result.execution.argv).toEqual(request.tmux_argv);
		expect(parseOwnerIsolationRequest(JSON.stringify({ ...request, tmux_argv: ["tmux", ""] }))?.op).toBe("plan");
		expect(parseOwnerIsolationRequest(`${JSON.stringify(request)}\nextra`)).toBeNull();
		expect(parseOwnerIsolationRequest(JSON.stringify({ ...request, extra: true }))).toBeNull();
		expect(parseOwnerIsolationRequest("x".repeat(16 * 1024 + 1))).toBeNull();
		expect(
			await planTmuxOwnerIsolation(request, {
				readCallerCgroup: async () => {
					throw new Error("unavailable");
				},
				probeServer: async () => ({ state: "absent" }),
			}),
		).toMatchObject({ ok: false, code: "scope_unavailable" });
	});

	it("plans and executes managed paths synchronously with a post-spawn server proof", () => {
		const attempts: string[] = [];
		const scoped = planTmuxOwnerIsolationSync(request, {
			readCallerCgroup: () => "0::/caller.service",
			probeServer: () => ({ state: "absent" }),
			recordAttempt: input => attempts.push(input.attempt.token),
		});
		expect(scoped.ok && scoped.execution.mode).toBe("scoped");
		expect(scoped.ok && scoped.execution.attempt_session).toBe("owned-session");
		expect(attempts).toHaveLength(1);
		const calls: Array<{ argv: string[]; stdin?: string }> = [];
		const executed = executeTmuxOwnerIsolationPlanSync(scoped, {
			socketKey: "socket",
			spawn: (argv, stdin) => {
				calls.push({ argv, stdin });
				return {
					exitCode: 0,
					stdout: '{"schema_version":1,"ok":true,"code":"bootstrapped","native_session_id":"$0"}\n',
				};
			},
			probeServer: socketKey => ({
				state: "safe",
				pid: 12,
				startTime: "34",
				cgroup: { classification: "safe", scope: `/gjc-${socketKey}.scope` },
			}),
		});
		expect(executed).toMatchObject({
			ok: true,
			server_key: "socket",
			server_pid: 12,
			server_start_time: "34",
			server_session: "owned-session",
		});
		expect(calls).toHaveLength(1);
		expect(calls[0]?.argv).toEqual(scoped.ok && scoped.execution.mode === "scoped" ? scoped.execution.argv : []);
		expect(calls[0]?.stdin).toBe(
			scoped.ok && scoped.execution.mode === "scoped" ? scoped.execution.stdin_line : undefined,
		);
		expect(calls[0]?.argv.slice(0, 6)).toEqual([
			"systemd-run",
			"--user",
			"--scope",
			"--quiet",
			"--unit",
			scoped.ok && scoped.execution.mode === "scoped" ? scoped.execution.expected_scope : "",
		]);
		expect(calls[0]?.argv).not.toContain("sh");
		expect(calls[0]?.argv).not.toContain("-c");
		expect(calls[0]?.argv).not.toContain(calls[0]?.stdin ?? "");
	});

	it("fails closed synchronously for unsafe proof and failed scoped outcome", () => {
		const unsafe = planTmuxOwnerIsolationSync(request, {
			readCallerCgroup: () => "0::/x.service",
			probeServer: () => ({ state: "unsafe" }),
			recordAttempt: () => {
				throw new Error("must not persist");
			},
		});
		expect(unsafe).toMatchObject({ ok: false, code: "server_unsafe" });
		const direct = planTmuxOwnerIsolationSync(
			{ ...request, platform: "darwin" },
			{
				readCallerCgroup: () => null,
				probeServer: () => ({ state: "safe" }),
				recordAttempt: () => {
					throw new Error("must not persist");
				},
			},
		);
		const rejected = executeTmuxOwnerIsolationPlanSync(direct, {
			socketKey: "socket",
			spawn: () => ({ exitCode: 0 }),
			probeServer: () => ({ state: "unverifiable" }),
		});
		expect(rejected).toMatchObject({ ok: false, code: "server_unverifiable" });
	});

	it("rejects a direct execution when the pre-existing server identity changes", () => {
		const planned = planTmuxOwnerIsolationSync(
			{ ...request, platform: "darwin" },
			{
				readCallerCgroup: () => null,
				probeServer: () => ({
					state: "safe",
					pid: 12,
					startTime: "before",
					cgroup: { classification: "not_applicable" },
				}),
				recordAttempt: () => undefined,
			},
		);
		expect(planned).toMatchObject({
			ok: true,
			execution: { server_key: "socket", server_pid: 12, server_start_time: "before" },
		});
		expect(
			executeTmuxOwnerIsolationPlanSync(planned, {
				socketKey: "socket",
				spawn: () => ({ exitCode: 0 }),
				probeServer: () => ({
					state: "safe",
					pid: 12,
					startTime: "after",
					cgroup: { classification: "not_applicable" },
				}),
			}),
		).toMatchObject({ ok: false, code: "server_race" });
	});

	it("refuses a stale direct generation before spawn and after its post-spawn proof", () => {
		const planned = planTmuxOwnerIsolationSync(
			{ ...request, platform: "darwin" },
			{
				readCallerCgroup: () => null,
				probeServer: () => ({
					state: "safe",
					pid: 12,
					startTime: "before",
					cgroup: { classification: "not_applicable" },
				}),
				recordAttempt: () => undefined,
			},
		);
		let spawns = 0;
		expect(
			executeTmuxOwnerIsolationPlanSync(planned, {
				socketKey: "socket",
				isCurrentGeneration: () => false,
				spawn: () => {
					spawns += 1;
					return { exitCode: 0 };
				},
				probeServer: () => ({
					state: "safe",
					pid: 12,
					startTime: "before",
					cgroup: { classification: "not_applicable" },
				}),
			}),
		).toMatchObject({ ok: false, diagnostic: "owner_generation_stale" });
		expect(spawns).toBe(0);
		let current = true;
		expect(
			executeTmuxOwnerIsolationPlanSync(planned, {
				socketKey: "socket",
				isCurrentGeneration: () => current,
				spawn: () => {
					current = false;
					return { exitCode: 0 };
				},
				probeServer: () => ({
					state: "safe",
					pid: 12,
					startTime: "before",
					cgroup: { classification: "not_applicable" },
				}),
			}),
		).toMatchObject({ ok: false, diagnostic: "owner_generation_stale" });
	});

	it("requires bootstrap self-proof before spawning exact argv", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-bootstrap-"));
		const attempt = {
			token: "token",
			session_name: "owned",
			socket_key: "socket",
			server_absent_before: true,
			expires_at: new Date(Date.now() + 5_000).toISOString(),
		};

		const attemptDir = path.join(state, "session", "owner-lifecycle");
		await fs.mkdir(attemptDir, { recursive: true });
		await replaceOwnerGeneration(state, "session", "generation");
		await fs.writeFile(
			path.join(attemptDir, "attempt-token.json"),
			JSON.stringify({
				schema_version: 1,
				generation: "generation",
				session_id: "session",
				created_at: "2026-01-01T00:00:00.000Z",
				...attempt,
			}),
		);
		const bootstrap: BootstrapRequest = {
			schema_version: 1,
			op: "bootstrap",
			session_id: "session",
			owner_generation: "generation",
			state_dir: state,
			socket_key: "socket",
			expected_scope: "gjc-owner-token.scope",
			tmux_argv: ["tmux", "new-session", "-s", "owned", "a b"],
			attempt,
		};
		const calls: string[][] = [];
		const proofPrefixes: Array<string[] | undefined> = [];
		const result = await bootstrapTmuxOwnerIsolation(bootstrap, {
			readSelfCgroup: async () => "0::/gjc-owner-token.scope",

			spawn: argv => {
				calls.push(argv);
				return { exitCode: 0, stdout: "$0\n" };
			},
			probeServer: async (_socketKey, tmuxControlArgv) => {
				proofPrefixes.push(tmuxControlArgv);
				return { state: "safe", pid: 1, startTime: "1", cgroup: { classification: "safe" } };
			},
		});
		expect(result.ok).toBe(true);
		expect(calls).toEqual([["tmux", "new-session", "-s", "owned", "a b"]]);

		expect(proofPrefixes).toEqual([["tmux"]]);
		const explicitAttempt = {
			token: "explicit-token",
			session_name: "owned-explicit",
			socket_key: "opaque socket",
			server_absent_before: true,
			expires_at: new Date(Date.now() + 5_000).toISOString(),
		};

		await fs.writeFile(
			path.join(attemptDir, "attempt-explicit-token.json"),
			JSON.stringify({
				schema_version: 1,
				generation: "generation",
				session_id: "session",
				created_at: "2026-01-01T00:00:00.000Z",
				...explicitAttempt,
			}),
		);
		const explicitPrefixes: Array<string[] | undefined> = [];
		await expect(
			bootstrapTmuxOwnerIsolation(
				{
					...bootstrap,
					socket_key: "opaque socket",
					expected_scope: "gjc-owner-explicit-token.scope",
					tmux_argv: ["tmux", "-L", "explicit", "new-session", "-s", "owned-explicit", "a b"],

					attempt: explicitAttempt,
				},
				{
					readSelfCgroup: async () => "0::/gjc-owner-explicit-token.scope",

					spawn: () => ({ exitCode: 0, stdout: "$0\n" }),
					probeServer: async (_socketKey, tmuxControlArgv) => {
						explicitPrefixes.push(tmuxControlArgv);
						return { state: "safe", pid: 1, startTime: "1", cgroup: { classification: "safe" } };
					},
				},
			),
		).resolves.toMatchObject({ ok: true });
		expect(explicitPrefixes).toEqual([["tmux", "-L", "explicit"]]);
		const planPrefixes: Array<string[] | undefined> = [];
		for (const tmux_argv of [
			request.tmux_argv,
			["tmux", "-L", "explicit", "new-session", "-d", "-s", "owned-session", "literal value"],
		]) {
			await planTmuxOwnerIsolation(
				{ ...request, tmux_argv },
				{
					readCallerCgroup: async () => null,
					probeServer: async (_socketKey, tmuxControlArgv) => {
						planPrefixes.push(tmuxControlArgv);
						return { state: "safe", pid: 1, startTime: "1", cgroup: { classification: "safe" } };
					},
				},
			);
		}
		expect(planPrefixes).toEqual([["tmux"], ["tmux", "-L", "explicit"]]);
		const denied = await bootstrapTmuxOwnerIsolation(bootstrap, {
			readSelfCgroup: async () => "0::/bad.service",
			spawn: () => {
				throw new Error("must not spawn");
			},
			probeServer: async () => ({ state: "absent" }),
		});
		expect(denied.code).toBe("scope_bootstrap_failed");
		const replay = await bootstrapTmuxOwnerIsolation(bootstrap, {
			readSelfCgroup: async () => "0::/gjc-owner-token.scope",

			spawn: () => ({ exitCode: 0 }),
			probeServer: async () => ({ state: "safe", pid: 1, startTime: "1", cgroup: { classification: "safe" } }),
		});
		expect(replay).toMatchObject({ ok: false, diagnostic: "attempt_capability_invalid" });
		await fs.rm(state, { recursive: true, force: true });
	});

	it("never cleans after an unsafe or unrelated post-spawn server proof", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-bootstrap-cleanup-"));
		const sessionId = "session";
		const generation = "generation";
		const root = lifecyclePaths(state, sessionId, generation).root;
		const expires_at = new Date(Date.now() + 5_000).toISOString();
		const qualifyingAttempt = {
			token: "qualifying-token",
			session_name: "qualifying-session",
			socket_key: "qualifying-socket",
			server_absent_before: true,
			expires_at,
		};
		const nonQualifyingAttempt = {
			token: "non-qualifying-token",
			session_name: "non-qualifying-session",
			socket_key: "non-qualifying-socket",
			server_absent_before: true,
			expires_at,
		};
		const qualifyingProof = {
			state: "unsafe" as const,
			pid: 41,
			startTime: "42",
			sessionNames: [qualifyingAttempt.session_name],
		};
		const nonQualifyingProof = {
			state: "unsafe" as const,
			pid: 43,
			startTime: "44",
			sessionNames: ["unrelated-session"],
		};
		let spawnCount = 0;
		try {
			await fs.mkdir(root, { recursive: true });
			await replaceOwnerGeneration(state, sessionId, generation);
			for (const attempt of [qualifyingAttempt, nonQualifyingAttempt]) {
				await fs.writeFile(
					path.join(root, `attempt-${attempt.token}.json`),
					JSON.stringify({
						schema_version: 1,
						generation,
						session_id: sessionId,
						created_at: "2026-01-01T00:00:00.000Z",
						...attempt,
					}),
				);
			}
			for (const [attempt, proof] of [
				[qualifyingAttempt, qualifyingProof],
				[nonQualifyingAttempt, nonQualifyingProof],
			] as const) {
				const result = await bootstrapTmuxOwnerIsolation(
					{
						schema_version: 1,
						op: "bootstrap",
						session_id: sessionId,
						owner_generation: generation,
						state_dir: state,
						socket_key: attempt.socket_key,
						expected_scope: `gjc-owner-${attempt.token}.scope`,
						tmux_argv: ["tmux", "-L", attempt.token, "new-session", "-s", attempt.session_name, "a b"],
						attempt,
					},
					{
						readSelfCgroup: async () => `0::/gjc-owner-${attempt.token}.scope`,
						spawn: () => {
							spawnCount += 1;
							return { exitCode: 0, stdout: "$0\n" };
						},
						probeServer: async () => proof,
					},
				);
				expect(result).toMatchObject({
					ok: false,
					code: "scope_bootstrap_failed",
					diagnostic: "server_proof_failed",
				});
			}
			expect(spawnCount).toBe(2);
		} finally {
			await fs.rm(state, { recursive: true, force: true });
		}
	});

	it("rejects a stale bootstrap generation before consuming its capability or spawning", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-bootstrap-stale-"));
		const attempt = {
			token: "stale-token",
			session_name: "owned",
			socket_key: "socket",
			server_absent_before: true,
			expires_at: new Date(Date.now() + 5_000).toISOString(),
		};
		const root = lifecyclePaths(state, "session", "stale").root;
		try {
			await replaceOwnerGeneration(state, "session", "current");
			await fs.mkdir(root, { recursive: true });
			const attemptFile = path.join(root, `attempt-${attempt.token}.json`);
			await fs.writeFile(
				attemptFile,
				JSON.stringify({
					schema_version: 1,
					generation: "stale",
					session_id: "session",
					created_at: "2026-01-01T00:00:00.000Z",
					...attempt,
				}),
			);
			const result = await bootstrapTmuxOwnerIsolation(
				{
					schema_version: 1,
					op: "bootstrap",
					session_id: "session",
					owner_generation: "stale",
					state_dir: state,
					socket_key: "socket",
					expected_scope: "gjc-owner-stale-token.scope",
					tmux_argv: ["tmux", "new-session", "-s", "owned"],
					attempt,
				},
				{
					readSelfCgroup: async () => "0::/gjc-owner-stale-token.scope",
					spawn: () => {
						throw new Error("must not spawn");
					},
					probeServer: async () => ({ state: "absent" }),
				},
			);
			expect(result).toMatchObject({ ok: false, diagnostic: "attempt_capability_invalid" });
			await expect(fs.access(attemptFile)).resolves.toBeNull();
			await expect(fs.access(`${attemptFile}.consumed`)).rejects.toThrow();
		} finally {
			await fs.rm(state, { recursive: true, force: true });
		}
	});

	it("serializes generation replacement behind a live generation lock", async () => {
		if (process.platform !== "linux") return;
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-generation-lock-"));
		try {
			await replaceOwnerGeneration(state, "session", "initial");
			await createOwnerIntent(state, {
				generation: "initial",
				session_id: "session",
				server_key: "socket",
				expected_terminal: { signal: "SIGTERM", result: "owner_term_then_session_cleanup" },
				dispatch_id: "dispatch",
				created_at: "2026-01-01T00:00:00.000Z",
				expires_at: "2099-01-01T00:00:00.000Z",
			});
			const paths = lifecyclePaths(state, "session", "second"),
				now = Date.now();
			await fs.writeFile(
				paths.generationLockFile,
				JSON.stringify({
					pid: process.pid,
					start_time: await currentProcessStartTime(),
					boot_id: (await fs.readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim(),
					created_at: new Date(now).toISOString(),
					expires_at: new Date(now + 30_000).toISOString(),
					token: "holder",
					generation: "second",
					session_id: "session",
					server_key: "generation",
				}),
			);
			const replacement = replaceOwnerGeneration(state, "session", "second");
			await Bun.sleep(100);
			expect(JSON.parse(await fs.readFile(paths.generationFile, "utf8"))).toMatchObject({ generation: "initial" });
			await expect(fs.access(lifecyclePaths(state, "session", "initial").intentFile)).resolves.toBeNull();
			await fs.unlink(paths.generationLockFile);
			await expect(replacement).resolves.toBe("second");
			expect(JSON.parse(await fs.readFile(paths.generationFile, "utf8"))).toMatchObject({ generation: "second" });
			await expect(
				fs.access(`${lifecyclePaths(state, "session", "initial").intentFile}.invalidated`),
			).resolves.toBeNull();
		} finally {
			await fs.rm(state, { recursive: true, force: true });
		}
	});

	it("rejects stale generations before creating a SIGTERM intent", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		await replaceOwnerGeneration(state, "session", "current");
		await expect(
			closeExactTmuxOwner(
				{
					stateDir: state,
					sessionId: "session",
					generation: "stale",
					serverKey: "socket",
					pid: process.pid,
					startTime: "start",
					dispatchId: "dispatch",
					createdAt: "2026-01-01T00:00:00.000Z",
					expiresAt: "2026-01-01T00:01:00.000Z",
				},
				{
					readStartTime: async () => "start",
					sendSigterm: async () => {
						throw new Error("must not signal");
					},
					waitForVerdict: async () => null,
					cleanupSession: async () => undefined,
				},
			),
		).rejects.toThrow("owner_generation_mismatch");
		await expect(fs.access(lifecyclePaths(state, "session", "stale").intentFile)).rejects.toThrow();
		await fs.rm(state, { recursive: true, force: true });
	});

	it("writes verdict before consuming a matching attempt intent and converges observers", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		const generation = await replaceOwnerGeneration(state, "session", "generation");
		await createOwnerIntent(state, {
			generation,
			session_id: "session",
			server_key: "socket",
			expected_terminal: { signal: "SIGTERM", result: "owner_term_then_session_cleanup" },
			dispatch_id: "dispatch",
			created_at: "2026-01-01T00:00:00.000Z",
			expires_at: "2026-01-01T00:01:00.000Z",
		});
		const observed = {
			schema_version: 1 as const,
			op: "observe_terminal" as const,
			session_id: "session",
			owner_generation: generation,
			state_dir: state,
			socket_key: "socket",
			observer: "sidecar" as const,
			observed_at: "2026-01-01T00:00:01.000Z",
			signal: "SIGTERM" as const,
			exit_code: 0,
			exit_kind: "exit",
			reason: "owner_exit",
			operator_dispatch_id: "dispatch",
		};
		const first = await observeOwnerTerminal(observed);
		const second = await observeOwnerTerminal({ ...observed, observer: "raw_monitor", reason: "different" });
		expect(first.classification).toBe("expected_operator_shutdown");
		expect(second).toEqual(first);
		await expect(
			fs.access(path.join(state, "session", "owner-lifecycle", "intent-generation.json.consumed")),
		).resolves.toBeNull();
		await expect(Bun.file(path.join(state, "verdict.json")).json()).resolves.toEqual({
			...first,
			owner_generation: generation,
		});
		await fs.rm(state, { recursive: true, force: true });
	});

	it("waits for a contending observer's immutable verdict", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		const generation = await replaceOwnerGeneration(state, "session", "generation");
		const paths = lifecyclePaths(state, "session", generation);
		const now = Date.now();
		await fs.writeFile(
			paths.lockFile,
			JSON.stringify({
				pid: process.pid,
				boot_id: (await fs.readFile("/proc/sys/kernel/random/boot_id", "utf8").catch(() => os.hostname())).trim(),
				start_time: await currentProcessStartTime(),
				created_at: new Date(now).toISOString(),
				expires_at: new Date(now + 30_000).toISOString(),
				token: "winning-observer",
				generation,
				session_id: "session",
				server_key: "socket",
			}),
		);
		const loser = observeOwnerTerminal({
			schema_version: 1,
			op: "observe_terminal",
			session_id: "session",
			owner_generation: generation,
			state_dir: state,
			socket_key: "socket",
			observer: "sidecar",
			observed_at: "2026-01-01T00:00:01.000Z",
			signal: "SIGTERM",
			exit_code: 0,
			exit_kind: "exit",
			reason: "sidecar",
		});
		await Bun.sleep(20);
		const winner = {
			schema_version: 1 as const,
			generation,
			session_id: "session",
			server_key: "socket",
			observed_at: "2026-01-01T00:00:01.000Z",
			signal: "SIGTERM" as const,
			exit_code: 0,
			result: "exit",
			observer: "raw_monitor" as const,
			classification: "unexpected_owner_loss" as const,
			reason: "raw_terminal",
			dedupe_key: `owner-loss:session:${generation}`,
		};
		await fs.writeFile(paths.verdictFile, JSON.stringify(winner));
		expect(await loser).toEqual(winner);
		await fs.rm(state, { recursive: true, force: true });
	});

	it("rejects a partial persisted verdict and still records the observed owner-loss incident", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		try {
			const generation = await replaceOwnerGeneration(state, "session", "generation");
			const paths = lifecyclePaths(state, "session", generation);
			await fs.writeFile(
				paths.verdictFile,
				JSON.stringify({ schema_version: 1, generation, session_id: "session", server_key: "socket" }),
			);
			await expect(
				observeOwnerTerminal({
					schema_version: 1,
					op: "observe_terminal",
					session_id: "session",
					owner_generation: generation,
					state_dir: state,
					socket_key: "socket",
					observer: "sidecar",
					observed_at: "2026-01-01T00:00:01.000Z",
					signal: "SIGTERM",
					exit_code: 0,
					exit_kind: "owner_lost",
					reason: "sidecar",
				}),
			).rejects.toThrow("immutable_record_conflict");
			await expect(fs.access(paths.incidentFile)).resolves.toBeNull();
		} finally {
			await fs.rm(state, { recursive: true, force: true });
		}
	});

	it("fails closed after bounded contention with a live complete lock descriptor", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		const generation = await replaceOwnerGeneration(state, "session", "generation");
		const paths = lifecyclePaths(state, "session", generation);
		const now = Date.now();
		await fs.writeFile(
			paths.lockFile,
			JSON.stringify({
				pid: process.pid,
				boot_id: (await fs.readFile("/proc/sys/kernel/random/boot_id", "utf8").catch(() => os.hostname())).trim(),
				start_time: await currentProcessStartTime(),
				created_at: new Date(now).toISOString(),
				expires_at: new Date(now + 30_000).toISOString(),
				token: "live-observer",
				generation,
				session_id: "session",
				server_key: "socket",
			}),
		);
		await expect(
			observeOwnerTerminal({
				schema_version: 1,
				op: "observe_terminal",
				session_id: "session",
				owner_generation: generation,
				state_dir: state,
				socket_key: "socket",
				observer: "sidecar",
				observed_at: "2026-01-01T00:00:01.000Z",
				signal: "SIGTERM",
				exit_code: 0,
				exit_kind: "exit",
				reason: "sidecar",
			}),
		).rejects.toThrow("verdict_lock_contended");
		await fs.rm(state, { recursive: true, force: true });
	});

	it("takes over an expired verdict lock, including one held by a live process", async () => {
		if (process.platform !== "linux") return;
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		const generation = await replaceOwnerGeneration(state, "session", "generation");
		const paths = lifecyclePaths(state, "session", generation);
		const startTime = await currentProcessStartTime();
		await fs.writeFile(
			paths.lockFile,
			JSON.stringify({
				pid: process.pid,
				boot_id: (await fs.readFile("/proc/sys/kernel/random/boot_id", "utf8").catch(() => os.hostname())).trim(),
				start_time: startTime,
				created_at: "2026-01-01T00:00:00.000Z",
				expires_at: "2026-01-01T00:00:01.000Z",
				token: "expired-observer",
				generation,
				session_id: "session",
				server_key: "socket",
			}),
		);
		await expect(
			observeOwnerTerminal({
				schema_version: 1,
				op: "observe_terminal",
				session_id: "session",
				owner_generation: generation,
				state_dir: state,
				socket_key: "socket",
				observer: "sidecar",
				observed_at: "2026-01-01T00:00:01.000Z",
				signal: "SIGTERM",
				exit_code: 0,
				exit_kind: "exit",
				reason: "sidecar",
			}),
		).resolves.toMatchObject({ classification: "unexpected_owner_loss" });
		await fs.rm(state, { recursive: true, force: true });
	});

	it("cancels failed and expires nonauthorizing current-generation SIGTERM intents without cleanup", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		let signals = 0;
		let cleanups = 0;
		const dependencies = {
			readStartTime: async () => "start",
			sendSigterm: async () => {
				signals += 1;
				throw new Error("dispatch_failed");
			},
			waitForVerdict: async () => null,
			cleanupSession: async () => {
				cleanups += 1;
			},
		};
		const requestFor = (generation: string, expiresAt: string) => ({
			stateDir: state,
			sessionId: "session",
			generation,
			serverKey: "socket",
			pid: process.pid,
			startTime: "start",
			dispatchId: `dispatch-${generation}`,
			createdAt: "2026-01-01T00:00:00.000Z",
			expiresAt,
		});
		await replaceOwnerGeneration(state, "session", "dispatch-failure");
		await expect(
			closeExactTmuxOwner(requestFor("dispatch-failure", "2099-01-01T00:00:00.000Z"), dependencies),
		).rejects.toThrow("dispatch_failed");
		await expect(
			fs.access(`${lifecyclePaths(state, "session", "dispatch-failure").intentFile}.cancelled`),
		).resolves.toBeNull();
		await replaceOwnerGeneration(state, "session", "expired");
		await expect(
			closeExactTmuxOwner(requestFor("expired", "2020-01-01T00:00:00.000Z"), dependencies),
		).rejects.toThrow("owner_intent_invalid");
		expect(signals).toBe(1);
		expect(cleanups).toBe(0);
		await expect(fs.access(lifecyclePaths(state, "session", "expired").intentFile)).rejects.toThrow();
		for (const [generation, verdict] of [
			["null-verdict", null],
			[
				"mismatched-verdict",
				{
					schema_version: 1 as const,
					generation: "mismatched-verdict",
					session_id: "session",
					server_key: "socket",
					observed_at: "2026-01-01T00:00:00.000Z",
					signal: "SIGTERM" as const,
					exit_code: 0,
					result: "owner_term_then_session_cleanup",
					observer: "sidecar" as const,
					classification: "expected_operator_shutdown" as const,
					reason: "test",
					intent_id: "wrong-intent",
					dedupe_key: "owner-loss:session:mismatched-verdict",
				},
			],
		] as const) {
			await replaceOwnerGeneration(state, "session", generation);
			await expect(
				closeExactTmuxOwner(requestFor(generation, "2099-01-01T00:00:00.000Z"), {
					...dependencies,
					sendSigterm: async () => {
						signals += 1;
					},
					waitForVerdict: async () => verdict,
				}),
			).rejects.toThrow("owner_term_verdict_timeout");
			await expect(
				fs.access(`${lifecyclePaths(state, "session", generation).intentFile}.expired`),
			).resolves.toBeNull();
		}
		await replaceOwnerGeneration(state, "session", "replayed");
		await createOwnerIntent(state, {
			generation: "replayed",
			session_id: "session",
			server_key: "socket",
			expected_terminal: { signal: "SIGTERM", result: "owner_term_then_session_cleanup" },
			dispatch_id: "prior-dispatch",
			created_at: "2026-01-01T00:00:00.000Z",
			expires_at: "2099-01-01T00:00:00.000Z",
		});
		await expect(
			closeExactTmuxOwner(requestFor("replayed", "2099-01-01T00:00:00.000Z"), dependencies),
		).rejects.toThrow("owner_intent_replay");
		expect(signals).toBe(3);
		expect(cleanups).toBe(0);
		await fs.rm(state, { recursive: true, force: true });
	});

	it("keeps expired/replayed intents nonauthorizing and isolates replacement generations", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-"));
		await replaceOwnerGeneration(state, "session", "old");
		await createOwnerIntent(state, {
			generation: "old",
			session_id: "session",
			server_key: "socket",
			expected_terminal: { signal: "SIGTERM", result: "owner_term_then_session_cleanup" },
			dispatch_id: "dispatch",
			created_at: "2026-01-01T00:00:00.000Z",
			expires_at: "2026-01-01T00:00:00.000Z",
		});
		const replacement = await replaceOwnerGeneration(state, "session", "new");
		expect(replacement).toBe("new");
		await expect(
			observeOwnerTerminal({
				schema_version: 1,
				op: "observe_terminal",
				session_id: "session",
				owner_generation: "old",
				state_dir: state,
				socket_key: "socket",
				observer: "sidecar",
				observed_at: "2026-01-01T00:00:01.000Z",
				signal: "SIGTERM",
				exit_code: 0,
				exit_kind: "exit",
				reason: "x",
				operator_dispatch_id: "dispatch",
			}),
		).rejects.toThrow("generation_mismatch");
		await fs.rm(state, { recursive: true, force: true });
	});
	it("rejects malformed owner intents before they can authorize an expected terminal verdict", async () => {
		const state = await fs.mkdtemp(path.join(os.tmpdir(), "gjc-owner-intent-"));
		try {
			await expect(
				createOwnerIntent(state, {
					generation: "generation",
					session_id: "session",
					server_key: "socket",
					expected_terminal: { signal: "SIGTERM", result: "owner_term_then_session_cleanup" },
					dispatch_id: "dispatch",
					created_at: "2026-01-01T00:01:00.000Z",
					expires_at: "2026-01-01T00:00:00.000Z",
				}),
			).rejects.toThrow("owner_intent_invalid");
		} finally {
			await fs.rm(state, { recursive: true, force: true });
		}
	});
});
