// 护栏改动的独立验证挂具 —— **不用重启宿主就能验**。
//
// 全部逻辑都在两个纯函数面里：rules.js 的 evaluate(exec) 是纯的；
// index.js 的 apply(ctx, config) 只依赖 ctx.tools.guard / ctx.tools.register / ctx.on。
// 给一个**假 ctx** 就能跑真实代码路径，逐条断言。
//
// ⚠️ 判据一律是 **"主动触发一次 → 读它写下来的字节 → 比对期望"**，
//    不是"看有没有这个字段"。Lead 明确要求过：
//    「"有没有这个字段"不算证据，"这个字段的值对不对"才算。」
//
// 用法：cd <plugin-dir> && node verify_plugin.mjs
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "guardrail-verify-"));
const LEDGER = join(TMP, "ledger.jsonl");
const REPORTS = join(TMP, "reports.jsonl");
const STAMP = join(TMP, "stamp.txt");

const { evaluate } = await import("../lib/rules.js");
const { apply, Config } = await import("../lib/index.js");

let pass = 0, fail = 0;
const chk = (ok, msg) => { console.log(`  ${ok ? "[OK]  " : "[FAIL]"} ${msg}`); ok ? pass++ : fail++; };
const lines = (p) => existsSync(p) ? readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse) : [];
const RAW = (p) => existsSync(p) ? readFileSync(p, "utf8") : "";

// ─────────────────────────── ① G21 误报修复 ───────────────────────────
console.log("=".repeat(78));
console.log("① G21：新建文件不该提示，改已有文件才提示");
console.log("=".repeat(78));
{
	const NEW = join(TMP, "brand-new.txt");
	const OLD = join(TMP, "exists.txt");
	writeFileSync(OLD, "x");
	chk(evaluate({ name: "write", arguments: { file_path: NEW } }).warns.length === 0,
		"write 到**不存在**的文件 → 不提示");
	chk(evaluate({ name: "write", arguments: { file_path: OLD } }).warns.some((r) => r.id === "G21"),
		"write 到**已存在**的文件 → 提示 G21");
	chk(evaluate({ name: "edit", arguments: { file_path: NEW } }).warns.some((r) => r.id === "G21"),
		"edit → 仍提示 G21");
	for (const [cmd, id] of [["python -c \"x\"", "G01"], ["a && b", "G02"], ["pwsh -File x.ps1", "G03"]])
		chk(evaluate({ name: "pwsh", arguments: { command: cmd } }).blocks.some((b) => b.id === id),
			`block 回归：${JSON.stringify(cmd)} → ${id}`);
	chk(evaluate({ name: "pwsh", arguments: { command: "Get-ChildItem ." } }).warns.length === 0,
		"干净命令 → 不提示");
}

// ─────────────────────────── ② 装插件（假 ctx） ───────────────────────────
const cap = { guard: null, handlers: {}, tools: {} };
const ctx = {
	tools: { guard: (f) => { cap.guard = f; }, register: (d) => { cap.tools[d.name] = d; } },
	on: (e, f) => { cap.handlers[e] = f; },
};
const config = {
	refuseCap: 3, ledgerPath: LEDGER, reportsPath: REPORTS,
	pitfallList: join(TMP, "nope.json"),
	rescanScript: join(TMP, "fake-rescan.py"), rescanStampPath: STAMP, rescanStaleHours: 24,
};
chk(typeof Config === "object" || typeof Config === "function", "Config 导出存在");
apply(ctx, config);
chk(Object.keys(cap.tools).length === 7 && "guardrail_report" in cap.tools
	&& "guardrail_parse_stats" in cap.tools && "guardrail_rules_status" in cap.tools
	&& "guardrail_dispute" in cap.tools && "guardrail_rule_profile" in cap.tools
	&& "guardrail_thresholds" in cap.tools,
	`注册了 7 个工具（${Object.keys(cap.tools)}）`);
chk(typeof cap.handlers["agent/session-start"] === "function", "session-start 处理器注册成功");

// ─────────────────────────── ③ session 必须是**真值** ───────────────────────────
console.log();
console.log("=".repeat(78));
console.log("③ 缺陷 1：session 必须是真值（不是占位符）");
console.log("=".repeat(78));
const REAL = "<your-session-id>";
{
	const e = { name: "pwsh", arguments: { command: "python -c \"print(1)\"" },
		agent: { session: { header: { id: REAL } } } };
	const r = cap.guard(e);
	chk(typeof r === "string" && r.includes("G01"), "触发一次拒绝（G01）");
	const rec = lines(LEDGER).find((l) => l.kind === "refused");
	chk(rec && rec.session === REAL, `台账 session **等于真实 id**（实得 ${JSON.stringify(rec && rec.session)}）`);
	chk(!RAW(LEDGER).includes("unknown-session"), "台账里**没有** 'unknown-session' 占位符");
}
{
	const e = { name: "pwsh", arguments: { command: "python -c \"print(2)\"" } };
	cap.guard(e);
	const recs = lines(LEDGER).filter((l) => l.kind === "refused");
	const last = recs[recs.length - 1];
	chk(!("session" in last), `拿不到 agent 时**该字段干脆不写**（实得 keys=${JSON.stringify(Object.keys(last))}）`);
	chk(!RAW(LEDGER).includes("unknown-session"), "仍然没有占位符");
}

// ─────────────────────────── ④ warn 真的进台账 ───────────────────────────
console.log();
console.log("=".repeat(78));
console.log("④ warn 记账：主动触发一条 warn，再读台账找它");
console.log("=".repeat(78));
{
	const before = lines(LEDGER).length;
	const out = await cap.handlers["tools/post-execute"](
		{ name: "pwsh", arguments: { command: "Get-ChildItem -Recurse ." },
			agent: { session: { header: { id: REAL } } } },
		null,
		async () => ({ kind: "accept", additionalContexts: [{ marker: "downstream-msg" }] }),
	);
	const after = lines(LEDGER);
	chk(after.length === before + 1, `台账正好多 1 行（${before} → ${after.length}）`);
	const w = after[after.length - 1];
	chk(w.kind === "warned", `新行 kind='warned'（实得 ${w.kind}）`);
	chk(w.rules === "G12" && w.pitfalls === "P07", `记了命中的规则/坑（实得 ${w.rules} / ${w.pitfalls}）`);
	chk(w.session === REAL, `warn 台账 session 也是真值（实得 ${JSON.stringify(w.session)}）`);
	chk(out.additionalContexts.length === 2 && out.additionalContexts[1].marker === "downstream-msg",
		"⭐ downstream 被保留（没被覆盖 —— 与计划锚共存的关键）");
	chk(out.additionalContexts[0].source.form === "notice" && !!out.additionalContexts[0].source.summary,
		"⭐ source 三字段齐全（P25 事故的直接防线）");
}

// ─────────────────────────── ⑤ 定期重扫凭据（分支都留痕） ───────────────────────────
console.log();
console.log("=".repeat(78));
console.log("⑤ 缺陷 3：重扫凭据必须能区分'门槛没到'和'没生效'");
console.log("=".repeat(78));
{
	const raw1 = RAW(STAMP);
	chk(raw1.length > 0, `凭据文件已出现（${raw1.split("\n").filter(Boolean).length} 行）`);
	chk(/lazy-first-tool/.test(raw1), "有一行来自 lazy-first-tool（兜底触发点生效）");
	chk(/spawned pid=/.test(raw1) || /spawn-error/.test(raw1),
		`首次可区分（spawned / spawn-error）：${(raw1.match(/\[[^\]]+\] (spawned|spawn-error)[^\n]*/) || ["?"])[0]}`);
	cap.handlers["agent/session-start"]();
	const raw2 = RAW(STAMP);
	chk(/skipped-fresh/.test(raw2), "第二次触发 → 写 skipped-fresh（**这就是'门槛没到'的可读凭据**）");
	const lastLine = raw2.trim().split("\n").pop();
	chk(/skipped-fresh ageH=/.test(lastLine), `最后一行写出了 ageH：${lastLine.slice(0, 96)}`);
}

// ─────────────────────────── ⑥ guardrail_report 端到端 ───────────────────────────
console.log();
console.log("=".repeat(78));
console.log("⑥ guardrail_report：写进去 → 读回字节验");
console.log("=".repeat(78));
{
	// 先让 guard 跑一次（模拟真实顺序：**guard 总是先于工具的 execute**），
	// 这样 lastSessionId 被捕获 —— report 正是靠它拿到自己的会话。
	cap.guard({ name: "pwsh", arguments: { command: "Get-ChildItem ." },
		agent: { session: { header: { id: REAL } } } });
	const out = await cap.tools["guardrail_report"].execute({
		what: "验证挂具写的样例", symptom: "症状", evidence: "verify_plugin.mjs", trigger: "验证时",
	});
	chk(JSON.parse(out.result).ok === true, "返回 ok=true");
	const rec = lines(REPORTS).pop();
	chk(rec && rec.source === "AI自报", `落盘 source='AI自报'（实得 ${JSON.stringify(rec && rec.source)}）`);
	chk(rec && rec.what === "验证挂具写的样例" && rec.evidence === "verify_plugin.mjs",
		"落盘 what/evidence 与传入**逐字一致**");
	const bytes = readFileSync(REPORTS);
	chk(bytes.toString("utf8").includes("验证挂具写的样例"), "UTF-8 字节可原样解回中文");
	chk(rec && rec.session === REAL,
		`⭐ 自报记录带**真实** session（靠 guard 先捕获；实得 ${JSON.stringify(rec && rec.session)}）`);
	chk(rec && !!rec.v, `自报记录带版本号 v（实得 ${JSON.stringify(rec && rec.v)}）`);
}

// ⚠️ 2026-09-26 删掉了一处**重复的总结打印**（原来在这里还有一行 `结果：…`）。
//    它是在第 ⑦ 节**之前**打印的 → 报的是**当时的** pass（32），
//    而真正的总结在文件末尾（37）。**任何按"第一个匹配"读结果的人都会拿到错的数** ——
//    而"数不对但看不出来"正是本项目一直在防的形状。**总结只留一处，在最后。**
// ─────────────────────────── ⑦ 回归护栏：占位符与版本号 ───────────────────────────
console.log();
console.log("=".repeat(78));
console.log("⑦ 回归护栏：任何一行都不许出现占位符；每行都要带版本号");
console.log("=".repeat(78));
{
	const all = lines(LEDGER);
	// (1) **值必须等于真实 id**（不是"有 session 字段"）—— 两条路径都要覆盖到
	const withSess = all.filter((l) => "session" in l);
	chk(withSess.length >= 2, `有 session 的行数 ≥2（refused + warned 都覆盖）：${withSess.length}`);
	const bad = withSess.filter((l) => l.session !== REAL);
	chk(bad.length === 0, `**每一行**的 session 都 === 真实 id（不合格 ${bad.length} 行）`);
	const kinds = [...new Set(withSess.map((l) => l.kind))].sort();
	chk(kinds.includes("refused") && kinds.includes("warned"),
		`refused 与 warned **两条路径都有真实 session**（实得 kinds=${JSON.stringify(kinds)}）`);
	// (2) 占位符字面量绝不许出现
	chk(!RAW(LEDGER).includes("unknown-session"), "台账里**没有** 'unknown-session' 字面量");
	// (3) 每行都带版本号 —— "哪版代码写的"不再靠时间戳推断
	const noVer = all.filter((l) => !l.v);
	chk(noVer.length === 0, `每一行都带版本号 v（实得 ${JSON.stringify([...new Set(all.map((l) => l.v))])}）`);
}

console.log();
console.log("=".repeat(78));
console.log(`结果：${pass} 通过 / ${fail} 失败`);
console.log("=".repeat(78));
process.exit(fail === 0 ? 0 : 1);
