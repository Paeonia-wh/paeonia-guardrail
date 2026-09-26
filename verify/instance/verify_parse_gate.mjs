// 解析闸（护栏第 5 条规则）的独立挂具 —— 双向 + 五条隔离逐条验。
//
// ⚠️ 挂具**只证代码、不证部署**（本会话已认账的纪律）。
//    真实路径要等重启后，**它真的拦我一次**才算数。
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { apply } from "../lib/index.js";
import { gateVerdict, parseCheck } from "../lib/parse-gate.js";

let pass = 0, fail = 0;
const chk = (ok, msg) => { console.log(`  ${ok ? "[OK]  " : "[FAIL]"} ${msg}`); ok ? pass++ : fail++; };

const TMP = mkdtempSync(join(tmpdir(), "gate-verify-"));
const LEDGER = join(TMP, "ledger.jsonl");
const lines = (p) => existsSync(p) ? readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];

function makeCtx() {
	const cap = { guard: null, tools: {} };
	const ctx = {
		tools: { guard: (f) => { cap.guard = f; }, register: (d) => { cap.tools[d.name] = d; } },
		on: () => {},
	};
	return { cap, ctx };
}
const CFG = (over = {}) => ({
	refuseCap: 5, ledgerPath: LEDGER, reportsPath: "", pitfallList: "",
	rescanScript: "", rescanStampPath: "", rescanStaleHours: 24, metricRegistry: "",
	parseCheck: true, parseMaxBytes: 2 * 1024 * 1024, parseTimeoutMs: 4000, ...over,
});

// ───────────────── ① 纯函数层：能抓 + 不误抓 ─────────────────
console.log("=".repeat(76));
console.log("① parseCheck：能抓 + 不误抓（判据是解析器说的）");
console.log("=".repeat(76));
const P = (n) => join(TMP, n);
const cases = [
	["good.py", "print('hi')\n", true],
	// ⭐ 不误抓：合法的多引号 Python（我第一版正则就是在这上面报了 47 处假阳性）
	["quote_ok.py", 'print("a" + "b")\n', true],
	["quote_bad.py", 'x = f"a"b"c"\n', false],
	["bad.py", "def f(:\n  pass\n", false],
	["good.json", '{"a":[1,2]}', true],
	["bad.json", '{"a":1,}', false],
	["good.mjs", "export const x = 1;\n", true],
	["bad.mjs", "const x = ;\n", false],
];
for (const [name, content, wantOk] of cases) {
	const r = parseCheck(name, content);
	chk(r.ok === wantOk, `${name.padEnd(14)} 期望 ${wantOk ? "通过" : "拒绝"}（实得 ${JSON.stringify(r.ok)}${r.ok === false ? " " + r.reason + (r.line ? " 第" + r.line + "行" : "") : ""}${r.ok === null ? " skip:" + r.skipped : ""}）`);
}
{
	const r = parseCheck("weird.xyz", "???");
	chk(r.ok === null, `未知类型 → ok:null（**没查**，不是"通过"）`);
	const r2 = parseCheck("big.py", "x=1\n".repeat(10), { maxBytes: 3 });
	chk(r2.ok === null, `超过大小上限 → ok:null（fail open）`);
	const r3 = parseCheck("x.py", null);
	chk(r3.ok === null, `内容不是字符串 → ok:null（fail open）`);
}

// ───────────────── ② 隔离②：gateVerdict 永不抛 ─────────────────
console.log();
console.log("=".repeat(76));
console.log("② 隔离②：gateVerdict **永不抛**（各种畸形输入）");
console.log("=".repeat(76));
const nasty = [null, undefined, {}, { name: "write" }, { name: "write", arguments: null },
	{ name: "write", arguments: { file_path: 123, content: "x" } },
	{ name: "edit", arguments: { file_path: "nope.py", old_string: "a", new_string: "b" } },
	{ name: "pwsh", arguments: { command: "x" } }];
let threw = 0;
for (const [i, e] of nasty.entries()) {
	try { const v = gateVerdict(e); if (v !== undefined) { threw++; console.log(`     #${i} 返回了非 undefined：${JSON.stringify(v)}`); } }
	catch (err) { threw++; console.log(`     #${i} **抛了**：${err.message}`); }
}
chk(threw === 0, `${nasty.length} 个畸形输入：**一个都没抛，且全部返回 undefined（放行）**`);

// ───────────────── ③ 走真实 guard 路径 ─────────────────
console.log();
console.log("=".repeat(76));
console.log("③ 走真实 guard 路径：write/edit");
console.log("=".repeat(76));
const { cap, ctx } = makeCtx();
apply(ctx, CFG());
// ⚠️ 修（挂具自抓）：原来 `exec()` **每次都新建 agent 对象** →
//    `agentIdOf` 用 WeakMap(Object)→id → **每次新 id → 熔断计数器永远从 0 开始 → 熔断永远不触发**。
//    这是**测试的 bug**，不是插件的（真实宿主里同一个会话是同一个 agent 对象，
//    护栏的熔断在真实路径上验过有效）。
//    现在：**每节一个稳定 agent** —— 既符合真实，又让各节互不干扰。
const mkAgent = (tag) => ({ session: { header: { id: tag } } });
const AG3 = mkAgent("gate-verify-s3");
let AGENT = AG3;
const exec = (name, args) => ({ name, arguments: args, agent: AGENT });

{
	const r = cap.guard(exec("write", { file_path: P("gate1.py"), content: 'x = f"a"b"c"\n' }));
	chk(typeof r === "string" && r.includes("G41"), `坏 .py → 拒绝（${r ? r.split("\n")[0] : "**放行了 ❌**"}）`);
	chk(typeof r === "string" && /第 \d+ 行/.test(r), `拒绝理由里有**行号**`);
	chk(typeof r === "string" && /ast\.parse/.test(r), `拒绝理由里有**权威判据**（ast.parse）`);
}
chk(cap.guard(exec("write", { file_path: P("ok1.py"), content: "print(1)\n" })) === undefined, `好 .py → 放行`);
chk(cap.guard(exec("write", { file_path: P("q.py"), content: 'print("a" + "b")\n' })) === undefined, `⭐ 合法的多引号 .py → 放行（不误抓）`);
chk(cap.guard(exec("write", { file_path: P("bad.json"), content: '{"a":1,}' })) !== undefined, `坏 .json → 拒绝`);
chk(cap.guard(exec("write", { file_path: P("bad.mjs"), content: "const x = ;\n" })) !== undefined, `坏 .mjs → 拒绝`);
chk(cap.guard(exec("write", { file_path: P("a.md"), content: "随便\n" })) === undefined, `未知类型 .md → 放行（fail open）`);

// edit：改坏 → 拦；本来就坏 → 不拦
{
	const f = P("e1.py");
	writeFileSync(f, "def ok():\n    return 1\n", "utf8");
	const r = cap.guard(exec("edit", { file_path: f, old_string: "return 1", new_string: "return (1" }));
	chk(typeof r === "string", `edit 把好文件**改坏** → 拒绝`);
	const f2 = P("e2.py");
	writeFileSync(f2, "def broken(:\n    pass\n", "utf8");     // 本来就坏
	const r2 = cap.guard(exec("edit", { file_path: f2, old_string: "pass", new_string: "return 2" }));
	chk(r2 === undefined, `edit 一个**本来就坏**的文件 → **放行**（不为它进来之前就有的问题背锅）`);
}

// ───────────────── ④ 隔离③：单独开关 ─────────────────
console.log();
console.log("=".repeat(76));
console.log("④ 隔离③：单独开关 parseCheck:false → 闸不跑，但其余规则不受影响");
console.log("=".repeat(76));
{
	const { cap: c2, ctx: x2 } = makeCtx();
	apply(x2, CFG({ parseCheck: false }));
	chk(c2.guard(exec("write", { file_path: P("off.py"), content: 'x = f"a"b"c"\n' })) === undefined,
		`parseCheck:false → 坏 .py **放行**（开关生效）`);
	chk(typeof c2.guard(exec("pwsh", { command: "python -c \"print(1)\"" })) === "string",
		`同一份配置下，**命令类规则照常工作**（G01 仍拦）—— 关闸不影响别的`);
}

// ───────────────── ⑤ 隔离④：独立台账 + 独立计数 + 独立熔断 ─────────────────
console.log();
console.log("=".repeat(76));
console.log("⑤ 隔离④：独立台账 kind / 独立计数 / **独立熔断表**");
console.log("=".repeat(76));
{
	const rows = lines(LEDGER);
	const kinds = [...new Set(rows.map((r) => r.kind))];
	chk(kinds.includes("parse_blocked"), `台账里有独立 kind：parse_blocked（实得 ${JSON.stringify(kinds)}）`);
	chk(rows.filter((r) => r.kind === "parse_blocked").every((r) => r.rule === "G41"),
		`都带独立 rule id G41`);
	chk(rows.filter((r) => r.kind === "parse_blocked").every((r) => String(r.session || "").startsWith("gate-verify")),
		`都带 session（gate-verify-s3 系列）`);
	// 独立熔断：命令类规则被拒 4 次（未到 cap=5），解析闸仍应独立计数、各自从 1 开始
	const before = lines(LEDGER).filter((r) => r.kind === "parse_blocked").length;
	cap.guard(exec("write", { file_path: P("z.py"), content: "def f(:\n" }));
	const after = lines(LEDGER).filter((r) => r.kind === "parse_blocked").length;
	chk(after === before + 1, `每拦一次记一条（${before} → ${after}）—— 这就是"这条规则到今天拦过几次"的来源`);
}
{
	const { cap: c3, ctx: x3 } = makeCtx();
	apply(x3, CFG());
	// ⭐⭐ 2026-09-26 **改口径**：G41 **不参与熔断**（判据见 rules-data.json 的 authoritativeNote）。
	//    熔断的前提是「**拒绝的理由可能不成立**」；而 G41 的理由**来自解析器** —— **它不可能不成立**。
	//    → 所以这里断言的是**反过来**的：**第 5 次仍然拦**，且**不产生 parse_cap_reached**。
	//    ⚠️ 但只断言"它从不熔断"是**半个测试** —— 那可能是"熔断整个坏了"。
	//       所以**同一条里加对照**：一条可熔断的规则（G01）**仍然会熔断**。
	AGENT = mkAgent("gate-verify-s5");
	for (let i = 0; i < 4; i++) c3.guard(exec("write", { file_path: P(`f${i}.py`), content: "def f(:\n" }));
	const fifth = c3.guard(exec("write", { file_path: P("f5.py"), content: "def f(:\n" }));
	chk(typeof fifth === "string" && fifth.includes("G41"),
		`⭐ 解析闸第 5 次 → **仍然拦**（**G41 不熔断** —— 它不是"理由可能不成立"的规则）`);
	chk(!lines(LEDGER).some((r) => r.kind === "parse_cap_reached" && r.rule === "G41"),
		`台账里**没有** G41 的 parse_cap_reached（不熔断 ⇒ 不留那个痕）`);
	// 而且台账那行要**自己说清**它不熔断 —— 否则将来数"为什么它拦了 20 次"会以为熔断坏了
	const lastBlocked = lines(LEDGER).filter((r) => r.kind === "parse_blocked").pop();
	chk(lastBlocked && lastBlocked.circuitBreakable === false,
		`⭐ 台账那行带 \`circuitBreakable: false\`（**自己说清它不熔断**，免得将来误读）`);

	// ── 对照：**一条可熔断的规则仍然熔断**（证明我改的是"哪条不熔断"，不是"熔断坏了"）──
	const { cap: c4, ctx: x4 } = makeCtx();
	apply(x4, CFG());
	AGENT = mkAgent("gate-verify-s5b");
	let released = false;
	for (let i = 0; i < 6; i++) {
		const r = c4.guard(exec("pwsh", { command: 'python -c "x"' }));   // G01（可熔断）
		if (r === undefined) { released = true; break; }
	}
	chk(released, `**对照**：G01（判据是我们自己写的正则 → 可熔断）**仍然会熔断放行**`);
}

// ───────────────── ⑥ 隔离⑤：放现有规则之后 + 现有规则回归 ─────────────────
console.log();
console.log("=".repeat(76));
console.log("⑥ 隔离⑤：**现有规则先判** + 现有 4 条规则回归");
console.log("=".repeat(76));
{
	const { cap: c4, ctx: x4 } = makeCtx();
	apply(x4, CFG());
	const r1 = c4.guard(exec("pwsh", { command: "python -c \"print(1)\"" }));
	chk(typeof r1 === "string" && r1.includes("G01") && !r1.includes("G41"),
		`命令类规则先判：G01 拦住，**理由里没有 G41**（闸没插手）`);
	chk(typeof c4.guard(exec("pwsh", { command: "a && b" })) === "string", `G02 回归`);
	chk(typeof c4.guard(exec("pwsh", { command: "pwsh -File x.ps1" })) === "string", `G03 回归`);
	chk(c4.guard(exec("pwsh", { command: "Get-ChildItem ." })) === undefined, `干净命令 → 放行`);
	// write 类调用不受命令类规则影响（工具范围不重叠）
	chk(c4.guard(exec("write", { file_path: P("plain.py"), content: "import os\n" })) === undefined,
		`正常 write 不受命令类规则影响（工具范围不重叠）`);
}

// ───────────────── ⑦ 计数工具 ─────────────────
console.log();
console.log("=".repeat(76));
console.log("⑦ 独立计数工具 guardrail_parse_stats");
console.log("=".repeat(76));
{
	chk(!!cap.tools["guardrail_parse_stats"], "工具已注册");
	const out = await cap.tools["guardrail_parse_stats"].execute({ limit: 3 });
	const j = JSON.parse(out.result);
	chk(typeof j.拦下次数 === "number", `能回答"到今天拦过几次"：拦下次数=${j.拦下次数}`);
	chk(typeof j.规则自身出错 === "number", `能单独看到"规则自身出错"次数：${j.规则自身出错}`);
	chk(!!j.开关, `能看出开关状态：${j.开关}`);
	console.log(`     —— 计数明细：${JSON.stringify(j.按错误类型)}`);
}

console.log();
console.log("=".repeat(76));
console.log(`结果：${pass} 通过 / ${fail} 失败`);
console.log("⚠️ 挂具只证代码、不证部署 —— 真实路径要等重启后由它拦我一次才算数。");
console.log("=".repeat(76));
process.exit(fail === 0 ? 0 : 1);
