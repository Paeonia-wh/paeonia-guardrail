// 「让它服气」三件的挂具 —— **正反用例都要**。
//
// ① 拒绝理由给证据（台账按 rule 计数）
// ② 申辩出口 guardrail_dispute + 规则画像（**且必须验"它不会自动改规则"**）
// ③ G21 三字段 file / targetExists / readBefore
//
// ⚠️ 挂具只证代码、不证部署。
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { apply } from "../lib/index.js";

let pass = 0, fail = 0;
const chk = (ok, msg) => { console.log(`  ${ok ? "[OK]  " : "[FAIL]"} ${msg}`); ok ? pass++ : fail++; };
const TMP = mkdtempSync(join(tmpdir(), "soothe-"));
const LEDGER = join(TMP, "ledger.jsonl");
const NEWFILE = join(TMP, "brand-new.txt");        // **不存在** → 用于 G21 的"新建"反例
const EXISTFILE = join(TMP, "exists.txt");
writeFileSync(EXISTFILE, "x", "utf8");

const cap = { tools: {}, guard: null, handlers: {} };
const AGENT = { session: { header: { id: "soothe-verify" } } };
apply({
	tools: { guard: (f) => { cap.guard = f; }, register: (d) => { cap.tools[d.name] = d; } },
	// ⚠️ **必须真的把 handler 存下来** —— 第一版我把 `on()` 写成空操作，
	//    于是 `warned` 那条路径**从来没跑过**，③ 全读到 undefined；
	//    而"新建不提示"那条**空跑通过**（它"通过"是因为压根没有任何 warned 条目）。
	//    **这正是今晚一直在防的形状：「没提示」和「没测」长得一样。**
	on: (name, fn) => { cap.handlers[name] = fn; },
}, {
	refuseCap: 5, ledgerPath: LEDGER, pitfallList: "",
	reportsPath: join(TMP, "reports.jsonl"),
	rescanScript: "", rescanStampPath: "", rescanStaleHours: 24, metricRegistry: "",
	parseCheck: false, rulesData: "",
});
const ex = (name, args) => ({ name, arguments: args, agent: AGENT });
const lines = () => readFileSync(LEDGER, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
/** 驱动一次完整的「guard → post-execute」——**warn 只走后面那半**。 */
async function call(name, args) {
	const g = cap.guard(ex(name, args));
	if (typeof g === "string") return g;                       // 被拦
	const h = cap.handlers["tools/post-execute"];
	if (h) await h(ex(name, args), null, async () => null);    // 放行 → 走 post-execute
	return undefined;
}

// ───────── ① 拒绝理由给证据 ─────────
console.log("=".repeat(76));
console.log("① 拒绝理由给证据（台账按 rule 计数）");
console.log("=".repeat(76));
{
	// 先人工灌 3 条历史 refused（模拟"这条规则以前拦过 3 次"）
	for (let i = 0; i < 3; i++) {
		writeFileSync(LEDGER, JSON.stringify({ t: Date.now(), kind: "refused", rule: "G01",
			pitfall: "P02", tool: "pwsh", v: "0.0.0" }) + "\n", { flag: "a" });
	}
	const msg = cap.guard(ex("pwsh", { command: 'python -c "x"' }));
	chk(typeof msg === "string" && msg.includes("G01"), "G01 被拦（基线）");
	console.log("     ── 实际拒绝对话（前 3 行）──");
	for (const l of String(msg).split("\n").slice(0, 3)) console.log("     " + l);
	chk(typeof msg === "string" && /拦过\s*3\s*次/.test(msg),
		`⭐ 拒绝理由里**给出了证据**（「拦过 3 次」—— **只算这次之前的历史**）`);
	chk(typeof msg === "string" && msg.includes("台账记录"), "证据那一行以「台账记录」打头（可辨）");

	// ⚠️ 加强断言（第一版那条是**弱**的：3 和总行数 4 差 1，纯属巧合）：
	//    先制造一条**别的规则**（G02）的拒绝，再看 G01 的数会不会被带偏。
	cap.guard(ex("pwsh", { command: "a && b" }));                  // G02 被拒（别的规则）
	const msg2 = cap.guard(ex("pwsh", { command: 'python -c "y"' }));  // G01 再被拒
	chk(/拦过\s*4\s*次/.test(String(msg2)),
		`⭐ **只数这条规则自己**：G01 从 3 → 4，**G02 那一次没被算进来**`);
	const total = lines().length;
	chk(!new RegExp(`拦过 ${total} 次`).test(String(msg2)),
		`**不是**台账总行数（总 ${total} ≠ G01 的 4）`);
}

// ───────── ③ G21 三字段 ─────────
console.log();
console.log("=".repeat(76));
console.log("③ G21 三字段：file / targetExists / readBefore");
console.log("=".repeat(76));
{
	// (a) edit 一个**没读过**的文件 → readBefore=false
	await call("edit", { file_path: EXISTFILE });
	const a = lines().filter((l) => l.kind === "warned").pop();
	chk(!!a, "**先证 warned 这条路径真的跑到了**（否则下面全是空跑）");
	chk(a && a.file === EXISTFILE, `带 \`file\`（实得 ${a && a.file ? a.file : "**没有**"}）`);
	chk(a && a.targetExists === true, `带 \`targetExists=true\`（实得 ${a && a.targetExists}）`);
	chk(a && a.readBefore === false, `⭐ 带 \`readBefore=false\`（**本会话没读过**，实得 ${a && a.readBefore}）`);

	// (b) 先 read 再 edit → readBefore=true（**这就是那三字段存在的全部意义**）
	cap.guard(ex("read", { file_path: EXISTFILE }));
	await call("edit", { file_path: EXISTFILE });
	const b = lines().filter((l) => l.kind === "warned").pop();
	chk(b && b.readBefore === true, `⭐ 读过之后 \`readBefore=true\`（同一个会话同一个文件）`);

	// (c) 反例：write 到**不存在**的文件 = 新建 → G21 **不该**提示（老误报，不许回退）
	//     ⚠️ 断言里必须**同时**证明"这条路径真的跑到了"（看：同一批里 edit 是有 warned 的）
	const nWarnBefore = lines().filter((l) => l.kind === "warned").length;
	await call("write", { file_path: NEWFILE, content: "x" });
	const nWarnAfter = lines().filter((l) => l.kind === "warned").length;
	chk(nWarnAfter === nWarnBefore && nWarnBefore > 0,
		`**反例**：write 到不存在的文件**不提示**（warned ${nWarnBefore} → ${nWarnAfter}，`
		+ `而这一批里 warned 确实在产生 → **不是空跑**）`);

	// (d) 但 write 到**已存在**的文件 → 该提示，且 targetExists=true
	await call("write", { file_path: EXISTFILE, content: "y" });
	const d = lines().filter((l) => l.kind === "warned").pop();
	chk(d && d.targetExists === true, `write 到已存在的文件 → 提示且 targetExists=${d && d.targetExists}`);
}

// ───────── ② 申辩出口 ─────────
console.log();
console.log("=".repeat(76));
console.log("② 申辩出口：guardrail_dispute + 规则画像（**且不许自动改规则**）");
console.log("=".repeat(76));
{
	chk(!!cap.tools["guardrail_dispute"], "`guardrail_dispute` 已注册");
	chk(!!cap.tools["guardrail_rule_profile"], "`guardrail_rule_profile` 已注册");

	// 反例 1：缺理由 → 拒绝（"只说「不服」不算申辩"）
	const r1 = await cap.tools["guardrail_dispute"].execute({ rule: "G01" });
	chk(String(r1.result).includes("必须给理由"), "**反例**：不给理由 → 拒绝");
	// 反例 2：缺规则 id
	const r2 = await cap.tools["guardrail_dispute"].execute({ why: "因为所以" });
	chk(String(r2.result).includes("缺 rule"), "**反例**：不给规则 id → 拒绝");

	// 正例
	const r3 = await cap.tools["guardrail_dispute"].execute({ rule: "G01", why: "那次是要跑一个 .py，被误判成内联了" });
	chk(String(r3.result).includes("已记录"), "正例：申辩被记下");
	const dis = lines().filter((l) => l.kind === "disputed");
	chk(dis.length === 1 && dis[0].rule === "G01", "台账里有 `kind=disputed` 且带 rule");
	chk(dis[0].why && dis[0].why.length > 5, "申辩**带理由**（留痕）");

	// 画像
	const r4 = await cap.tools["guardrail_rule_profile"].execute({});
	const prof = JSON.parse(r4.result);
	const g01 = prof.画像.find((x) => x.规则 === "G01");
	chk(!!g01 && g01.拦过 > 0, `画像里 G01：拦过 ${g01 && g01.拦过} 次`);
	chk(!!g01 && g01.被申辩 === 1, `画像里 G01：被申辩 ${g01 && g01.被申辩} 次`);
	chk(!!g01 && g01.争议率 !== "—", `画像里 G01 争议率 = ${g01 && g01.争议率}`);

	// ⭐⭐ 最要紧的一条反例：**申辩不许自动改规则**
	const rulesMsg = cap.guard(ex("pwsh", { command: 'python -c "x"' }));
	chk(typeof rulesMsg === "string" && rulesMsg.includes("G01"),
		"⭐ **申辩之后 G01 仍然拦**（**没有自动降级** —— 争议是信号不是判决）");
}

console.log();
console.log("=".repeat(76));
console.log(`结果：${pass} 通过 / ${fail} 失败`);
console.log("⚠️ 挂具只证代码、不证部署 —— 真实路径要等重启后由它拦我一次才算数。");
console.log("=".repeat(76));
process.exit(fail === 0 ? 0 : 1);
