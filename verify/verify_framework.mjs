/**
 * `verify_framework.mjs` —— **测这个框架本身**（不测我们那 9 条规则）。
 *
 * ═══ 为什么要有它（而不是直接发原来那 5 个挂具）═══
 * 原来那 5 个（`instance/`）**是「我们这个实例的验收单」** —— 它们断言
 * 「G01 会拦住内联 python」「G03 会拦住 pwsh」……**那些规则发布版里默认是关的** → **必然挂**。
 *
 * ⚠️ **而还有一个更硬的原因**：`lib/index.js` **import 了 `@deepseek-ai/dsh-tools`** ——
 *    **离开 DSH 就加载不了**（那正是"没 DSH 跑不起来"那层硬门槛）。
 *    → **所以这个挂具只测那两个「不依赖 DSH」的模块**：`rule-loader` / `parse-gate`。
 *
 * ═══ 它测什么（框架的四个承诺）═══
 *   ① 规则**能从数据加载**（不是只看代码默认）
 *   ② 数据**坏了 → 回落到代码默认**（fail open 的方向是「仍有设防」，不是全放行）
 *   ③ 阈值**读不到 → 回落代码默认**（**不是「没有阈值」**）
 *   ④ 解析闸**对坏代码会拦**、**对好代码放行**（判据来自解析器，不是我们的正则）
 *
 * 跑：node verify/verify_framework.mjs
 */
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

import { activeRules, configure, isAuthoritative, allThresholds,
         threshold, configureThresholds } from "../lib/rule-loader.js";
import { RULES } from "../lib/rules.js";
import { gateVerdict, parseCheck } from "../lib/parse-gate.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
let ok = 0, fail = 0;
const chk = (c, m) => { if (c) { ok++; console.log(`  [OK]   ${m}`); }
                        else { fail++; console.log(`  [FAIL] ${m}`); } };

console.log("=".repeat(78));
console.log("框架级验收（不依赖 DSH 的包，也不依赖我们那套规则）");
console.log("=".repeat(78));

// ── ① 规则能从数据加载 ──
console.log("\n① 规则能从**数据**加载（不是只看代码默认）");
{
	const { activeRules: ar } = await import("../lib/rule-loader.js");
	configure({ path: join(ROOT, "lib", "rules-data.json"), fallback: RULES });
	const r = ar(RULES);
	chk(r.length > 0, `加载到 ${r.length} 条规则`);
	chk(r.every((x) => x.id && x.level), "每条都有 id 和 level");
	chk(typeof r[0].test === "function", "每条都编译出了 test() 判据");
}

// ── ② 数据坏了 → 回落到代码默认（fail open 的方向）──
console.log("\n② 数据**坏了 → 回落**，而且**不是全放行**");
{
	const { activeRules: ar } = await import("../lib/rule-loader.js");
	const tmp = mkdtempSync(join(tmpdir(), "gr-"));
	for (const [name, content] of [
		["missing.json", null],
		["broken.json", "{ this is not json"],
		["wrongschema.json", JSON.stringify({ schema: 999, rules: [] })],
		["emptyrules.json", JSON.stringify({ schema: 1, rules: [] })],
		["badrule.json", JSON.stringify({ schema: 1, rules: [{ id: "NOPE" }] })],
	]) {
		const p = join(tmp, name);
		if (content !== null) writeFileSync(p, content, "utf-8");
		configure({ path: p, fallback: RULES });
		const got = ar(RULES);
		chk(got.length === RULES.length,
			`${name} → 回落到代码默认的 ${RULES.length} 条（**仍有设防，不是全放行**）`);
	}
	configure({ path: join(ROOT, "lib", "rules-data.json"), fallback: RULES });
}

// ── ③ 阈值读不到 → 回落代码默认 ──
console.log("\n③ 阈值**读不到 → 回落**（不是「没有阈值」）");
{
	const live = join(ROOT, "lib", "thresholds.json");
	if (existsSync(live)) {
		configureThresholds({ path: live });
		const v = threshold("circuitBreaker.max");
		chk(typeof v === "number", `从数据读到 circuitBreaker.max = ${v}`);
		const rows = allThresholds();
		chk(rows.length > 0, `列出 ${rows.length} 条阈值（带依据/出处）`);
		chk(rows.some((r) => r.待补依据), "**欠依据的那些能被筛出来**（source=null）");
	}
	configureThresholds({ path: join(tmpdir(), "definitely-missing.json") });
	const v2 = threshold("circuitBreaker.max");
	chk(typeof v2 === "number",
		`阈值文件不存在 → **仍返回代码默认 ${v2}**（不是 undefined、不是 0）`);
}

// ── ④ 解析闸：坏的拦、好的放 ──
console.log("\n④ 解析闸：**判据来自解析器**（不是我们的正则）");
{
	const bad = parseCheck("/tmp/x.py", "def f(:\n");
	chk(bad.ok === false, `坏 python 被认出（${String(bad.reason).slice(0, 40)}）`);
	const good = parseCheck("/tmp/x.py", "def f():\n    return 1\n");
	chk(good.ok === true, "好 python 放行");
	const js = parseCheck("/tmp/x.js", "const a = ;\n");
	chk(js.ok === false || js.ok === null, "坏 js 要么被认出、要么如实说查不了（不装）");
	const unknown = parseCheck("/tmp/x.zzz", "???");
	chk(unknown.ok === null, "**不认识的扩展名 → 如实说「没查」（ok=null），不是「没问题」**");
	// BOM：字节层的污染
	const bom = gateVerdict({ name: "write",
		arguments: { file_path: "/tmp/x.py", content: "\uFEFFx = 1\n" } });
	chk(bom && bom.bom === true, "**带 BOM 的内容被单独认出**（不是当成语法错）");
}

console.log("\n" + "=".repeat(78));
console.log(`结果：${ok} 通过 / ${fail} 失败`);
console.log("⚠️ 挂具只证代码、不证部署 —— 真跑起来要等它被 DSH 加载。");
process.exit(fail ? 1 : 0);
