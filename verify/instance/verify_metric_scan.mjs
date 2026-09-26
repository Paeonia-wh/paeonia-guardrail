// G31 裸数字检查的独立挂具 —— 不用重启就能验。
//
// ⚠️ 挂具**只证代码、不证部署**（本会话已认账的纪律）。
//    真实路径要等重启后，**护栏拦我一次**才算数。
//
// 双向验证（今晚反复吃的教训：只看一个方向）：
//   ① 手写登记表里有的数   → **必须拦**
//   ② 手写登记表里没有的数 → **必须拦**（凭空造）
//   ③ 生成器产出的标记块   → **必须放行**
//   ④ 与指标无关的百分数   → **必须放行**（负对照，防误抓）
//   ⑤ 走**真实 guard 路径**（假 exec 调 send_message）验 ①③
import { readFileSync } from "node:fs";
import { scanBareMetricNumbers } from "../lib/rules.js";
import { apply } from "../lib/index.js";

let pass = 0, fail = 0;
const chk = (ok, msg) => { console.log(`  ${ok ? "[OK]  " : "[FAIL]"} ${msg}`); ok ? pass++ : fail++; };

const REG_PATH = "<your-data-dir>/metrics/registry.json";
const REG = JSON.parse(readFileSync(REG_PATH, "utf8"));
const V = REG.metrics["hitrate.guardrail"].version;
const ADJ = REG.metrics["hitrate.guardrail"].reports.at(-1).adjusted.value;

const MARKED = `<!--METRIC:hitrate.guardrail:v${V}-->
**hitrate.guardrail**：调整后 **${ADJ}%**（口径 **v${V}**）
<!--/METRIC-->`;

console.log("=".repeat(74));
console.log("⑧ G31 裸数字检查（纯函数层）");
console.log("=".repeat(74));
console.log(`  登记表：v${V}，最近 adjusted=${ADJ}%，keywords=${JSON.stringify(REG.metrics["hitrate.guardrail"].keywords)}`);

const cases = [
	["手写（登记表里有这个数）", `护栏命中率是 ${ADJ}%，非常好。`, true],
	["手写（登记表里没有的数 = 凭空造）", "护栏命中率是 95%，非常好。", true],
	["手写（分数形态）", "命中率 3/5，还行。", true],
	["生成器产出的标记块", `结论如下：\n${MARKED}\n以上。`, false],
	["负对照：无关百分数", "这次扫描覆盖了 60% 的文件，剩下的是二进制。", false],
	["负对照：无关分数", "3/5 的会话日志是 v4 格式。", false],
	["负对照：提到词但没有数字", "命中率这个指标还没算出来。", false],
	["混合：标记块 + 手写", `正门数据：\n${MARKED}\n另外命中率约 88%。`, true],
];
for (const [desc, text, shouldHit] of cases) {
	const hits = scanBareMetricNumbers(text, REG);
	const got = hits.length > 0;
	chk(got === shouldHit, `${desc} → ${shouldHit ? "必须拦" : "必须放行"}（实得 ${got ? `拦 ${hits.map(h => h.shown).join(",")}` : "放行"}）`);
}
{
	const h = scanBareMetricNumbers("命中率 95%", REG);
	chk(h.length === 1 && h[0].inRegistry === false, "凭空造的数被标为 inRegistry=false（能区分'漏版本'与'编造'）");
	const h2 = scanBareMetricNumbers(`命中率 ${ADJ}%`, REG);
	chk(h2.length === 1 && h2[0].inRegistry === true, "登记表里有的数被标为 inRegistry=true");
}

console.log();
console.log("=".repeat(74));
console.log("⑨ 走**真实 guard 路径**（假 exec 调 send_message）");
console.log("=".repeat(74));
const cap = { guard: null };
apply({
	tools: { guard: (f) => { cap.guard = f; }, register: () => {} },
	on: () => {},
}, {
	refuseCap: 5, ledgerPath: "", reportsPath: "", pitfallList: "",
	rescanScript: "", rescanStampPath: "", rescanStaleHours: 24,
	metricRegistry: REG_PATH,
});
const mkExec = (msg) => ({ name: "send_message", arguments: { message: msg },
	agent: { session: { header: { id: "verify-metric-scan" } } } });

{
	const r = cap.guard(mkExec(`本轮命中率是 ${ADJ}%。`));
	chk(typeof r === "string" && r.includes("G31"),
		`手写消息 → guard 拒绝（实得 ${r === undefined ? "放行 ❌" : r.slice(0, 40) + "…"}）`);
	chk(typeof r === "string" && r.includes("P30"), "拒绝理由里标了坑清单 id P30");
	chk(typeof r === "string" && r.includes("report_gen"), "拒绝理由里给了改法（用 report_gen）");
}
{
	const r = cap.guard(mkExec(`结论如下：\n${MARKED}\n以上。`));
	chk(r === undefined, `生成器的标记块 → guard **放行**（实得 ${r === undefined ? "放行 ✅" : "误拦 ❌"}）`);
}
{
	const r = cap.guard(mkExec("这次扫描覆盖了 60% 的文件。"));
	chk(r === undefined, `无关百分数 → guard **放行**（负对照，实得 ${r === undefined ? "放行 ✅" : "误拦 ❌"}）`);
}
{
	const r = cap.guard({ name: "pwsh", arguments: { command: "Get-ChildItem ." },
		agent: { session: { header: { id: "s" } } } });
	chk(r === undefined, "普通 pwsh 调用不受 G31 影响（没误伤）");
}
{
	// 登记表读不到时**绝不放乱拦**
	const cap2 = { guard: null };
	apply({ tools: { guard: (f) => { cap2.guard = f; }, register: () => {} }, on: () => {} },
		{ refuseCap: 5, ledgerPath: "", reportsPath: "", pitfallList: "",
		  rescanScript: "", rescanStampPath: "", rescanStaleHours: 24,
		  metricRegistry: "/nonexistent/registry.json" });
	const r = cap2.guard(mkExec("命中率 100%"));
	chk(r === undefined, "登记表读不到 → **放行**（读不到就乱拦是更坏的错）");
}

console.log();
console.log("=".repeat(74));
console.log(`结果：${pass} 通过 / ${fail} 失败`);
console.log("⚠️ 挂具只证代码、不证部署 —— 真实路径要等重启后由护栏拦我一次才算数。");
console.log("=".repeat(74));
process.exit(fail === 0 ? 0 : 1);
