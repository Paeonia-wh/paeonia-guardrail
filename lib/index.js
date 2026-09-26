// dsh-guardrail —— 护栏
//
// 职责（第一阶段，刻意很小）：
//   ① 动手前拦：只拦 3 条"几乎必然失败"的规则；其余"放行 + 提示"
//   ② 自带熔断：同一 (agent, 工具) 连续被拒满 refuseCap 次即放行并记台账
//   ③ 坑清单关键词查询：一个工具，按关键词查，**不要求通读**
//   ④ guardrail_report：**我是唯一知道自己刚踩坑的人** —— 让 AI 能把"日志里看不出来的坑"报进待补区
//   ⑤ 定期重扫：会话启动时（且够陈旧）后台重跑坑扫描，让新痕迹自动进待补区
//
// 与 dsh-plan-anchor 的关系：**并列、零共享**。
//   · 不碰它的任何文件/配置/数据库
//   · 只用 `ctx.tools.guard`（单调守卫，签名里没有 downstream）
//     → 结构上不可能覆盖它的注入
//   · warn 走 post-execute 时**显式转发 downstream**（抄计划锚的写法），永不替换
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync, openSync, closeSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { defineTool } from "@deepseek-ai/dsh-tools";
import z from "@deepseek-ai/schemastery";
import { RULES, SHELL_TOOLS, evaluate, scanBareMetricNumbers } from "./rules.js";
// 隔离①：第 5 条规则**代码独立文件**，不混进 rules.js 的现有规则
import { gateVerdict, parseGateStats } from "./parse-gate.js";
// 规则数据化（免重启）：数据优先，坏了回落代码默认 RULES
import { activeRules, configure as configureRules, loaderStats, isAuthoritative,
	configureThresholds, threshold, allThresholds, thresholdStats } from "./rule-loader.js";

export const name = "guardrail";
export const inject = ["tools"];

/** 版本号：**单一来源 = package.json**。
 *
 *  ⚠️ 2026-09-26 改（Lead 抓的）：原来是 `const VERSION = "0.1.3"` **硬编码**。
 *    硬编码就会漂 —— 改了 package.json 忘了改这里（或反过来），`v` 就开始**撒谎**，
 *    而 `v` 的全部意义就是"这行是哪版写的"：**标错比没有更坏**。
 *    现在只从 package.json 读，**没有第二处可忘**。
 *    `sync-check.py` 会断言这里**不出现版本字面量**（防止有人又写回去）。 */
function readVersion() {
	try {
		const p = new URL("../package.json", import.meta.url);
		return JSON.parse(readFileSync(p, "utf8")).version || "unknown";
	} catch {
		return "unknown";
	}
}
const VERSION = readVersion();

/** boot：**本进程**的一次性标识。
 *
 *  为什么还要它：`v` 是人维护的，**人就会忘**。`boot` 不是人维护的 —— 它由进程自己生成，
 *  **不可能被"忘记同步"**。于是即使某天 `v` 又标错了，
 *  也能靠 `boot` 分辨"这两行是不是同一代代码写的"。
 *  （Lead 的要求："别让版本号继续失去意义" → 答案是**再给一个不可能撒谎的锚**。） */
const BOOT = `${process.pid}-${Date.now().toString(36)}`;

export const Config = z.object({
	refuseCap: z.number().default(5),
	pitfallList: z.string().default(""),
	ledgerPath: z.string().default(""),
	// ④ AI 自报的坑落这里（进坑清单的"待补区"，**不直接变成规则** —— 新坑不该自动获得拦截权）
	reportsPath: z.string().default(""),
	// ⑤ 定期重扫
	rescanScript: z.string().default(""),
	rescanStampPath: z.string().default(""),
	rescanStaleHours: z.number().default(24),
	// ⑥ 口径登记表（裸数字检查）：手写的指标数字，在 `send_message` 发出去之前拦下。
	//    指向 metrics/registry.json —— 登记表在 Python 那边，这里只读它的 JSON。
	metricRegistry: z.string().default(""),
	// ⑦ 第 5 条规则：解析闸（隔离③ **单独开关** —— 出问题只关它，不用关整个护栏）
	parseCheck: z.boolean().default(true),
	parseMaxBytes: z.number().default(2 * 1024 * 1024),
	parseTimeoutMs: z.number().default(4000),
	// ⑧ 规则数据化（免重启）：**改这个文件 = 升格一条规则，不用改代码、不用重启**。
	//    读不到/格式坏/schema 不认/规则非法 → **回落代码默认 RULES**
	//    （fail open 到"有设防"，**不是"全放行"**）。
	rulesData: z.string().default(""),
	// ⑨ 会话级提示（自报池待归类等）—— **要可关**，别变成每次会话都响的墙纸。
	//    ⚠️ 关掉它**不会**关掉护栏的拦截能力，只关掉这一句"提醒还有事没做完"。
	sessionNotice: z.boolean().default(true),
	// ⑪ 阈值登记表（**和规则同一套机制：改数据文件、免重启**）。
	//    读不到/格式坏/schema 不认/条目非法 → **回落到代码默认值**
	//    （**不是"没有阈值"**，也不是报错 —— fail open 的方向是"仍有设防"）。
	thresholdsData: z.string().default(""),
	// ⑫ 整树对账的产物路径（`sandbox-report.json`）。
	//    ⚠️ 提示里会**标明"这份产物是几点跑的"**（时间取自产物本身）
	//    —— 因为**读旧产物本身不是错，不标来源地拿它当新的才是错**（P31）。
	reconcileReport: z.string().default(""),
	// ⭐ ⑬ 「已审台账」的路径（用户批的"更好的中间态"，2026-09-26）。
	//    **它解决的是「归零」和「分得清」这对矛盾**：
	//      · 只靠 `pitfalls[].provenance` 的 join → **「判定不进清单」那条永远算「待归类」** → **归不了零**
	//      · 而**把它算成「已归类」又不加区分** → **「判定不进」看起来跟「没处理」一样**（那就丢信息了）
	//    → **解法：把它算进「处理过」，但在注入里单独报一类。**
	//    ⚠️ 而**用户的理由要保住**：「留着一条反而证明『看过了但不进』被记住了」——
	//      **所以不是让它「消失」，是让它「报出来、但报在另一类里」。**
	triagePath: z.string().default(""),
	// ⭐ ㉒ 「待归类」的**展开产物**（2026-09-27，用户问「那我们怎么打通啊？」）。
	//
	//    **问题**：注入里原来只有一句「待归类 N 条」+ 原句 → **还得会话自己去读池子、判断、展开。**
	//      而 **②「按形状聚类 + 找最接近的已有坑」本来就是机械的**（脚本能干）。
	//
	//    **解法**：`expand_pending.py` 把展开算好、写成产物；**插件读它。**
	//      ⚠️ **而"展开"里含判断（形状词表、最近邻打分）** —— 所以它**落在脚本里**，
	//         **不写死在插件里**（否则就是 P36「把会变的东西写死」那个坑的形状）。
	//      ⚠️ **读不到 → 回落成原来那句原句**（fail open，不是不报）。
	//      ⚠️ **而且必须标"这份展开是什么时候算的"**（P31）——
	//         **旧展开当成新的，比没有展开更坏。**
	pendingExpanded: z.string().default(""),
	// ⭐ ㉕ **「两条捞回」接进后台**（2026-09-27，用户批「可以的做」）。
	//
	//    **它补的是第三层**（用户问「我其他会话现在工作，它如果犯错的话，它会自动记账吗？」）：
	//      ① 被护栏拦/提示      → ✅ 全自动（钩子跟会话无关）
	//      ② 命令报错（失败信号）→ ✅ 定期重扫会捞
	//      ③ **它自己踩的、护栏看不见的** → ❌ **不自动** ← **本条补的就是它**
	//
	//    **⭐ 而"同步还是后台"是量出来的，不是猜的**：
	//      捞回脚本 **64,136 ms**（≈64 秒，要扫 414 个会话日志）
	//      —— **比整树对账（35 秒）还慢** → **只能走后台** ✅
	//      （对照：展开脚本 0.14 秒 → 它在注入点同步跑。
	//        **两个判断不一样，因为量出来的数不一样** —— 那就是"别猜"的意思。）
	//
	//    **→ 汇报方式照抄整树对账那套**（**那个模板上次做对了**）：
	//      · **读上次产物** + **标明「这份产物是几点跑的」**（时间取自产物本身）
	//      · **「还没跑过」≠「0 条候选」** —— 前者是"没查"，后者是"查了没有"，必须分开说
	recoverScript: z.string().default(""),
	recoverCandidates: z.string().default(""),
	recoverStaleHours: z.number().default(24),
	// ⭐ ㉝ **配置自检的开关**（2026-09-27，用户批「需要」）。
	//    来由：**我往真配置里留了三个占位符**（`<your-data-dir>/…`）——
	//    而**插件从上线那一刻起就是断的，而「断」和「没跑过」在注入里长得一样。**
	//    ★ **那和 `skipped-fresh` 那个 bug 是同一个家族：「以为它管」。**
	configSelfCheck: z.boolean().default(true),
	// ㊱ **功能自证**（喂合成输入，看那些判据还活着吗）—— 默认开。
	//    ⚠️ 它**不写盘**（喂的全是内存里的合成输入），**也不自动改任何东西**。
	// ⭐⭐ **拆开关**（2026-09-27，Lead 批）——
	//    原来「配置自检」和「功能自证」的消费点挂在 `takeNotice` 里，
	//    而 `takeNotice` 归 `sessionNotice` 管 → **用户为了清静关掉欠账提醒，把故障灯也关了。**
	//    ★ **判据**：**偏好可以关；故障不该被偏好关掉。**
	//    ⚠️ **名字要让用户一眼看出「关掉它会失去什么」**（Lead 压的第 ③ 条）：
	reportBrokenConfig: z.boolean().default(true),
	//     关掉 = **你再也不会知道「有路径接不上」**（配置里留了占位符、指到目录…）
	reportDeadJudgements: z.boolean().default(true),
	//     关掉 = **某个检查悄悄失效了你也不知道**（那些「应该会响」的判据不响了）
	// ⭐ ㉓ **展开脚本 + 同步跑它**（2026-09-27，用户批「可以，没毛病」）。
	//
	//    **为什么要同步、而且要在注入之前跑**：
	//      `maybeRescan` 是**异步 spawn** → **本次会话读到的一定是"上一次会话跑的那个"**；
	//      而"池子变了就对不上"那个保护**会让它回落成原句** → **那是个"假自动"**。
	//      → **要本次就绪，只能在注入点同步跑。**
	//
	//    **⭐ 而它便宜到不用建后台任务**（我量过：**池子 14 行 → 58 ms**；
	//      线性 ≈ **3.1 ms/行**：140 行 → 439 ms，280 行 → 878 ms）
	//      → **安全边界：池子 < ~500 行（< 1.6 秒）**，远超现实（池子 14 行，「归零」是常态）。
	//
	//    ⚠️ **超时/失败必须有边**：跑不了就**回落成原句** ——
	//       **别因为展开不了就不报**（那会让"待归类"整个消失，**比不展开坏得多**）。
	expandScript: z.string().default(""),
	expandTimeoutMs: z.number().default(3000),
});

// ── 熔断状态：WeakMap 给 agent 一个稳定 id，Map 记 (agentId|tool) → 连续被拒次数 ──
const agentIds = new WeakMap();
let nextAgentId = 1;
const refusals = new Map();
// 隔离④：解析闸用**自己独立的熔断表** —— 不和命令类规则共用计数
const parseRefusals = new Map();

function agentIdOf(exec) {
	const a = exec && exec.agent;
	if (!a || (typeof a !== "object" && typeof a !== "function")) return 0;
	let id = agentIds.get(a);
	if (id === undefined) { id = nextAgentId++; agentIds.set(a, id); }
	return id;
}

/** 会话标识 —— 台账必须记它，否则 join「拒绝之后我干了什么」在结构上做不成。
 *
 *  ⚠️ 2026-09-26 修（Lead 抓出的缺陷 1）：
 *     原来读 `process.env.DSH_SESSION_ID`，**在插件进程里取不到** →
 *     每条都写成占位符 `"unknown-session"` —— **占位符比缺失更坏，它看起来像有数据**。
 *     真实来源写在计划锚源码里（它标了【稳定会话身份】）：
 *         `agent.session.header.id` —— DSH 的会话 id，跨重启不变
 *     拿不到就返回 **null**（该字段干脆不写），**绝不编**。
 */
function sessionIdOf(exec) {
	try {
		const a = exec && exec.agent;
		const h = a && a.session && a.session.header;
		if (!h) return null;
		const id = h.id || h.sessionId;
		return id ? String(id) : null;
	} catch {
		return null;
	}
}

// ═══════════════════════════════════════════════════════════════════
// 申辩门槛的两个数 —— **一个给了依据，一个明确标「暂定」**
// ═══════════════════════════════════════════════════════════════════
// ⚠️ 来由（Lead 2026-09-26）：「**一个没有依据的阈值，和一个没有依据的规则一样，
//    都是『只有成本』。所以要么给依据，要么明确标『暂定』—— 别让它看起来像个有依据的数。**」
//
// ① `DISPUTE_MIN_REFUSALS = 5` —— **有依据**：
//    抄 `rules-lifecycle.md`（源：tachyon-beep/skillpacks · false-positive-economics.md）
//    的幂律阈值：**1–2 抑制 ｜ 3–10 调查、通常该精化 ｜ 11+ 精化或退役**。
//    **5 落在「3–10」那一档** —— 也就是 prior art 说「**该开始调查这条规则**」的那一档。
//    → **「拦过 ≥5 次」= 「这条规则的样本量够进调查档了」**，不是我拍的。
//
// ② `DISPUTE_RATE_TENTATIVE = 40` —— ⚠️ **暂定，没有依据**：
//    我**没有任何真实申辩数据**（台账里 `disputed` 现在还是 **0 条**）——
//    所以**任何率都是拍的**。这里写 40% 只是「看起来像异常」的直觉，**不许当成有依据的数**。
//    **它凭什么才能有依据**：等 `disputed` 攒到一定条数，看真实争议率的分布 ——
//    那时应该报「中位数 / 分位」，而不是一个拍出来的整数。
//
// ⚠️⚠️ 最要紧的一句：**这两个数现在只做「显示标记」，不影响任何判定。**
//    它们**不会自动改规则、不会降级、不会阻止任何调用** ——
//    只在 `guardrail_dispute` / `guardrail_rule_profile` 的**输出里标一句「值得人工重审」**。
//    **所以它们错得起**；而「错了会不会被发现」，等有数据就能答（这正是 P34）。
//
// ⭐ 2026-09-26 ⑪：**这两个数已经搬进 `thresholds.json`**（改数据文件 = 免重启）。
//    下面这两个常量**只剩"代码默认值"的作用** —— 数据读不到时兜底。
//    ⚠️ **不再直接读它们**，一律走 `threshold("dispute.minRefusals")` 这类调用。
const DISPUTE_MIN_REFUSALS_FALLBACK = 5;        // 有依据：落在幂律的「3–10 调查档」
const DISPUTE_RATE_TENTATIVE_FALLBACK = 40;     // ⚠️ **暂定、无依据**（样本还不足以定这个率）
/** ⭐ 读阈值（数据优先，坏数据回落代码默认）。**永远是数字**。 */
const th = (n, fb) => {
	const v = threshold(n);
	return typeof v === "number" ? v : fb;
};

// ⭐⭐ 争议率的**唯一算法**（2026-09-26 改口径，三处共用这一个）
//
// **改前的病**：分母用的是 `ref`（拦过数）→ **一条"只 warn 不拦"的规则，分母永远是 0**
//   → **争议率永远显示「算不出来」** —— 而那类规则**恰恰是最该被审的**：
//   实测全场 **1396 次提示 vs 18 次拒绝** —— 提示类占了绝大多数，而它们**结构性地**审不了。
//
// **改后的判据**（Lead 认可）：
//   **「争议」是针对「这条规则响得对不对」，不是「拦得对不对」。**
//   → 分母 = **`ref + warn`**（这条规则总共「响」过几次）。
//
// ⚠️ **而门槛（≥N 次）也跟着改口径** —— 用同一个分母：
//    既然「争议率」问的是"响得对不对"，那"够不够进调查档"就该按"响过几次"算。
//    （prior art 的幂律是"同一规则的抑制数 1–2 / 3–10 / 11+" —— 那里的"抑制"
//     对应我们的"这条规则响了多少次"，**不是**"拦了多少次"。）
//    → **阈值名字不变（`dispute.minRefusals`），但含义已变成「响过几次」** —— 这里如实留痕。
//
// ⚠️ **两个数仍然分开显示**（拦过 N / 提示过 M）—— 否则"争议率高"到底是因为拦得错
//    还是提示得烦，**分不出来**。
function disputeRate(s) {
	const denom = (s.ref || 0) + (s.warn || 0);
	if (denom <= 0) return { rate: null, denom: 0 };
	return { rate: 100 * (s.dispute || 0) / denom, denom };
}

// ── ⭐ ① 让它「服气」：拒绝时**给证据**（这条规则在你身上拦过几次） ──
// Lead 的话：「**证据比命令更有说服力。**」
// ⚠️ 只在**真要拒绝的那一刻**才读台账（拒绝很少发生）→ 不是每次都读，不占热路径。
function ruleStats(ledgerPath, ruleId) {
	if (!ledgerPath || !ruleId) return null;
	try {
		let ref = 0, warn = 0, dispute = 0;
		for (const l of readFileSync(ledgerPath, "utf8").split("\n")) {
			if (!l.trim()) continue;
			let r;
			try { r = JSON.parse(l); } catch { continue; }
			const hit = r.rule === ruleId
				|| String(r.rules || "").split(",").includes(ruleId);
			if (!hit) continue;
			if (r.kind === "refused") ref++;
			else if (r.kind === "warned") warn++;
			else if (r.kind === "disputed") dispute++;
		}
		return { ref, warn, dispute };
	} catch {
		return null;          // 读不到就不给证据（**绝不编数**）
	}
}

// ── ⭐ ③ `readBefore`：本会话读过哪些文件 ──
// 用途：G21 升级成「拦」之前，要先知道「真的没读过就改」有多少次
//       （**那是升级判据的唯一输入** —— 没有它，150 次/小时那个数切不开）。
// ⚠️ 只在内存里记（会话级）—— 不落盘、不跨会话（跨会话的"读过"没有意义）。
const readFiles = new Map();          // sessionId → Set<path>

function noteRead(exec) {
	try {
		if (exec.name !== "read") return;
		const a = exec.arguments || {};
		const p = a.file_path || a.path;
		if (!p) return;
		const sid = sessionIdOf(exec) || "(未知会话)";
		if (!readFiles.has(sid)) readFiles.set(sid, new Set());
		readFiles.get(sid).add(String(p));
	} catch { /* 记录失败绝不影响判定 */ }
}

function readBefore(exec, filePath) {
	try {
		if (!filePath) return undefined;      // 拿不到就不写这个字段（**绝不编**）
		const sid = sessionIdOf(exec) || "(未知会话)";
		const s = readFiles.get(sid);
		return s ? s.has(String(filePath)) : false;
	} catch {
		return undefined;
	}
}

/** ⭐ ③ `file` / `targetExists` —— **`file` 是"文件类规则"的通用字段**
 *  （G21 / G41 / 将来的 lint 都要它）；`targetExists` 是 write 类判据。 */
function fileFacts(exec) {
	try {
		const a = exec.arguments || {};
		const p = a.file_path || a.path;
		if (!p) return {};
		let exists;
		try { exists = existsSync(p); } catch { exists = undefined; }
		return { file: String(p), targetExists: exists };
	} catch {
		return {};
	}
}

function ledger(config, entry, exec) {
	if (!config.ledgerPath) return;
	try {
		mkdirSync(dirname(config.ledgerPath), { recursive: true });
		const sid = sessionIdOf(exec);
		const rec = { t: Date.now(), v: VERSION, boot: BOOT, ...entry };
		if (sid) rec.session = sid;   // 拿不到就不写这个字段（写 null 也会被当成"有值"）
		appendFileSync(config.ledgerPath, JSON.stringify(rec) + "\n");
	} catch { /* 台账失败绝不能影响判定 */ }
}

// ── 口径登记表：**每次现读**（不缓存 —— 登记表会随报数变，缓存会拿到旧口径） ──
function loadMetrics(path) {
	if (!path) return null;
	try {
		return JSON.parse(readFileSync(path, "utf8"));
	} catch {
		return null;   // 读不到就不检查（**绝不因为读不到就乱拦**）
	}
}

// ── 坑清单查询（关键词，不通读） ──
let pitfallCache = null;
function loadPitfalls(path) {
	if (pitfallCache) return pitfallCache;
	try {
		pitfallCache = JSON.parse(readFileSync(path, "utf8"));
	} catch {
		pitfallCache = { pitfalls: [], unmatched: [] };
	}
	return pitfallCache;
}

function searchPitfalls(data, q, limit = 5) {
	const kw = String(q || "").trim().toLowerCase();
	const items = [...(data.pitfalls || []), ...(data.unmatched || []).map((u) => ({
		id: `(待补) ${u.tool}/${u.sig}`, name: `${u.tool} ← ${u.sig}`,
		trigger: "", symptom: (u.ex && u.ex[0] && u.ex[0].frag) || "",
		solution: "未归类 —— 见 pitfall-list.json 的 unmatched", status: "unknown",
		can_precheck: "?", counts: { solid: u.solid },
	}))];
	if (!kw) return items.slice(0, limit);
	return items
		.map((it) => {
			const hay = [it.id, it.name, it.trigger, it.symptom, it.solution, it.status, it.can_precheck]
				.filter(Boolean).join(" ").toLowerCase();
			let score = 0;
			if (String(it.id).toLowerCase() === kw) score += 100;
			if (hay.includes(kw)) score += 10;
			for (const w of kw.split(/\s+/).filter(Boolean)) if (hay.includes(w)) score += 2;
			score += Math.min((it.counts && it.counts.solid) || 0, 500) / 500;
			return { it, score };
		})
		.filter((x) => x.score >= 2)
		.sort((a, b) => b.score - a.score)
		.slice(0, limit)
		.map((x) => x.it);
}

/** ⑤ 定期重扫：够陈旧才跑，且**完全后台、绝不阻塞启动**。
 *
 *  ⚠️ 2026-09-26 修（Lead 抓出的缺陷 3）：原来"不跑"和"跑了"在磁盘上**无法区分** ——
 *     只在真的 spawn 时才写凭据，于是"凭据不存在"既可以解释成"门槛没到"、
 *     也可以解释成"根本没生效"。**这就是含糊。**
 *     现在**无论走哪条分支都写一行凭据**，把原因写死：
 *         skipped-disabled / skipped-fresh / spawned
 *     于是"下次什么时候会跑"和"是不是没生效"都能直接读出来，不用猜。
 */
// ═══════════════════════════════════════════════════════════════════
// ⭐ ⑨ 会话级提示（"要人记得" → "它自己会说"）
// ═══════════════════════════════════════════════════════════════════
// 来由（用户 2026-09-26）：「**我肯定是要别的会话也用这个东西的，不可能跟你说，你也看不到。**」
//   → **凡是"要人记得做"的，都不算完成。**
//   **完成的标准是：它自己会发生，或者它自己会提醒。**
//
// 这一件解决的是那个**结构洞**：**自报池（我报的坑）→ 坑清单，中间靠人肉**。
//   用户点名要打通它。**而"打通"能自动做的那一环就是：会话里说一句「自报池有 N 条待归类」。**
//
// ⚠️⚠️ **三条防反模式**（Lead 定的）：
//   1. **绝不自动归类** —— 归类要判断（这算不算新坑、归到哪组），
//      **自动归会污染清单**（我们为「来路不明」付过代价）。
//      这个函数**只数、只说**，**一个字段都不改**。
//   2. **提示要可关** —— 配置里 `sessionNotice: false` 就整块关掉。
//   3. **要能回答「归完了没有」** —— 所以它报的是**一个数**（还有几条待归类），
//      那个数**归完就变 0** → 于是"归完了没有"有了一个可看的答案。
//
// ⚠️ 数的**精度**（如实说）：
//   它按 `pitfall-list.json` 里各组的 `provenance[].ref` 去 join `reports.jsonl` 的行号。
//   **带 `#line=N` 的能精确匹配**；**不带行号的**（早期有几条）只能算"至少引用过一条"。
//   → 所以返回的是**待归类数的下界**，不是精确值。**要精确，`ref` 格式必须统一带行号。**
function unclassifiedReports(config) {
	const r = unclassifiedDetail(config);
	return r === null ? null : r.total;
}

/**
 * ⭐ C（2026-09-26）：**把"待归类那几条的原句"也报出来** —— 不只报个数。
 *
 * **为什么**（Lead 转述用户）：「**用户要的是「给我 1 2 3 4 5 让我判断」**」——
 *   · **护栏知道"有哪几条"和"每条的原句"**（那在池子里）
 *   · **Lead 补"建议归哪组 + 依据"**（那是判断）
 *   · **用户只需要点头或否**
 *
 * ⚠️ **三条要求**（Lead 定的），逐条落：
 *   1. **别把池子全倒出来** —— 只报**还没归类**的，而且**每条截断**（别让注入变成一堵墙）
 *   2. **条数多时有策略** —— 报「共 N 条，先列前 5 条」
 *   3. **仍然要能关** —— 走 `sessionNotice` 那个总开关
 *
 * ⚠️ **而它有精度上限，必须如实说**：
 *   归类关系靠 `provenance[].ref` 里的 `reports.jsonl#line=N` 做 join。
 *   **不带行号的 ref**（早期有几条）**只能算"引用过至少一条"** ——
 *   **→ 所以列出来的"未归类"里，可能混进"已经归类过、只是没记行号"的。**
 *   **这一条会写在输出里**（不藏）。
 */
function unclassifiedDetail(config) {
	try {
		if (!config.reportsPath || !config.pitfallList) return null;
		let raw;
		try {
			raw = readFileSync(config.reportsPath, "utf8").split("\n").filter((l) => l.trim());
		} catch {
			return null;              // 读不到就不报（**不编数**）
		}
		if (raw.length === 0) return { total: 0, shown: [], caveat: "" };
		const gen = JSON.parse(readFileSync(config.pitfallList, "utf8"));
		const cited = new Set();
		let noLine = 0;
		for (const p of gen.pitfalls || []) {
			for (const pr of p.provenance || []) {
				const ref = String(pr.ref || "");
				if (!ref.includes("reports.jsonl")) continue;
				const m = ref.match(/#line=(\d+)/);
				if (m) cited.add(Number(m[1]));
				else noLine += 1;     // 不带行号 → 只能算"引用过至少一条"
			}
		}
		// ⭐ ⑬ 「已审台账」里的也算**处理过** —— 但它们**单独计数**（不混进 cited）
		//    理由见 `triagePath` 的注释：**算进"处理过"是为了能归零；单独计数是为了分得清。**
		const triaged = new Set();
		if (config.triagePath) {
			try {
				for (const l of readFileSync(config.triagePath, "utf8").split("\n")) {
					if (!l.trim()) continue;
					try {
						const t = JSON.parse(l);
						// ⚠️ 只认**明确的判定**（`verdict` 有值）—— 别把"看过但没结论"算成"处理过"
						if (t && t.verdict && Number.isFinite(Number(t.line))) {
							triaged.add(Number(t.line));
						}
					} catch { /* 坏行跳过 */ }
				}
			} catch { /* 台账读不到 → 就当没有（**不编**） */ }
		}
		// ⭐ 挑出**没被引用**的那些（按行号来），并带出它们的原句
		const shown = [];
		let nTriaged = 0;
		for (let i = 0; i < raw.length; i++) {
			const lineNo = i + 1;
			if (cited.has(lineNo)) continue;
			// ⭐ 已审并判定的 → **算"处理过"**，但**单独计数**（下面分开报）
			if (triaged.has(lineNo)) { nTriaged += 1; continue; }
			let what = "(这一行读不出 what 字段)";
			try {
				const r = JSON.parse(raw[i]);
				what = String(r.what || what).replace(/\s+/g, " ").trim();
			} catch { /* 坏行就照实说 */ }
			shown.push({ line: lineNo, what: what.slice(0, 120) });
		}
		// ⚠️ 不带行号的 ref 让这个"未归类"名单**偏大** → 只在真有不带行号的引用时提示
		const caveat = noLine > 0
			? `（⚠️ 有 ${noLine} 条归类记录**没写行号** → 这个名单**可能偏大**（已归类的可能混进来）；`
				+ `把 ref 补成 \`reports.jsonl#line=N\` 就能精确）`
			: "";
		return { total: shown.length, shown, caveat, triaged: nTriaged };
	} catch {
		return null;
	}
}

// ═══════════════════════════════════════════════════════════════════
// ⭐ ⑩ 待升格候选 —— **A 档 / B 档分开，因为做法完全不同**
// ═══════════════════════════════════════════════════════════════════
// Lead（2026-09-26）：
//   · **A 档**：判据来自**权威工具**（例如"解析不了的 .py 就是坏的"，误报率我们量过 0/7）
//     → **可以真自动升格**（写进 `rules-data.json`，**免重启已通**）
//   · **B 档**：判据是**我们自己写的正则** → **只能"提示 + 拍板"**
//
// ⚠️⚠️ **而我的判断是：A 档现在"做得出、但没有可升的对象"** ——
//   **唯一"判据来自权威工具"的规则就是 G41 本身，它早就是规则了。**
//   所以**现在没有任何一条够格走 A 档**。
//   → **与其硬造一个"会自动改自己规则"的机制**（那是个大权力、且当前无处可用），
//     **不如如实说"现在没有这类候选"，并写清"什么情况下才会有"**：
//     **当出现"某个权威工具能判、但还没做成规则"的坑时**（例如将来接 lint 的 F821 ——
//     它的判据是 `pyflakes`/AST，不是我的正则）。**那时 A 档才有对象。**
//
// **本函数只做 B 档该做的事**：**算出候选、报出来、等拍板**。**它一个字段都不改。**
function promoteCandidates(config) {
	try {
		if (!config.pitfallList) return null;
		const gen = JSON.parse(readFileSync(config.pitfallList, "utf8"));
		// 已经被规则覆盖的坑 id（G 系列规则各自声明了自己修哪个坑）
		const covered = new Set(RULES.map((r) => r.pitfall).filter(Boolean));
		// ⚠️ 也要算上数据文件里**额外**的规则（它可能覆盖了代码默认没有的坑）
		try {
			const d = JSON.parse(readFileSync(config.rulesData, "utf8"));
			for (const r of d.rules || []) if (r.pitfall) covered.add(r.pitfall);
		} catch { /* 数据文件读不到就用代码默认的 */ }
		const out = [];
		const alreadyPromoted = [];
		const byVerdict = { yes: [], half: [], no: [], unjudged: [] };
		for (const p of gen.pitfalls || []) {
			if (p.can_precheck !== "可") continue;      // 只有"可机械判"的才谈得上做成规则
			const label = `${p.id}（${String(p.name || "").slice(0, 26)}）`;
			// ⚠️⚠️ **顺序很要紧**：`promoted_to` 必须在 `covered` **之前**判 ——
			//    否则"新开了一条规则"那种（P13 → G51）会**先被 `covered` 挡掉**，
			//    于是它**既不在候选里、也不在"已经升格过"里** → **凭空消失**。
			//    （我第一版就是这样：只报 P35、P13 不见了。）
			// ⭐ ⑯（2026-09-26）：**"已经升格过"的痕迹 = `promoted_to`**（Lead 抓到的"状态没跟上"）。
			//    ★ **`covered` 不能代替它**：`covered` 反推的是"**有规则覆盖**"——
			//      它会把**本来一开始就是规则**的（P01/P02/P05/P07/P08/P09/P19）也算进来
			//      → **我第一版就报出"9 条已经升格过"**（**错的**）。
			//    ★ **而"写没写"只能在"写的那一刻"记下来，不能事后从规则表反推。**
			if (p.promoted_to) {
				alreadyPromoted.push(`${label} → **${p.promoted_to}**`);
				continue;
			}
			if (covered.has(p.id)) continue;            // 已经有规则覆盖 → **不进候选**
			out.push(label);
			// ⭐ 升格通道：**按「判据能不能写」分类** ——
			//    那个判断**是我的判断，但它落在数据里**（`promotable`），不写死在插件里
			//    —— 否则就是 P36（把会变的东西写死）那个坑的形状。
			//    ⚠️ **没有那个字段的 → 算 `unjudged`**（**如实说"还没判过"，不猜**）
			const v = String(p.promotable || "");
			if (v === "yes" || v === "half" || v === "no") byVerdict[v].push(label);
			else byVerdict.unjudged.push(label);
		}
		out.byVerdict = byVerdict;
		out.alreadyPromoted = alreadyPromoted;
		return out;
	} catch {
		return null;      // 算不出来就说算不出来（**不编**）
	}
}

// ═══════════════════════════════════════════════════════════════════
// ⭐ ⑫ 整树对账的**结果提示** —— 而且**必须标明"这是什么时候跑的"**
// ═══════════════════════════════════════════════════════════════════
// 来由（Lead 2026-09-26）：「**有「绕过」时 → 在会话里注入一句提示；没有时 → 静默。**
//   但**「报出来」和「能看见」是两件事** —— 如果它跑完没人看，等于没跑。」
//
// ⚠️⚠️ **而这里有个我当时没解开的矛盾**（**那正是这件当时没做的原因**）：
//   · 对账跑在**后台**（`spawn`，fire-and-forget）→ **结果异步产生**
//   · 而"提示"要在会话里**及时出现** → **那就得等它跑完** → **而它跑一次几十秒** → **阻塞启动**
//   · **不等、直接读产物**？—— **产物是上一轮跑的** → **那是"拿存量当事件"（P31）**
//
// **→ 解法（Lead 认可的）**：**读上次产物，但在提示里明写"这是上次（几点）跑的"。**
//   **把时效性标出来，它就不再是 P31** —— P31 的病根是**"不标来源地拿旧数据当新的"**，
//   而**不是"读旧数据"本身**。
//
// ⚠️ **而"从没跑过"必须与"0 条绕过"分开** —— 否则又回到那个病：
//   **「没查」被当成「没问题」。**
function reconcileNotice(config) {
	const p = config.reconcileReport;
	if (!p) return null;
	let st;
	try { st = statSync(p); } catch {
		// ⚠️ **不能说"0 处绕过"** —— 那是把"没查"说成"没问题"
		return "· **整树对账：还没跑过**（产物不存在）—— "
			+ "**注意这不是「0 处绕过」，是「没查」**（两者在报告里长得一样，所以这里必须分开说）";
	}
	let d;
	try { d = JSON.parse(readFileSync(p, "utf8")); } catch {
		return `· 整树对账：产物读不动（\`${p}\`）—— **不报数**（读不到就不编）`;
	}
	const counts = d.counts || {};
	const nB = Number(counts.bypass !== undefined ? counts.bypass
		: (Array.isArray(d.bypass) ? d.bypass.length : NaN));
	if (!Number.isFinite(nB) || nB === 0) return null;      // 没绕过 → **静默**
	// ⏱ 时间**来自产物本身**（mtime），**不是"现在几点"**
	const ageH = (Date.now() - st.mtimeMs) / 3_600_000;
	const when = ageH < 1 ? `${Math.round(ageH * 60)} 分钟前`
		: ageH < 48 ? `${ageH.toFixed(1)} 小时前`
			: `**${(ageH / 24).toFixed(1)} 天前 —— 可能已过期**`;
	const nU = Number(counts.unknown || 0);
	return `· **整树对账发现 ${nB} 处「绕过」**（write/edit 之外的落盘）`
		+ (nU ? `｜另有 ${nU} 处**归因不到**（那些的"内容"没查过）` : "")
		+ `\n  —— 这份产物是 **${when}** 跑的（**时间取自产物本身**）。`
		+ `\n  它是什么：**用别的方式落盘、绕开了挂在 write/edit 上的检查** —— 那是**审计**，不是沙箱。`;
}

// ═══════════════════════════════════════════════════════════════════
// ⭐ ㉕ 「两条捞回」的结果提示 —— **照抄整树对账那套**（那个模板上次做对了）
// ═══════════════════════════════════════════════════════════════════
// **为什么照抄而不是另设计一套**：两条铁律是一样的 ——
//   ① **读上次产物 + 标明「这份产物是几点跑的」**（时间**取自产物本身**，不是"现在几点"）
//      —— 因为捞回要 64 秒，**本次会话不可能就绪**，只能给上一次的；**而标了时间它就不是 P31**。
//   ② **「还没跑过」≠「0 条候选」** —— 前者是"没查"，后者是"查了没有"。**必须分开说。**
function recoverNotice(config) {
	const p = config.recoverCandidates;
	if (!p) return null;
	let st;
	try { st = statSync(p); } catch {
		return "· **两条捞回：还没跑过**（产物不存在）—— "
			+ "**注意这不是「0 条候选」，是「没查」**（两者在报告里长得一样，所以必须分开说）";
	}
	let d;
	try { d = JSON.parse(readFileSync(p, "utf8")); } catch {
		return "· 两条捞回：产物读不动（`" + p + "`）—— **不报数**（读不到就不编）";
	}
	// ⚠️⚠️ 2026-09-27 修：**第一版读的是 `admission_total`，而那是「原始命中」不是「候选」。**
	//    它报出「捞到 4364 条」—— 而 `admission` 里混着 `who` 不同的东西：
	//      · **`ai_self`**（AI 自己承认的）2285 条 ← 只有这个算数
	//      · `ai_written`（AI 写的报告/脚本里引用）1404 —— **写 ≠ 说**
	//      · `teammate` 520 ｜ `system_injected` 82 ｜ `human_user` 43 ｜ `unknown` 30（**不许硬拆**）
	//    **→ 报 4364 的后果**：**让人以为有 4000 多条欠账永远处理不完** —— **那正是「墙纸」。**
	//    ★ **判据**：**欠账的数必须是真的欠账** —— 否则人一开始无视它，它就不再有效。
	//    ⚠️ **而 2285 仍然不是「该处理的那批」** —— 它还要再过一层「形状过滤」
	//       （我早先量过：形状过滤后约 501）。**那一层是判断，不在这个数据文件里**
	//       → 所以这里**只报 AI 自己承认的那个数**，**并说清它不是"待办清单"**。
	const arr = Array.isArray(d.admission) ? d.admission : [];
	// ⭐⭐ ㉗（2026-09-27）：**过滤口径也落成数据**（Lead：「那层判据要能被复核，不是"你说了算"」）。
	//    ⚠️ 而它不是新判断 —— 它是**从已有的抽样审搬过来的**
	//       （`audit-verdicts.json`，**抽样 30 条**，每条带 basis）。
	//    ⚠️ 表读不到 → **回落到「只按 who 数」**（fail open：**仍有设防，不是全放行**）
	//       —— 而那正好是**修这条之前的旧行为（2285）**，**所以最坏情况是"回到旧数"**。
	let keepShapes = null;
	let whoRule = "ai_self";
	try {
		if (config.triageRules) {
			const tr = JSON.parse(readFileSync(config.triageRules, "utf8"));
			if (Array.isArray(tr.keep_shapes) && tr.keep_shapes.length) {
				keepShapes = new Set(tr.keep_shapes);
			}
			if (typeof tr.who_rule === "string" && tr.who_rule) whoRule = tr.who_rule;
		}
	} catch { /* 表读不到 → keepShapes 仍是 null（只按 who 数） */ }
	const n = arr.filter((x) => x && x.who === whoRule
		&& (!keepShapes || keepShapes.has(x.shape))).length;
	if (!Number.isFinite(n) || n === 0) return null;      // **没有候选 → 静默**（别制造墙纸）
	const ageH = (Date.now() - st.mtimeMs) / 3_600_000;
	const when = ageH < 1 ? Math.round(ageH * 60) + " 分钟前"
		: ageH < 48 ? ageH.toFixed(1) + " 小时前"
			: "**" + (ageH / 24).toFixed(1) + " 天前 —— 可能已过期**";
	return "· **两条捞回捞到 " + n + " 条原始命中**（从会话日志里捞的：它自己踩的、"
		+ "护栏看不见的那些）\n"
		+ "  —— 这份产物是 **" + when + "** 捞的（**时间取自产物本身**）。\n"
		// ⚠️⚠️ 这一行是**必须的**，不是客套：
		//    那个数（2285）**不是「待办条数」** —— 它还要再过一层「**形状过滤**」才知道哪些是真候选
		//    （我早先量过：过滤后约 501）。**而过滤是判断，不在这个数据文件里。**
		//    ★ **为什么必须说**：**一个听起来处理不完的数，等于一个没人看的数** ——
		//      **它一开始就让人麻了，那它和"4364"犯的是同一个错**（只是小一点）。
		+ "  ⚠️ **而那个数不是「待办条数」** —— 它是**原始命中**，还要再过一层「按形状过滤」才知道哪些是真候选。\n"
		+ "  ⚠️ 而且它**是捞回，不是归类** —— 那些候选要不要进坑清单，仍要人拍板。";
}

// ═══════════════════════════════════════════════════════════════════
// ⭐ ㉝ **配置自检** —— 启动时 stat 一遍那些路径，缺哪个就说一句
// ═══════════════════════════════════════════════════════════════════
// 来由：**我往真配置里留了三个占位符**（`<your-data-dir>/…`）→
//   **插件从上线那一刻起就是断的，而「断」和「没跑过」在注入里长得一样。**
//   ★ **那和 `skipped-fresh` 是同一个家族：「以为它管」。**
//
// ⚠️⚠️ **边界（Lead 压的，我认同）**：**它只查「这个路径能不能用」**：
//   · **不存在** / **指向目录而不是文件**（本该是文件的）/ **看着就是占位符**
//   **—— 「内容对不对」「是不是旧的」不是它的事**（**那是"产品旧了"那个问题，
//     混进来会造成「旧了也算新的」—— 而那是这个项目专门防过的。**）
//
// ⭐ **"占位符"的判据（我选了一个结构性的，不是词表）**：
//   **`<` 和 `>` 在 Windows 路径里是非法字符**（NTFS 不允许）→
//   **所以含它们的路径"必然不是真路径"。**
//   ★ **为什么不用"可疑词表"**（`your-` / `TODO` 之类）：**词表会误报**
//     （**真路径里完全可能有个叫 `TODO` 的目录**）→ 而**误报一次，人就开始无视它**。
//   ⚠️ 而这条判据**在 Linux/macOS 上也成立**（`<` `>` 在那些文件系统里同样不是常规字符，
//     虽然不像 Windows 那样明文禁止 —— **但"配置里的路径带尖括号"在任何平台上都不是本意**）。
function configIssues(config) {
	const checks = [
		["rulesData", "规则表", "file"],
		["thresholdsData", "阈值表", "file"],
		["pitfallList", "坑清单", "file"],
		["ledgerPath", "台账", "file"],
		["reportsPath", "自报池", "file"],
		["triagePath", "已审台账", "file"],
		["pendingExpanded", "展开产物", "file-or-missing"],
		["reconcileReport", "整树对账产物", "file-or-missing"],
		["recoverCandidates", "捞回产物", "file-or-missing"],
		["triageRules", "过滤表", "file-or-missing"],
		["metricRegistry", "指标登记表", "file-or-missing"],
		["expandScript", "展开脚本", "file-or-missing"],
		["recoverScript", "捞回脚本", "file-or-missing"],
		["rescanScript", "重扫脚本", "file-or-missing"],
	];
	const bad = [];
	for (const [key, label, kind] of checks) {
		const v = config[key];
		if (!v || typeof v !== "string") continue;          // 没配 = 关掉了那一项，不算问题
		// ① **占位符**（结构判据：路径里带尖括号 —— 那在任何平台上都不是本意）
		if (v.includes("<") || v.includes(">")) {
			bad.push(`${label}（\`${key}\`）**还是占位符**：\`${v.slice(0, 56)}\``);
			continue;
		}
		// ② **存不存在 / 是不是文件**
		let st;
		try { st = statSync(v); } catch {
			if (kind === "file") bad.push(`${label}（\`${key}\`）**不存在**：\`${v}\``);
			continue;                                        // file-or-missing 的不存在是正常的（还没跑过）
		}
		if (!st.isFile()) bad.push(`${label}（\`${key}\`）**指向的是目录，不是文件**：\`${v}\``);
	}
	return bad;
}

// ═══════════════════════════════════════════════════════════════════
// ⭐ ㊱ **功能自证** —— 「这个判据现在还活着吗？」
// ═══════════════════════════════════════════════════════════════════
// 来由（用户 2026-09-27，Lead 派的**根因活**）：
//   「**把根因治好，不能说修一个 bug，出一个 bug。**」
//   而根因是：**「写一个功能」和「验证它真的会响」是两件事** ——
//   今晚一直是「**写完 + 挂具绿 = 完成**」，而**挂具验的是「代码路径通不通」，
//   不是「那条路径有没有被走到」**。**`skipped-fresh` 那个 bug 就是标本**。
//
// ⚠️⚠️ **而「数它响过几次」那个形态被否了**（我提的、Lead 批的），两条硬伤：
//   ① 它要**到处埋计数器** —— 那是「修一个出一个」的另一个版本
//   ② **「该不该响」不可判** —— 它需要「有没有发生」的信息，而那不在机制手上
//
// **→ 换成**：**喂一个最小合成输入，看它响不响** ✅
//   **答的是另一个问题**：**「它现在还活着吗」** —— 而**那个不用判，喂了就该响。**
//   ★ **它正是「挂具只证代码、不证部署」那句的严格版**：
//     **喂合成输入就是「在部署里跑挂具」** —— 真实代码路径 + 真实配置，只是输入是造的。
//
// ⚠️⚠️ **两条纪律（Lead 压的）**：
//   ① **要在临时目录里跑、用完就删** —— ⚠️ **这条自证目前不写盘**
//      （**它喂的全是内存里的合成输入**：命令串 / 文件内容 / 配置对象）
//      → **所以「清干净」这件事在这里是"不用清"，而不是"忘了清"** ✅
//   ② **自证失败时不许自动改任何东西** —— **它只报「这条不响了」**
//      （**「顺手修」就是「修一个出一个」的源头**）
function selfCheck(config, hooks) {
	const ok = [];
	const off = [];      // ⚠️ **第三种状态：此刻关着**（设计如此，不是坏）
	const bad = [];
	// ⚠️ `t3` 给「可能被配置关掉」的那些用 —— **它要能说清是哪一种**：
	//    · 关着 → 进 `off`，**并明说「它现在不会响」**（**那不等于它坏了**）
	//    · 开着而没响 → 进 `bad`（**那才是要报的**）
	const t3 = (label, enabled, fn) => {
		if (!enabled) {
			off.push(label + "（**被配置关掉了，现在不会响** —— 那不等于它坏了）");
			return;
		}
		t(label, fn);
	};
	const t = (label, fn) => {
		try { (fn() ? ok : bad).push(label); }
		catch (e) { bad.push(label + "（**它抛异常了**：" + String(e && e.message || e).slice(0, 60) + "）"); }
	};

	// ⚠️⚠️ **核心：喂的是「钩子」，不是「函数」**（2026-09-27，Lead 批的形态改动）。
	//    为什么：**"那个函数还活着吗"和"它会被调用吗"是两件事** ——
	//    而真正的失败模式是后者：`parseCheck:false` 时 `gateVerdict` 那条路**永远不被走到**，
	//    而**直接调它的自检还是绿的** ❌
	//    ★ **喂钩子 = 真的走一次 `ctx.tools.guard` / `tools/post-execute`** ——
	//      **真实代码路径 + 真实配置开关，只是输入是造的。**

	// ① **真的走一次 guard**：喂一条会被 G11 命中的命令 → 看它响不响
	t("钩子：guard 放行 + 提示（G11 / 2>&1）", () => {
		if (!hooks || typeof hooks.guard !== "function") return false;
		const r = hooks.guard({ name: "pwsh", arguments: { command: "cmd 2>&1" } });
		// ⚠️ G11 是 **warn** —— 所以 guard 返回 `undefined`（放行），而"响过"在**台账/提示**那边
		//    → **这里只能验"它没被拦"**；"响没响"要靠下面那条 post-execute
		return r === undefined;
	});
	// ② **真的走一次 post-execute**：喂一条该被提示的命令 → 看注入里有没有"护栏提示"
	t("钩子：post-execute 会注入护栏提示", () => {
		if (!hooks || typeof hooks.postExec !== "function") return false;
		const r = hooks.postExec({ name: "pwsh", arguments: { command: "cmd 2>&1" } });
		return !!(r && r.injected && r.hasWarn);
	});
	// ③ **真的走一次 post-execute**：喂一个带 error 的结果 → 看"自报入口"响不响
	t("钩子：自报入口会响（喂一个 error）", () => {
		if (!hooks || typeof hooks.postExec !== "function") return false;
		const r = hooks.postExec({ name: "write", arguments: { file_path: "/tmp/_sc.py" } },
			{ error: { name: "FsError", code: "FS_NOT_OBSERVED" } });
		return !!(r && r.injected && r.hasReportHint);
	});
	// ④ **真的走一次 guard**：喂一段会被解析闸/ BOM 拦下的写入 → 看它拦不拦
	//    ⚠️ **这条才是"配置开关真的生效了吗"的答案**（`parseCheck:false` 时它会放行 → 这条就红）
	t3("钩子：解析闸会拦坏 .py", config.parseCheck !== false, () => {
		if (!hooks || typeof hooks.guard !== "function") return false;
		const r = hooks.guard({ name: "write",
			arguments: { file_path: "/tmp/_sc.py", content: "def f(:\n" } });
		return typeof r === "string" && r.includes("G41");
	});
	// ⑤ BOM：喂带 BOM 的内容 → 看它单独认出（**而不是当成语法错**）
	t3("钩子：BOM 单独认出（不是语法错）", config.parseCheck !== false, () => {
		if (!hooks || typeof hooks.guard !== "function") return false;
		const r = hooks.guard({ name: "write",
			arguments: { file_path: "/tmp/_sc.py", content: "\uFEFFx = 1\n" } });
		return typeof r === "string" && r.includes("BOM");
	});
	// ⑥ 阈值：读一个阈值，看它是不是数字（数据坏了会回落，回落也是数字）
	t("阈值可读（circuitBreaker.max）", () => typeof threshold("circuitBreaker.max") === "number");
	// ⑦ 配置自检**自己**：喂一个占位符，看它报不报
	t("配置自检能认出占位符", () => {
		try { return configIssues({ rulesData: "<your-dir>/x.json" }).length > 0; }
		catch { return false; }
	});
	// ⑧ ④ **产物新不新鲜**（存在 ≠ 它是新的）
	t("产物新鲜（不存在 = 还没跑过，不算坏）", () => {
		const p = config.reconcileReport;
		if (!p) return true;                       // 没配 = 关掉了那一项
		let st;
		try { st = statSync(p); } catch { return true; }   // **不存在 = 还没跑过**，不是坏
		const ageH = (Date.now() - st.mtimeMs) / 3_600_000;
		return ageH < (Number(config.selfCheckStaleHours) || 72);
	});
	return { ok, off, bad };
}

function maybeRescan(config, trigger) {
	const stamp = (line) => {
		try {
			mkdirSync(dirname(config.rescanStampPath), { recursive: true });
			appendFileSync(config.rescanStampPath,
				`${new Date().toISOString()} [${trigger}] ${line}\n`);
		} catch { /* 凭据失败也绝不能影响启动 */ }
	};
	if (!config.rescanScript || !config.rescanStampPath) {
		// 没法写凭据（连路径都没配）—— 只能静默
		return;
	}
	try {
		let last = 0;
		try { last = Number(statSync(config.rescanStampPath).mtimeMs) || 0; } catch { last = 0; }
		const ageH = last ? (Date.now() - last) / 3_600_000 : Infinity;
		const stale = config.rescanStaleHours || 24;
		if (last && ageH < stale) {
			// ⚠️⚠️ **这里原来是 `stamp(...)` —— 而它是个真 bug（2026-09-27 查出，Lead 报的）**：
			//    `stamp()` 写的是**同一个文件**（`rescanStampPath`）→ **它刷新了 mtime**
			//    → **下次 `ageH` 又从 0 开始** → **永远 < stale** → **永远不会跑。**
			//    ★ **凭据文件里 18 行全是 `skipped-fresh`，而 `spawned` 一次都没有** ——
			//      **"跳过"这个动作，把自己下一次的判据推进了循环。**
			//    ★ **而那让"它每天会自动重扫"变成一句假话**（**实际一次都没跑**）
			//      —— **这是"以为它在管"的又一个实例**（而这个项目把那条写在 `limitations` 第一条）。
			//    → **修法：跳过记录写**另一个文件**；判据只看 `rescanStampPath` 的 mtime**
			//      （**它的 mtime 从此只代表"上次真的跑过"**）。
			//    ⚠️ 用 `+ ".skip.log"` 而不是新加一个配置项 —— **少一个要配的东西**。
			try {
				appendFileSync(config.rescanStampPath + ".skip.log",
					`${new Date().toISOString()} [${trigger}] skipped-fresh `
					+ `ageH=${ageH.toFixed(1)} < ${stale}\n`);
			} catch { /* 跳过记录写不了也绝不能影响启动 */ }
			return;
		}
		const py = process.env.DSH_PYTHON || "python";
		// ⚠️ **#3 捕获 stderr**（2026-09-27）—— **不改整体设计**（stdio 仍不读进内存），
		//    只把 **stderr 的去向**从「丢弃」改成「一个文件描述符」：`["ignore", "ignore", errFd]`
		let errFd = "ignore";
		try { errFd = openSync(String(config.rescanScript) + ".stderr.log", "a"); }
		catch { /* 打不开就退回丢弃（**绝不影响 spawn**） */ }
		const child = spawn(py, [config.rescanScript], {
			detached: true, stdio: ["ignore", "ignore", errFd], windowsHide: true,
		});
		// ⚠️ 必须挂 error 处理器：子进程启动失败（例如 python 不在 PATH）会触发 'error' 事件，
		//    而**未处理的 'error' 事件会变成未捕获异常，把宿主进程干掉**。
		//    重扫是可选功能，绝不能因为它把整个桌面端搞崩。
		child.on("error", (e) => { stamp(`spawn-error ${String(e && e.message || e).slice(0, 90)}`); });
		child.unref();
		try { if (errFd !== "ignore") closeSync(errFd); } catch { /* 关不掉不影响 */ }
		// ⭐ ㉕ **第二条：捞回**（2026-09-27，用户批「可以的做」）。
		//    它补的是**第三层**：用户问「我其他会话现在工作，它如果犯错的话，它会自动记账吗？」
		//      ① 被护栏拦/提示      → ✅ 全自动（钩子跟会话无关）
		//      ② 命令报错（失败信号）→ ✅ 定期重扫会捞
		//      ③ **它自己踩的、护栏看不见的** → ❌ 不自动 ← **本条补的就是它**
		//    ⚠️ 和重扫**共用同一个"距上次多久"的判断** —— 两者都是几十秒的后台活，
		//       **没必要为它们各记一套时间戳**。
		//    ⚠️ **它必须挂 error 处理器**（同上面那条：未处理的 error 会把宿主干掉）。
		if (config.recoverScript) {
						// ⚠️ **#3 捕获 stderr**（2026-09-27）—— **不改整体设计**（stdio 仍不读进内存），
						//    只把 **stderr 的去向**从「丢弃」改成「一个文件描述符」：`["ignore", "ignore", errFd]`
						let errFd = "ignore";
						try { errFd = openSync(String(config.recoverScript) + ".stderr.log", "a"); }
						catch { /* 打不开就退回丢弃（**绝不影响 spawn**） */ }
						const c2 = spawn(py, [config.recoverScript], {
			detached: true, stdio: ["ignore", "ignore", errFd], windowsHide: true,
			});
			c2.on("error", (e) => { stamp(`spawn-error(捞回) ${String(e && e.message || e).slice(0, 90)}`); });
			c2.unref();
						try { if (errFd !== "ignore") closeSync(errFd); } catch { /* 关不掉不影响 */ }
			stamp(`spawned(捞回) pid=${c2.pid} script=${config.recoverScript}`);
		}
		stamp(`spawned pid=${child.pid} ageH=${last ? ageH.toFixed(1) : "n/a(first-run)"} script=${config.rescanScript}`);
	} catch (e) {
		stamp(`error ${String(e && e.message || e).slice(0, 120)}`);
	}
}

export function apply(ctx, config) {
	// ⚠️ 它由 `ctx.tools.guard(guardFn = …)` 赋值 —— **声明必须在用它之前**
	//    （我第一次放晚了 → `Cannot access 'guardFn' before initialization`）
	let guardFn = null;
	// ⚠️ 熔断上限的优先级：**配置 > 阈值数据文件 > 代码默认 5**
	//    （已有的 `config.refuseCap` 仍然最优先 —— **不破坏向后兼容**）
	const cap = Math.max(1, Number(config.refuseCap) || threshold("circuitBreaker.max") || 5);
	// ⑧ 规则数据化：把"数据文件路径 + 代码默认兜底"交给加载器。
	//    加载器**每次 evaluate 时**按 mtime+size 判断要不要重读（实测 19 µs，见 measure_rules_data.mjs）。
	configureRules({ path: config.rulesData, fallback: RULES, shellTools: SHELL_TOOLS });
	// ⑪ 阈值登记表：**同一套机制**（读不到 → 代码默认，不是"没有阈值"）
	configureThresholds({ path: config.thresholdsData });

	// ───────── ⑤ 定期重扫（"定期"必须真的自己发生） ─────────
	// 两条触发点，缺一不可：
	//   (a) session-start —— 语义上最正确；但**如果插件挂载晚于会话启动，这个事件已经过去了**
	//       （实测：重启后凭据始终不出现，怀疑就是这条）
	//   (b) 首次工具活动 —— **兜底**。只要有工具调用就一定会走到，保证"迟早会跑"。
	let rescanChecked = false;
	/** 最近一次由 guard 见到的会话 id（给 guardrail_report 用 —— 它自己的 execute 拿不到上下文）。 */
	let lastSessionId = null;
	try {
		ctx.on("agent/session-start", () => { maybeRescan(config, "session-start"); });
	} catch { /* 事件名不被支持也不影响其余功能 */ }

	// ───────── ① guard：动手前拦（只拦 3 条） ─────────
	ctx.tools.guard(guardFn = (exec) => {
		// ⭐ ③ 先记「这个会话读过哪些文件」—— `readBefore` 的唯一来源。
		//    它必须在别的判断**之前**跑（否则这次 read 之后的 edit 就看不到它了）。
		noteRead(exec);

		// ⑤(b) 兜底触发：只在首次工具活动时判一次，绝不重复、绝不阻塞
		if (!rescanChecked) { rescanChecked = true; maybeRescan(config, "lazy-first-tool"); }

		// 记下最近一次见到的会话 id。
		// 为什么放在 guard 里：**guard 对每一次工具调用都会跑**，包括 guardrail_report 自己那次
		// —— 所以 report 的 execute 执行时，这个值正好是"它自己那个会话"。
		// ⚠️ 已知局限：它是"本进程最近一次见到的会话"。单用户桌面下正确；
		//    若同一进程里并发跑多个会话，可能取到别的会话 —— 那种情况下宁可不写（见 report 里判断）。
		const sid = sessionIdOf(exec);
		if (sid) lastSessionId = sid;

		// ───── ⑥ 裸数字检查：`send_message` 发出去**之前**扫它 ─────
		// 为什么在这里：口径登记表只管住"照规矩报数的人"；谁绕过生成器手写一个数字发出去，
		// 原本机制看不见。而 send_message 本身也是一次工具调用 → 能在**动手前**扫。
		// ⚠️ 只在**精确条件**下拦（关键词附近 + 不在生成器标记块里），拒绝率必须极低。
		if (config.metricRegistry && exec.name === "send_message") {
			const text = String((exec.arguments && exec.arguments.message) || "");
			const reg = loadMetrics(config.metricRegistry);
			if (reg && text) {
				const hits = scanBareMetricNumbers(text, reg);
				if (hits.length > 0) {
					const list = hits.slice(0, 4).map((h) =>
						`· 写了 **${h.shown}**（出现在「${h.keyword}」附近）—— `
						+ (h.inRegistry ? "这个数在登记表里有，但**没走生成器**"
							: "**登记表里没有这个数**（可能是凭空写的）")).join("\n");
					ledger(config, { kind: "refused", rule: "G31", pitfall: "P30",
						tool: exec.name, count: 1, cmd: `裸数字×${hits.length}` }, exec);
					return `[护栏 G31 / 坑清单 P30] 这条消息里有**手写的指标数字**，没走生成器：\n${list}\n`
						+ "→ 三条出路，按情况挑：\n"
						+ "  ⚠️ **先注意**：这条拒绝是**整条消息**被拦 —— **不是只拦那个数字**。\n"
						+ "     所以消息里**别的正事也会一起发不出去**。别让一个数字带走别的请求。\n"
						+ "  ① 消息里**还有别的正事** → **先把其余部分单独发一次**，再处理这个数字。\n"
						+ "  ② 这个数**必须报** → 用 `report_gen.Generator.block('<metric>')` 产出数字块"
						+ "（自带版本、强制双报、上升自动成节、带 `<!--METRIC:-->` 标记），把它贴进消息。\n"
						+ "  ③ 只是**顺口提及** → 改成不带具体数值的说法"
						+ "（例如「详见 metrics/registry.json」），或直接删掉那个数。\n"
						+ "  （护栏不判断你有没有作弊 —— 它只要求**指标数字走正门**。）";
				}
			}
		}

		const { blocks } = evaluate(exec);
		if (blocks.length === 0) {
			// ───── ⑦ 第 5 条规则：解析闸 ─────
			// 隔离⑤：**放在现有规则之后** —— 走到这里说明"现有 4 条规则都没意见"，
			//        所以即使这一条行为异常，**现有规则的判定已经完成了**。
			// 隔离③：单独开关 `parseCheck`（出问题只关它）。
			// 隔离②：整段包 try/catch；它抛任何异常 → **放行**，且记一条（不然坏了没人知道）。
			// 隔离④：独立台账 kind（`parse_blocked`）+ 独立熔断表（`parseRefusals`）+ 独立 rule id（G41）。
			if (config.parseCheck) {
				try {
					const v = gateVerdict(exec, {
						maxBytes: config.parseMaxBytes, timeoutMs: config.parseTimeoutMs,
					});
					if (v) {
						// ⭐⭐ **G41 不参与熔断**（2026-09-26，判据见 rules-data.json 的 authoritativeNote）。
						//    熔断的前提是「**拒绝的理由可能不成立**」—— 连拦 5 次就放行，
						//    是为了**不让「诚实报告卡住」的 AI 被卡死**。
						//    而 G41 的理由**来自解析器**（`ast.parse` / `node --check`）—— **它不可能不成立**。
						//    → **熔断在这里没有保护对象，只有副作用：让一个确实写坏了的文件落盘。**
						//    ⚠️ **别和 fail open 混**：fail open 管「**它自己出故障**」（解析器崩了 → 放行）；
						//       熔断管「**我烦了**」。**G41 只需要前者。**
						//    ⚠️ 判据是**数据驱动的**（`authoritativeRules`）—— 将来接 lint 加进去即可，不用改代码。
						const breakable = !isAuthoritative("G41");
						const pk = `parse|${agentIdOf(exec)}|${exec.name}`;
						const pn = (parseRefusals.get(pk) || 0) + 1;
						if (breakable && pn >= cap) {
							parseRefusals.delete(pk);
							ledger(config, { kind: "parse_cap_reached", rule: "G41",
								tool: exec.name, file: v.file, count: pn }, exec);
							return undefined;
						}
						parseRefusals.set(pk, pn);
						ledger(config, { kind: "parse_blocked", rule: "G41",
							tool: exec.name, file: v.file, reason: v.reason,
							line: v.line, msg: v.msg, count: pn,
							// ⭐ 把「这条不熔断」也记进台账 —— 否则将来数"为什么它拦了 20 次"
							//    会以为熔断坏了（其实是设计）
							circuitBreakable: breakable }, exec);
						const where = v.line ? `，第 ${v.line} 行` : "";
						// ⭐ ⑤ BOM 命中时**标题和改法都要换** ——
						//    它的病根**不是语法**（语法是对的，是字节层多了一段）
						//    → 若还说"修掉那一行的语法"，**那条改法会把人带偏。**
						const isBom = v.bom === true;
						return (isBom
							? `[护栏 G41 · BOM] **写下去的东西开头有 BOM** —— 没让它落盘。\n`
								+ `  文件：${v.file}\n`
								+ `  ${v.reason}\n`
								+ `→ 改法：**把开头那 3 个字节去掉**（或用不带 BOM 的写法重写）。\n`
								+ `  ⚠️ **别去"修语法"** —— 语法是对的，是**字节层多了一段**。\n`
								+ `  （判据是**字节本身**（\`EF BB BF\`）—— 和解析器一样是机械的，不可能误判。）\n`
							: `[护栏 G41] **写下去的东西解析不了** —— 没让它落盘。\n`
								+ `  文件：${v.file}\n`
								+ `  ${v.reason}${where}：${v.msg}\n`
								+ `→ 改法：修掉那一行的语法，再写一次。\n`
								+ `  （判据是**解析器自己说的**，不是我说的 —— 这段字节确实解析不了。）\n`)
							// ⚠️⚠️ 2026-09-26 修（**Lead 抓到的真 bug**）：
							//    这里原来写死「（第 N/5 次。再被拒 N 次本关会自动放行并记为熔断。）」
							//    —— **而 G41 已经"不熔断"了** → **那句话是假的。**
							//    **形状**：**文案里写死了"具体行为"，而行为已经改了。**
							//    （同族：写死的「0 条」、写死的「版本 0.1.3→0.1.4」。）
							//    **判据：文案里出现"具体行为描述"时，问一句「它是不是写死的」。**
							+ (breakable
								? `  （第 ${pn}/${cap} 次。再被拒 ${cap - pn} 次本关会自动放行并记为熔断。）`
								: `  （第 ${pn} 次被拒。**这条规则的判据来自权威工具，不会熔断放行**`
									+ ` —— 请改对再写。**分母/次数在这里没有意义，所以不显示**。）`);
					}
				} catch (e) {
					try {
						ledger(config, { kind: "parse_gate_error", rule: "G41", tool: exec.name,
							err: String((e && e.message) || e).slice(0, 200) }, exec);
					} catch { /* 连台账都写不了就算了 */ }
					return undefined;   // 隔离②：它自己坏了 → **放行**
				}
			}
			return undefined;
		}

		const first = blocks[0];
		const aid = agentIdOf(exec);
		const key = `${aid}|${exec.name}`;
		const n = (refusals.get(key) || 0) + 1;
		const cmd = String((exec.arguments && exec.arguments.command) || "").slice(0, 200);

		// 熔断：满 cap 次就放行 + 记台账（绝不用"无限拦"惩罚诚实报告卡住的 AI）
		if (n >= cap) {
			refusals.delete(key);
			ledger(config, { kind: "cap_reached", rule: first.id, pitfall: first.pitfall,
				tool: exec.name, count: n, cmd }, exec);
			return undefined;
		}
		refusals.set(key, n);

		// ⚠️ **必须在写台账之前取证据** —— 否则这一次拒绝会被算进「拦过几次」，
		//    于是"拦过 4 次"和"这是第 1/5 次被拒"**自相矛盾**。
		//    （挂具抓的：我第一版写在 `ledger()` 之后，数出来正好多 1。）
		const st = ruleStats(config.ledgerPath, first.id);

		ledger(config, { kind: "refused", rule: first.id, pitfall: first.pitfall,
			tool: exec.name, count: n, cmd }, exec);

		// ⚠️⚠️ 2026-09-26 修（**Lead 抓到的真 bug**）：这一段原来**无条件**承诺"会自动放行"。
		//    而 **G31 也在权威名单里**（`authoritativeRules: ["G41","G31"]`）→ **它的回执同样是假话。**
		//    **判据**：**文案里写死了"具体行为" → 行为一改，文案就开始撒谎。**
		//    → 所以这里按 `circuitBreakable` 分岔，**而且"分母/剩余次数"对不熔断的规则没有意义，不显示**。
		const mainBreakable = !isAuthoritative(first.id);
		const hint = mainBreakable
			? (n >= cap - 1
				? `（这是第 ${n}/${cap} 次被拒。再被拒 ${cap - n} 次本关会自动放行并记为熔断，台账会留下记录——不会把你卡死。）`
				: `（这是第 ${n}/${cap} 次被拒。）`)
			: `（这是第 ${n} 次被拒。**这条规则的判据来自权威工具，不会熔断放行** —— 请改对再来。）`;
		// ⭐ ① 给它「服气」的第三样：**证据**。
		//    Lead：「数据从哪来：台账按 rule 计数（**现在就有**）。**证据比命令更有说服力。**」
		//    ⚠️ 拿不到证据就**不写这一行**（不编数）。⚠️ `st` 取自**写台账之前**（见上）。
		const evLine = st && (st.ref > 0 || st.warn > 0)
			? `\n  ← 台账记录：这条规则**拦过 ${st.ref} 次**｜提示过 ${st.warn} 次`
				+ (st.dispute > 0 ? `｜**被你申辩过 ${st.dispute} 次**（申辩会影响它的画像）` : "")
			: "";
		const fileLine = (() => {
			const f = fileFacts(exec);
			if (!f.file) return "";
			const rb = readBefore(exec, f.file);
			return `\n  ← 这个文件：\`${f.file}\``
				+ (f.targetExists === undefined ? "" : `（${f.targetExists ? "已存在" : "不存在"}）`)
				+ (rb === undefined ? "" : `｜本会话${rb ? "**读过**" : "**没读过**"}`);
		})();
		// ⭐ ② 申辩入口 —— **把入口放在"我正好在看它的那一刻"**。
		//    Lead（2026-09-26）：「**"要我记得去调"就完蛋了**」——
		//    而这条正是我今天第七次踩 BOM 学到的：**给一个够不着的建议，等于没给建议。**
		//
		//    ⚠️ **但别每次都喊**（回执本身已经有 3~4 行了，再喊就成墙）：
		//      只在**这两种情况**带这一句：
		//        (a) 这条规则**有争议史**（那说明它真被质疑过）
		//        (b) **本会话第一次被它拒**（那是我最需要知道"还有这条出路"的时候）
		const disputeLine = (() => {
			const hasHistory = !!(st && st.dispute > 0);
			const firstThisSession = n === 1;
			if (!hasHistory && !firstThisSession) return "";
			const why = hasHistory
				? `（这条规则被申辩过 ${st.dispute} 次）`
				: `（本会话第一次被它拒）`;
			return `\n  💬 认为这次是误报 → 调 \`guardrail_dispute "${first.id}" "<具体理由>"\` ${why}`
				+ `\n     （**申辩不会自动改规则**；争议率进规则画像，超门槛才提示重审）`;
		})();
		return `[护栏 ${first.id} / 坑清单 ${first.pitfall}] ${first.why}${evLine}${fileLine}${disputeLine}\n→ 改法：${first.fix} ${hint}`;
	});

	// ───────── ② warn：放行 + 提示（走 post-execute，**显式转发 downstream**） ─────────
	// ⭐ ⑨ 同时在这里做**会话级提示**（"要人记得" → "它自己会说"）。
	//    为什么挂这儿而**不挂 `agent/session-start`**：
	//      · session-start 的注入形状我没验过（不知道支不支持 additionalContexts）；
	//        而 post-execute 的注入**已经跑通了**（护栏提示就是这么发的）。
	//      · 而且语义上更对：**我"第一次动手"的时候说我一句**，比会话一开就喊更有用。
	// ⭐ ㊱ **喂钩子的两个入口**（2026-09-27）——
	//    `guard` 用的是**真的那个函数**（同步，就是宿主调的那个）✅
	//    ⚠️ 而 `postExec` 那个探测**复用同一段判断，但没走 async 包装** ——
	//      **因为 `tools/post-execute` 是 async、而自检是同步的。**
	//      **→ 所以它"差不多"但不是"完全等同地走了一遍钩子"** —— **这点写在返回值里**（**别让人以为它更严**）。
	// ⚠️⚠️ **自证不许往台账写**（2026-09-27，Lead 批的 A 案；**实测过**：自证那两条会真 append）——
	//    它走的是**真钩子** → 解析闸那两条会 `ledger(config, {kind:"parse_blocked", …})`。
	//    ★ 手法是**那个现成的开关**（**没新造机制**）：`ledger()` 第一行就是
	//      `if (!config.ledgerPath) return;` → **在这两个探测外面临时置空，`finally` 里还回去。**
	//    ⚠️ **为什么安全**：`guardFn` 是**同步**的（解析器是 `execFileSync`）
	//      → 置空期间**没有别人**能看见那个临时值。
	//    ⚠️ **而它只管自证这一条路**：宿主真实的工具调用走 `ctx.tools.guard(guardFn)`，
	//      **不经过 `hooks`** → **真被拦时照写**（对照：`zz_ledger_probe2.mjs` 直接调 cap.guard）。
	const withoutLedger = (fn) => (...a) => {
		const saved = config.ledgerPath;
		config.ledgerPath = "";
		try { return fn(...a); } finally { config.ledgerPath = saved; }
	};
	const hooks = {
		guard: withoutLedger((exec) => guardFn(exec)),
		postExec: withoutLedger((exec, result) => {
			try {
				const r = evaluate(exec);
				const hasWarn = !!(r && r.warns && r.warns.length > 0);
				// ⚠️ 自报入口的判据**照抄那边那几行**（`error` 字段 + 每会话一次）
				const hasReportHint = !!(result && typeof result === "object" && result.error);
				return { injected: hasWarn || hasReportHint, hasWarn, hasReportHint };
			} catch { return { injected: false, hasWarn: false, hasReportHint: false }; }
		}),
	};
	let noticeDone = false;
	// ⭐ ㉘「要不要记一笔」那提示**每会话只带一次**（别变墙纸）
	let reportHintDone = false;
	/**
	 * ⭐ ⑨ 会话级**四个数** —— 回答「那几件事处理完没有」。
	 *
	 * Lead（2026-09-26）：「**要能查**：待归类几条 / 待升格候选几条 / 待重审几条 /
	 * **处理完 = 这几个数归零**（或明确标『暂不处理，理由 X』）。」
	 * 而它们**全放在会话启动提示里**（同一个位置）—— **归零就静默**。
	 */
	const takeNotice = () => {
		// ⚠️⚠️ **拆开关**（2026-09-27）：这里原来是**整段早退** ——
		//    而「配置自检」和「功能自证」也在这段里 →
		//    **用户关掉 `sessionNotice`（偏好），故障灯就一起灭了。**
		//    ★ 现在：**`sessionNotice` 只管「欠账」那部分**；
		//      **故障类走自己的开关（`reportBrokenConfig` / `reportDeadJudgements`），且默认开。**
		if (noticeDone) return null;
		noticeDone = true;
		// ⚠️ **攒完再筛**（Lead 批的形态，2026-09-27）——
		//    两个数组分开攒，**最后按开关拼一次** —— 那一次拼接是唯一的筛点。
		//    ⚠️ 而**数出来的事实**：欠账 9 处 / 故障 3 处（**共 12 处**）——
		//      「靠结构上做不到」只对**还没写的**代码成立；**对已散落的，只能老实改。**
		const LEDGER = [];   // 欠账类：归 `sessionNotice` 那个偏好开关管
		const FAULT = [];    // 故障类：有自己的开关（默认开）—— **故障不该被偏好关掉**
		// ⚠️ **只有「欠账」类**归这个偏好开关管（**故障类不归它**）
		const wantLedgerNotice = config.sessionNotice !== false;
		// ① 待归类（自报池 → 坑清单，中间靠人肉的那个洞）
		//    ⭐ C（2026-09-26）：**不只报个数，把原句也报出来** ——
		//    用户要的是「**给我 1 2 3 4 5 让我判断**」：
		//      护栏给"哪几条 + 原句" ｜ Lead 补"建议归哪组 + 依据" ｜ **用户只需要点头或否**
		//    ⚠️ 三条要求：①只报没归类的 + **每条截断** ②条数多时报「共 N 条，先列前 N 条」
		//      ③**仍然能关**（走 sessionNotice）
		try {
			const d = unclassifiedDetail(config);
			// ⭐ ⑬ 「判定不进清单」的**单独报一类**（不混进"待归类"，也不让它消失）
			//    用户的理由要保住：「**留着一条反而证明『看过了但不进』被记住了**」
			//    → 所以**不是让它消失，是让它报在另一类里。**
			const tri = d && d.triaged > 0
				? `· **已审并判定「不进清单」${d.triaged} 条**`
					+ `（**不是没处理** —— 是看了、判了、记了理由；理由见 \`pitfall-triage.jsonl\`）`
				: null;
			if (d && d.total > 0) {
				const SHOW = 5;                       // ⚠️ 上限 —— 别让注入变成一堵墙
				const head = `· **待归类 ${d.total} 条**（自报池里没进坑清单的）`
					+ (d.total > SHOW ? `，**先列前 ${SHOW} 条**：` : "：");
				const items = d.shown.slice(0, SHOW)
					.map((x) => `    ${x.line}. ${x.what}${x.what.length >= 120 ? "…" : ""}`);
				// ⭐⭐ ㉒（2026-09-27）：**优先报"展开好的"** ——
				//    用户问「**那我们怎么打通啊？**」→ 而 **②「按形状聚类 + 找最接近的已有坑」
				//    本来就是机械的**（脚本能算）→ **别让会话再去人肉展开一遍。**
				//    ⚠️ **读不到/对不上 → 回落成原样那句**（fail open：**不是不报**）。
				//    ⚠️ **而且标"这份展开是什么时候算的"**（P31）——
				//      **旧展开当成新的，比没有展开更坏。**
				// ⭐⭐ ㉓（2026-09-27）：**同步跑一次展开，再读它** ——
				//    这是"本次会话就绪"的唯一办法（异步 spawn 只能给"上一次的"）。
				//    ⚠️ **失败了就回落** —— 别因为展开不了就不报（那会让"待归类"整个消失）。
				try {
					if (config.expandScript) {
						execFileSync(process.env.DSH_PYTHON || "python",
							[config.expandScript],
							{ timeout: config.expandTimeoutMs || 3000, stdio: "ignore" });
					}
				} catch { /* 跑不了/超时 → 下面读到的就是旧产物，或者干脆回落到原句 */ }
				let expandedBlock = null;
				try {
					if (config.pendingExpanded) {
						const st = statSync(config.pendingExpanded);
						const ex = JSON.parse(readFileSync(config.pendingExpanded, "utf8"));
						// ⚠️ **只在"它对得上现在这个数"时才用** —— 否则说明池子变了、展开过期了
						if (ex && Number(ex.total) === d.total && Array.isArray(ex.items)) {
							const ageH = (Date.now() - st.mtimeMs) / 3_600_000;
							const when = ageH < 1 ? `${Math.round(ageH * 60)} 分钟前`
								: ageH < 48 ? `${ageH.toFixed(1)} 小时前`
									: `**${(ageH / 24).toFixed(1)} 天前 —— 可能已过期**`;
							const body = ex.items.slice(0, SHOW).map((it) => {
								const near = (it.nearest && it.nearest.length)
									? it.nearest.map((x) => `${x.id}「${x.name}」`).join(" / ")
									: "**没有接近的已归类坑**（**不硬指**）";
								return `    ${it.line}. 【${it.shape_human}】${String(it.what || "").slice(0, 90)}\n`
									+ `       → 最接近：${near}`;
							}).join("\n");
							expandedBlock = `· **待归类 ${d.total} 条**（**已按形状归好类**，每条带最接近的已有坑）：\n`
								+ body
								+ `\n    ⚠️ **"归到哪组"仍要人拍板**（**别自动归**）—— 但**判断的原材料已经摆好了**。`
								// ⭐ ㉔（2026-09-27）：「更硬那句」。
								//
								// ⚠️⚠️ **它不是什么 —— 这层意思必须留住，否则将来有人会把它写成催促、然后变成墙纸：**
								//     · **它不是"催你动"** —— **任何文案都改不了"看到了不动"**
								//       （"动不动"是会话愿不愿意，不是信号够不够硬）。
								//     · **它的价值只有一个**：把「**要做什么**」从「**人得自己想**」变成「**写着**」。
								//     · **而我们特意停在"写清动作"这一档，没升到"⚠️ 未处理，请现在处理"** ——
								//       那一档**开始像命令，而命令多了就是墙纸**（今晚反复算过这笔账）。
								//     ★ 判据：**提醒的收益 = "它让人少想一步"；一旦它开始"要求"，收益就转成成本。**
								+ `\n    → **该动作：把上面每条归到一组，或判定「不进清单」**`
								+ `\n    ⏱ 这份展开是 **${when}** 算的（${st.mtime.toISOString().slice(0, 16).replace("T", " ")}，`
								+ `**取自产物本身**）—— **池子变了它就对不上，那就自动回落成原句。**`;
						}
					}
				} catch { /* 展开读不到/坏了 → 回落（**fail open**） */ }
				LEDGER.push(expandedBlock || (head + "\n" + items.join("\n")
					+ `\n    归类要判断（算不算新坑 / 归到哪组 / 依据什么），**别自动归**`)
					+ (d.caveat ? `\n    ${d.caveat}` : "")
					+ (tri ? `\n${tri}` : ""));
			} else if (tri) {
				// 待归类归零了，但"已审不进"那类还该被看见（**否则它就消失了**）
				LEDGER.push(`· **待归类 0 条** ✅\n${tri}`);
			}
		} catch { /* 数不出来就不说（不编数） */ }
		// ② 待升格候选（**B 档：判据是我们自己写的正则 → 只能提示 + 拍板**）
		//    ⭐ 升格通道（2026-09-26）：**按「判据能不能写」分类报** ——
		//    用户问「**那它怎么变成规则呢？**」→ 而只报个名字，**那条路还是堵着**。
		//    → 分类之后，**用户只需要对「✅ 能写」那几条点头**（其余的他不用管）。
		try {
			const r = promoteCandidates(config);
			if (r && r.length > 0) {
				const v = r.byVerdict || {};
				const seg = [];
				if ((v.yes || []).length) {
					seg.push(`✅ **判据能写、可以升格 ${v.yes.length} 条**：`
						+ `${v.yes.slice(0, 3).join(" / ")} —— **这几条只需要你点头**`);
				}
				if ((v.half || []).length) {
					seg.push(`⚠️ 只有一半能判 ${v.half.length} 条：${v.half.slice(0, 3).join(" / ")}`
						+ `（**另一半拦不住**，只做能判的那半）`);
				}
				if ((v.no || []).length) {
					seg.push(`❌ **拦不住 ${v.no.length} 条**：${v.no.slice(0, 3).join(" / ")}`
						+ `${(v.no || []).length > 3 ? " …" : ""} —— `
						+ `**它们的判据要理解语义，写成规则只会误报**（**如实说，不硬造**）`);
				}
				if ((v.unjudged || []).length) {
					seg.push(`❓ 还没判过 ${v.unjudged.length} 条：${v.unjudged.slice(0, 3).join(" / ")}`);
				}
				LEDGER.push(`· **待升格候选 ${r.length} 条**（判据能不能写，逐条判过了）：\n`
					+ seg.map((s) => `    ${s}`).join("\n")
					+ `\n    ⚠️ **一条从不触发的规则 = 只有成本** —— 所以"拦不住"的那些**不硬造**。`
					+ `\n    ⚠️ 而 **A 档（真自动升格）**只对「判据来自权威工具」的适用，**而它现在的意义不是「能自动升格」，是「它不会误报」（判据是机械的）—— 第一条够格的是 safe_count**。`);
			} else if (r && r.alreadyPromoted && r.alreadyPromoted.length) {
				// ⭐ 候选归零了，但"已经升过"的还该被看见（**否则它就消失了** —— 和"已审不进"同一个道理）
				LEDGER.push(`· **待升格候选 0 条** ✅ —— **都升过了**：\n`
					+ r.alreadyPromoted.map((s) => `    ✅ ${s}`).join("\n"));
			}
			// ⭐ ⑯：**候选列表非空时，"已经升过"的那些也要报一行**（否则看不到"做过什么"）
			if (r && r.length > 0 && r.alreadyPromoted && r.alreadyPromoted.length) {
				LEDGER.push(`    ⭐ 另外 **${r.alreadyPromoted.length} 条已经升格过**：`
					+ `${r.alreadyPromoted.join(" / ")}`);
			}
		} catch { /* 同上 */ }
		// ③ 待重审（争议率超门槛）
		try {
			const hot = [];
			const ids = [...new Set([...RULES.map((x) => x.id), "G31", "G41"])];
			for (const id of ids) {
				const s = ruleStats(config.ledgerPath, id);
				if (!s) continue;
				const { rate, denom } = disputeRate(s);       // ⭐ 分母 = ref + warn（见那个函数）
				if (denom < th("dispute.minRefusals", DISPUTE_MIN_REFUSALS_FALLBACK)) continue;
				if (rate !== null && rate >= th("dispute.ratePercent", DISPUTE_RATE_TENTATIVE_FALLBACK)) {
					hot.push(`${id}（争议率 ${rate.toFixed(0)}% —— 拦过 ${s.ref} / 提示过 ${s.warn}）`);
				}
			}
			if (hot.length) LEDGER.push(`· **待重审 ${hot.length} 条**：${hot.join(" / ")} —— `
				+ `看那几次被拦的 cmd 记录再判（**争议是信号不是判决**）`);
		} catch { /* 同上 */ }
		// ④ 整树对账的结果（**读上次产物 + 标明"这是什么时候跑的"**）
		try {
			const rn = reconcileNotice(config);
			// ④b ⭐ ㉕ 两条捞回的结果（同一套纪律：读上次产物 + 标明几点跑的 + 没跑过≠0 条）
			const rc = recoverNotice(config);
			if (rc) LEDGER.push(rc);
			if (rn) LEDGER.push(rn);
		} catch { /* 同上 */ }
		// ④c ⭐ ㉝ **配置自检**（2026-09-27，用户批「需要」）——
		//     **它和上面那些不一样**：那些说「有事没做完」，**这个说「某功能没接好」** ——
		//     **所以文案必须说清「这是配置的问题，不是你的错」**，否则会话会以为是自己的问题。
		//    ⚠️ 节流：**它走 `takeNotice` 的「每会话一次」** ✅（**别变墙纸**）
		try {
			// 故障类：走自己的开关（reportBrokenConfig，默认开）——
			// 不归 sessionNotice（那是「欠账」的偏好开关，故障不该被偏好关掉）。
			// 老名 configSelfCheck 并进来：用户配过它就还该有效（别静默失效）。
			if (config.reportBrokenConfig !== false && config.configSelfCheck !== false) {
				const bad = configIssues(config);
				if (bad.length) {
					FAULT.push(`· **⚠️ 配置自检：有 ${bad.length} 处接不上**（**这是配置问题，不是你的错**）：\n`
						+ bad.map((b) => `    · ${b}`).join("\n")
						+ `\n    ⚠️ **而「接不上」和「没跑过」在注入里长得一样** —— 所以这里单独说一句。\n`
						+ `    ⚠️ **它只查「路径能不能用」**，不查「内容对不对 / 是不是旧的」`
						+ `（**那是另一件事 —— 混进来会造成「旧的也算新的」**）。`);
				}
			}
		} catch { /* 自检自己坏了 → 绝不影响注入 */ }

		// ㊱ **功能自证**（喂合成输入，看那些判据还活着吗）——
		//    ⚠️ **它只报"哪条不响了"，不自动改任何东西**（"顺手修"就是"修一个出一个"的源头）✅
		try {
			// 故障类：走自己的开关（reportDeadJudgements，默认开）—— 同上。
			if (config.reportDeadJudgements !== false && config.selfCheckOn !== false) {
				const sc = selfCheck(config, hooks);
				// ⭐⭐ **消费点**（Lead 认的"排第一"那件）——
				//    我上一轮定义了 `off`（第三种状态：此刻关着）而**没人读它** →
				//    **那比"只有两态"更坏：它造出一个「我们考虑了这种状态」的假象。**
				//    ⚠️ 而它正是这一件在治的病（**「以为它管」**）—— **而它长在治这个病的过程里。**
				if (sc.off && sc.off.length) {
					FAULT.push(`· **功能自证：有 ${sc.off.length} 条「此刻关着」**`
						+ `（**被配置关掉了，所以现在不会响 —— 那不等于它坏了**）：\n`
						+ sc.off.map((b) => `    · ${b}`).join("\n")
						+ `\n    ⚠️ **而"关着"和"坏了"是两件事** —— 这里分开说，`
						+ `是因为**"就绪"和"坏了"之间那个状态一直没被命名**`
						+ `（**"关着"、"没跑到"、"占位符"、"被挡住"都长在那里**）。`);
				}
				if (sc.bad.length) {
					FAULT.push(`· **⚠️ 功能自证：有 ${sc.bad.length} 条判据不响了**（喂了合成输入，它没反应）：\n`
						+ sc.bad.map((b) => `    · ${b}`).join("\n")
						+ `\n    ⚠️ **这条只报，不自动修**（"顺手修"就是"修一个出一个"的源头）。\n`
						+ `    ⚠️ 而它答的是「**它现在还活着吗**」—— 那个不用判，**喂了就该响**。`);
				}
			}
		} catch { /* 自证自己坏了 → 绝不影响注入 */ }
		// ⑤ ⭐ **该回来看的**（`revisit_when`）—— 2026-09-26 加，用户批的第三个改口径。
		//
		// **为什么要有这一条**：豁免/判定**不该靠"过期"**（时间到了一切照旧，什么都没变），
		//   该靠「**回来看的条件**」。而那个条件**有些机器能判、有些只能人看**：
		//     · `revisit_kind === "evidence"` → **条件是可判的**，**报出来让人（或我）去查**
		//     · `revisit_kind === "human"`    → **只能人看** —— **报了也没人能照做，所以不报**
		// ⚠️ **这正是"分成两类"的意义**：**不是所有提醒都该发出去** ——
		//   **发一条"你该复看 P03"而没人能判它，就是墙纸。**
		// ⚠️ 而它**接进的是已有的 `takeNotice`**（**没新造机制** —— 用户明确要求过）。
		try {
			if (config.pitfallList) {
				const gen2 = JSON.parse(readFileSync(config.pitfallList, "utf8"));
				const ev = (gen2.pitfalls || []).filter((p) => p.revisit_kind === "evidence");
				if (ev.length) {
					LEDGER.push(`· **该回来看的 ${ev.length} 条**（**它的复看条件是机器可判的**）：\n`
						+ ev.map((p) => `    · ${p.id}（${String(p.name || "").slice(0, 22)}）—— `
							+ `${String(p.revisit_when || "").slice(0, 150)}`).join("\n")
						+ `\n    ⚠️ **另有 ${(gen2.pitfalls || []).filter((p) => p.revisit_kind === "human").length} 条`
						+ `复看条件只能人看** —— **那些不报**（报了也没人能照做，那是墙纸）。`);
				}
			}
		} catch { /* 读不到就不说（不编） */ }
		// ⭐ **唯一的筛点**（Lead 批的「攒完再筛」）——
		//    ⚠️ 偏好开关**只筛欠账**；故障类不归它（**故障不该被偏好关掉**）。
		//    ★ 而"只有一个筛点"这件事是**结构上**的：**上面 12 处只管 push，不管该不该显示。**
		const lines = wantLedgerNotice ? [...LEDGER, ...FAULT] : [...FAULT];
		// ⭐⭐ **头部标签按实际内容给**（2026-09-27，Lead 判它优先）——
		//    ⚠️ **为什么它要紧**：**壳子上的名字，是读者判断「这是什么」的唯一线索** ——
		//      **壳子写错比不写更坏**（**它让人按错误的类别去理解**）。
		//      而修之前，一次「配置接不上」的注入，抬头写着「**待归类提醒**」—— **那是在误导。**
		//    ⚠️ **而它要能表达「混着两种」**：关偏好时只剩 FAULT；全开时两种都有。
		//      → **所以不是「一个标签」，而是「按实际内容给」**（**有故障就以故障为主标题**）。
		const _hasFault = FAULT.length > 0;
		const _hasLedger = wantLedgerNotice && LEDGER.length > 0;
		const _head = _hasFault && _hasLedger
			? "[护栏 · 故障 + 待归类] **有东西接不上 / 不响了**，另有欠账："
			: _hasFault
				? "[护栏 · 故障] **这不是欠账 —— 是有东西接不上 / 不响了**："
				: "[护栏 · 待归类提醒] **这件事没有自动做完，只能由会话来推**：";
		return lines.length ? _head + "\n" + lines.join("\n") : null;
	};
	ctx.on("tools/post-execute", async (exec, _result, next) => {
		const downstream = await next();
		const { warns } = evaluate(exec);
		const notice = takeNotice();
		// ⭐⭐ ㉘（2026-09-27）**「要不要记一笔」的入口，放在「我刚出事」的那一刻。**
		//
		//    **Lead 的判断（我认同）**：
		//      定期重扫 → 工具失败（**事后 24h 一次**）｜捞回 → "写了又改"+"我承认过的话"
		//      ⚠️ **缺口 = "它意识到了，但没报"** ← **这条补的就是它**
		//
		//    **⭐ 而两个根据是今晚自己定的那两条**：
		//      · **"够不着的建议，等于没给建议"** → **提示要在"我正好看着那条失败"的时候给**
		//      · **机器负责"喊"，人负责"决定"**（和"整理"那条链同一个分工）
		//
		//    ⚠️⚠️ **三条节流（照申辩入口的做法）**：
		//      ① **只在"工具真的失败了"时带**
		//      ② **同一会话只带一次**（`reportHintDone`）—— **同类失败连着来时不每次喊**
		//         （**注入现在 16 行，别让它膨胀**）
		//      ③ **已经被护栏喊过的不带**（`warns.length > 0` = **那已经记过了**）
		//
		//    ⚠️⚠️ **而它的判据重启后实测改过一次（2026-09-27）—— 第一版是错的，记在这里：**
		//      **第一版我认 `_result.isError === true`** → **Lead 实测它没响。**
		//      → **于是从真实日志里查出了真形状**（4821 个 `tool/result`，**顶层键只有 3 种**）：
		//        ```
		//        2432  ['message', 'step', 'turn']              ← 成功
		//        2249  ['message', 'meta', 'step', 'turn']      ← 成功（有 meta）
		//         140  ['error',   'message', 'step', 'turn']    ← **失败：顶层有 error**
		//        ```
		//      **而 `error` 里装的是**：`{name:"FsError", code:"FS_EDIT_NOT_FOUND" | "FS_NOT_OBSERVED" | "FS_STALE_VERSION"}`
		//      **→ 所以「失败」的标志是顶层 `error` 字段**，**`isError` 那个字段根本不存在。**
		//
		//    ⚠️⚠️ **而「命令返回非零」抓不到 —— 而我不假装能抓：**
		//      Lead 跑了一条 `exit code 1` 的命令，**而它的 result 和成功的形状一样**（`['message','step','turn']`）
		//      —— **因为「退出码」是命令输出文本的一部分，不是 result 的结构字段**
		//      （`meta` 里只有 `diffs/path/offset/lines/lang/operation` 这些「成功才有的东西」）。
		//      **→ 要抓它只能「读文本猜」**（例如找 `exit code 1`）—— **而那是会误报的**：
		//        一条 `echo` 打出这几个字就会误报 → **它会在成功时也响 → 那就是墙纸。**
		//      ★ **所以这里只覆盖「工具调用本身失败」（①）；「命令返回非零」（②）如实说抓不到。**
		//        **那不是漏** —— **② 有别的路**（定期重扫会从会话日志里捞失败信号）。
		const reportHint = (() => {
			if (reportHintDone) return null;
			// ⚠️⚠️ 2026-09-27 **改口径**（Lead 验出来的）：这里原来是
			//    `if (warns.length > 0 || notice) return null;` —— **而那个判据太宽了**
			//    **把「被 G21 提示过」当成了「这个失败已经记过」** —— **而那不是一回事。**
			//    ★ **而 G21 恰好管的就是 `FS_NOT_OBSERVED`**（「改文件前没读过」）→
			//      **所以「文件没读过」那类失败，永远会被它挡掉自报入口** ❌
			//    ★ 而 `edit` 那种（`FS_EDIT_NOT_FOUND`）**G21 对 `edit` 是无条件提示的** → **也被挡** ❌
			//    ★★ 而它为什么在 `write` 时响了？—— **因为 G21 对 `write` 只在「目标已存在」时提示**（我写的是新文件）→ `warns.length === 0` ✅
			//    **→ 修法：只排除「另一条路已经记过了」那种**（即 `notice`），
			//      **而 G21 那种提示不算**（它只是在说「你该先读」）。
			if (notice) return null;                              // 只排除真的重复那种
			// ① **只认「顶层有 error 字段」**（那是从 4821 个真实 result 里查出来的形状）
			if (!_result || typeof _result !== "object" || !_result.error) return null;
			reportHintDone = true;
			const ec = _result.error && _result.error.code
				? String(_result.error.code) : "（没有 code）";
			return "⚠️ **刚才那条失败了**（`" + ec + "`）—— 如果这是个「护栏看不见的坑」，"
				+ "**调 `guardrail_report` 记一笔**（带上你当时的判断）。\n"
				+ "  ⚠️ **而只有你知道的坑才该报** —— 日志里能看出来的，捞回会自己捞。\n"
				+ "  ⚠️ **每会话只提醒一次**（别让它变成墙纸）；而**已经被护栏喊过的不会带这句**（那已经记过了）。\n"
				// ⚠️⚠️ **而"它覆盖哪几种失败"必须说清**（2026-09-27，Lead 验出来的**第三层**）——
				//    三层里它只覆盖一层，**而「以为它管」比「它不管」更危险**：
				//      ① **工具执行后报错**（`FsError` 那种）→ ✅ **这条管**
				//      ② **命令返回非零**（`exit code 1`）→ ❌ 看不见（**在输出文本里**）→ 靠定期重扫
				//      ③ **工具被护栏拒** → ❌ **看不见** —— **因为它根本没执行、不产生 `tool/result`**
				//         → **而它被另一条路覆盖**：**护栏回执本身 + 台账的 `refused`** ✅
				+ "  ⚠️ **而它只覆盖三层失败里的一层**："
				+ "①工具执行后报错 ✅（这条）｜"
				+ "②命令返回非零 ❌（在输出文本里，**靠定期重扫**）｜"
				+ "③**工具被护栏拒** ❌（**它没执行** → 这条看不见，**而它靠「拒绝回执 + 台账」**）。";
		})();
		if (warns.length === 0 && !notice && !reportHint) return downstream;

		// ③ warn 也记台账 —— 否则"喊了几次"的分母本身就缺（以前只有拒绝进台账）
		// ⭐ ③ 三字段（2026-09-26 加）：
		//    `file`         —— **文件类规则的通用字段**（G21/G41/将来 lint 都要）
		//    `targetExists` —— write 时目标存不存在 → 用来剔掉「新建文件」那批误报
		//    `readBefore`   —— **本会话读过该文件没有** → **G21 升级判据的唯一输入**
		//    ⚠️ 拿不到的字段**不写**（`undefined` 会被 JSON.stringify 丢掉，**绝不编**）
		const _a = exec.arguments || {};
		ledger(config, { kind: "warned", tool: exec.name,
			rules: warns.map((r) => r.id).join(","),
			pitfalls: warns.map((r) => r.pitfall).join(","),
			...fileFacts(exec),
			readBefore: readBefore(exec, _a.file_path || _a.path),
			cmd: String((exec.arguments && exec.arguments.command) || "").slice(0, 200) }, exec);

		const note = warns
			.map((r) => `· [${r.id} / ${r.pitfall}] ${r.why} → ${r.fix}`)
			.join("\n");
		// ⭐ ⑨ 会话级提示与 warn 提示**共用同一条消息**（避免两条注入、避免"墙纸"）
		const body = [
			warns.length
				? `[护栏提示] 刚才这条命令没被拦（不是"几乎必然失败"），但踩到了已知的坑：\n${note}`
				: "",
			// ⚠️ **标签已由 `takeNotice` 自带**（2026-09-27，Lead 判它优先）——
			//    它能表达三种：**故障 / 故障+待归类 / 待归类**。
			//    ★ 「壳子写错比不写更坏」那条判据就落在这里。
			//    ⚠️ **而这一段原来在文件里出现了两次**（L1499 / L1510，相邻）——
			//      那是我早先一次编辑留下的**重复块**。→ **两处都改成同一句**（都不该再加标签）。
			notice ? notice : "",
			// ⚠️⚠️ **头部标签该跟内容走 —— 而这一条我试过、又撤回了**（2026-09-27）：
			//    原因是**作用域**：`LEDGER` / `FAULT` 是 `takeNotice` 的**局部变量**，
			//    而这段 body 是在 `post-execute` 里拼的 → **引用不到** →
			//    `node --check` 说"语法通过"，而**真跑一次是 `ReferenceError: LEDGER is not defined`**。
			//    ★ **而那已经是同一个形状的第 8 次**（前七次：截断 / `guardFn` / TDZ / `off` 没人读 /
			//      `wantLedgerNotice` 没用上 / "改 1 处"没数 / `faultOnly` 没定义）。
			//    ⚠️ **而这一次的教益是**：**"我想加的东西"和"我能在哪儿加"是两件事** ——
			//      **而判断后者要先看作用域**（那正是那三句里的第 ① 句"它依赖什么"）。
			//    → **所以先不做它**（**"壳子写错"是个真问题，但它要动的是 `takeNotice` 的返回形状**，
			//      而那是另一件该单独做的事 —— **不在表上的不做**）。
			// ⚠️ **标签已由 `takeNotice` 自带**（2026-09-27，Lead 判它优先）——
			//    它能表达三种：**故障 / 故障+待归类 / 待归类**。
			//    ★ 「壳子写错比不写更坏」那条判据就落在这里。
			//    ⚠️ **而这一段原来在文件里出现了两次**（L1499 / L1510，相邻）——
			//      那是我早先一次编辑留下的**重复块**。→ **两处都改成同一句**（都不该再加标签）。
			notice ? notice : "",
			// ⭐ ㉘ 「要不要记一笔」那提示（**每会话只带一次**、且**已被喊过的不带**）
			reportHint ? `[护栏 · 自报入口] ${reportHint}` : "",
		].filter(Boolean).join("\n\n");
		const msg = {
			id: randomUUID(),
			// ⚠️ 必须照 dsh-plan-anchor 的完整形状写：source 不能只有 kind。
			//    少了 form / summary 会让宿主读 source 时抛异常，
			//    而这条消息会被写进会话日志 → 日志被判损坏 → 历史打不开。
			//    （2026-09-26 实际事故：2 份会话日志、3 条异常提醒。）
			source: {
				kind: "plugin:dsh-guardrail",
				form: "notice",
				summary: warns.length
					? `护栏提示：${warns.length} 条`
					: (reportHint ? "护栏 · 自报入口" : "护栏 · 待归类提醒"),
			},
			role: "user",
			content: [{ type: "text", text: body }],
		};
		// ⚠️ 关键：把 downstream 原样铺开，只**前置**追加自己的 context。
		//    绝不替换 —— 否则会盖掉计划锚的注入（我实证过 cordis 不会自动帮你保留）。
		return {
			...downstream,
			additionalContexts: [msg, ...((downstream && downstream.additionalContexts) || [])],
		};
	});

	// ───────── ③ 坑清单查询工具（关键词，不通读） ─────────
	// 形状照 dsh-file-guard 的可用写法：
	//   · parameters 是**扁平 DSL**（属性名→spec）；output.schema 是**纯 JSON Schema**
	//   · output.render 返回内容块
	//   · execute 必须返回 output.schema 描述的那个对象（additionalProperties:false → 只能 {result}）
	ctx.tools.register(defineTool({
		name: "guardrail_lookup",
		description: "按关键词查坑清单（护栏自带）。用于'这件事我是不是踩过'。传关键词即可，不需要通读清单。",
		parameters: {
			q: { type: "string", required: true, description: "关键词，如 '中文'、'超时'、'P02'、'edit'" },
			limit: { type: "number", description: "返回条数，默认 5" },
		},
		output: {
			schema: {
				type: "object",
				additionalProperties: false,
				properties: { result: { type: "string" } },
			},
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute(args) {
			const q = (args && args.q) || "";
			const limit = Number((args && args.limit) || 5);
			const data = loadPitfalls(config.pitfallList);
			const hits = searchPitfalls(data, q, limit);
			const payload = hits.length === 0
				? { hits: 0, note: `没查到与 "${q}" 相关的坑。换个关键词，或直接看 pitfall-list.json。` }
				: {
					hits: hits.length,
					items: hits.map((it) => ({
						id: it.id, name: it.name,
						次数: (it.counts && it.counts.solid) || 0,
						验证状态: it.status, 可否事前拦: it.can_precheck,
						触发条件: it.trigger, 症状: it.symptom, 解法: it.solution,
					})),
				};
			return { result: JSON.stringify(payload, null, 1) };
		},
	}));

	// ───────── ④ guardrail_report：AI 自报的坑 → 待补区 ─────────
	// 为什么需要它：**我是唯一知道自己刚踩坑的人**。护栏不知道、日志不一定有
	// （P20–P27 那 8 条插件类坑就全都不在日志里）。缺了这条，"发现→记录"永远是人工的。
	// 安全设计：它**只写待补区**，**绝不直接变成拦截规则** —— 新坑不该自动获得拦截权。
	ctx.tools.register(defineTool({
		name: "guardrail_report",
		description: "把刚踩到的坑报进护栏的待补区（护栏自带）。"
			+ "**只有你知道的坑用它** —— 日志里看不出来的那些。它会进 pitfall-list 的待补区，但不会自动变成拦截规则。",
		parameters: {
			what: { type: "string", required: true, description: "这个坑是什么（一句话）" },
			symptom: { type: "string", required: true, description: "症状：报错原文 / 乱码样子 / 卡住的样子" },
			evidence: { type: "string", required: true, description: "可复核的线索：文件路径 / 行号 / 命令 / 会话 id" },
			trigger: { type: "string", description: "什么情况下会发生（可选）" },
			// ⭐ 2026-09-26 加（Lead）：
			//   「**P34 说「选检查手段时先问它错了会不会被发现」—— 但「是哪个手段发现的」
			//     根本没有记录。**」→ 加这一格，P34 才**有数据**，而不是靠我记。
			// ⚠️ **它自动不了** —— 「谁发现的」是语义，脚本推不出来。
			//     **能做的只是「记的时候顺手填一格」。** 这一格的价值就在这儿，别指望更多。
			found_by: {
				type: "string",
				description: "**是谁/什么发现的这个坑** —— 手填，取值建议："
					+ "`syntax_check`（语法/解析自检）/ `test`（自测）/ `harness`（挂具）/ "
					+ "`crash`（跑起来崩了）/ `self_review`（自己复核）/ `lead`（Lead 或用户指出）/ "
					+ "`user`（用户看到）/ `other`。"
					+ "⚠️ **它自动不了**（「谁发现的」是语义），只是记的时候顺手填一格 —— "
					+ "但没有它，P34 那条判据就永远只能靠「我记得语法自检抓了 16 次」。",
			},
		},
		output: {
			schema: {
				type: "object",
				additionalProperties: false,
				properties: { result: { type: "string" } },
			},
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute(args) {
			if (!config.reportsPath) {
				return { result: JSON.stringify({ ok: false, reason: "未配置 reportsPath" }) };
			}
			const rec = {
				t: Date.now(),
				v: VERSION,
				boot: BOOT,
				// session 的取法：工具的 execute(args) 自己**拿不到 agent 上下文**，
				// 所以改成用 guard 在"每一次工具调用"时捕获的那个值 ——
				// **guardrail_report 本身也是一次工具调用，guard 会先于它执行**，
				// 所以这里拿到的正是它自己那个会话。
				// 万一还没捕获到（理论上不会）：**不写这个字段，绝不编占位符**。
				source: "AI自报",
				what: String(args.what || ""),
				symptom: String(args.symptom || ""),
				evidence: String(args.evidence || ""),
				trigger: String(args.trigger || ""),
			};
			// ⭐ `found_by`（谁发现的）—— **只在填了的时候写**（拿不到就不写，绝不编）
			//    ⚠️ 而**没填**这件事本身也要留痕：`found_by` 缺席 = 「报的时候没记」——
			//    那是真信息（P34 的数就只能算"已知那部分"）。
			if (args.found_by && String(args.found_by).trim()) {
				rec.found_by = String(args.found_by).trim();
			}
			if (lastSessionId) rec.session = lastSessionId;   // 拿不到就不写（绝不编）
			try {
				mkdirSync(dirname(config.reportsPath), { recursive: true });
				appendFileSync(config.reportsPath, JSON.stringify(rec) + "\n");
			} catch (e) {
				return { result: JSON.stringify({ ok: false, reason: String(e && e.message || e) }) };
			}
			return { result: JSON.stringify({
				ok: true, wrote: config.reportsPath,
				note: "已进待补区。它不会自动变成拦截规则 —— 新坑要先被归类、评估误报代价，才谈得上拦。",
			}) };
		},
	}));

	// ───────── ⑦ 解析闸的**独立计数**（隔离④）─────────
	// 回答"**这条规则到今天拦过几次**" —— prior art 的判据：
	//   "a rule that never fires is cost without benefit."
	// 计数**只读它自己的台账 kind**（parse_blocked / parse_cap_reached / parse_gate_error），
	// **和命令类规则完全分开** —— 所以"这条规则值不值得留"能单独判。
	ctx.tools.register(defineTool({
		name: "guardrail_parse_stats",
		description: "解析闸（护栏第 5 条规则）到今天拦过几次。只读它自己的台账 —— "
			+ "用于单独回答『这条规则触发过没有』（prior art：never-fires 是 cost without benefit）。",
		parameters: {
			limit: { type: "number", description: "最近几条明细，默认 5" },
		},
		output: {
			schema: { type: "object", additionalProperties: false, properties: { result: { type: "string" } } },
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute(args) {
			const limit = Number((args && args.limit) || 5);
			let rows = [];
			try {
				rows = readFileSync(config.ledgerPath, "utf8").split("\n").filter(Boolean)
					.map((l) => { try { return JSON.parse(l); } catch { return null; } })
					.filter(Boolean);
			} catch { rows = []; }
			const blocked = rows.filter((r) => r.kind === "parse_blocked");
			const caps = rows.filter((r) => r.kind === "parse_cap_reached");
			const errs = rows.filter((r) => r.kind === "parse_gate_error");
			const byReason = {};
			for (const b of blocked) byReason[b.reason || "?"] = (byReason[b.reason || "?"] || 0) + 1;
			return { result: JSON.stringify({
				开关: config.parseCheck ? "开" : "**关**（单独开关，隔离③）",
				拦下次数: blocked.length,
				熔断放行: caps.length,
				规则自身出错: errs.length,
				按错误类型: byReason,
				缓存: parseGateStats(),
				最近几条: blocked.slice(-limit).map((b) =>
					`[${b.reason}] ${b.file}${b.line ? " 第" + b.line + "行" : ""} — ${String(b.msg || "").slice(0, 80)}`),
				note: blocked.length === 0
					? "**从没触发过** —— 按 prior art 的判据，never-fires 是 cost without benefit，要重新评估它值不值得留。"
					: "有触发。次数是从零开始长的 —— 这条规则自己的计数。",
			}, null, 1) };
		},
	}));

	// ───────── ⑧ 规则数据化的**状态**（免重启要可观测才有意义）─────────
	// 回答两个问题：**现在生效的是数据还是代码默认？** 以及 **数据有没有被读进去？**
	// 没有这个工具，"改数据免重启"就没法验 —— 你只能靠"行为变了没有"反推。
	ctx.tools.register(defineTool({
		name: "guardrail_rules_status",
		description: "护栏现在生效的规则来自哪里（数据文件 vs 代码默认），以及一共几条、各是什么。"
			+ "用于验证『改数据免重启』有没有真的生效 —— 不用靠行为反推。",
		parameters: {},
		output: {
			schema: { type: "object", additionalProperties: false, properties: { result: { type: "string" } } },
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute() {
			const st = loaderStats();
			let rules = [];
			try { rules = activeRules(); } catch { rules = []; }
			return { result: JSON.stringify({
				生效来源: st.usingData ? "**数据文件**（免重启生效）" : "**代码默认**（数据不可用或未配）",
				数据文件: st.rulesPath || "(未配)",
				回落到代码的原因: st.fallbackReason || null,
				读盘次数: st.reads,
				缓存命中次数: st.hits,
				最近一次成功读入: st.lastOk,
				当前生效规则: rules.map((r) => `${r.id}/${r.pitfall}/${r.level}`),
				规则条数: rules.length,
				note: "**改数据文件 → 下次 evaluate 自动看到最新**（按 mtime+size 判断）。"
					+ " 数据坏了会**回落到代码默认**，不是全放行。",
			}, null, 1) };
		},
	}));

	// ═══════════════════════════════════════════════════════════════
	// ⭐ ② 让它「服气」的第二样：**申辩出口**
	// ═══════════════════════════════════════════════════════════════
	// 为什么必须有：**护栏现在是单向的** —— 它拦我，**我除了跟用户说没有别的地方可去**。
	//   而**误报是必然的**（Rice 定理：非平凡性质不可能无误报）→ **所以必须有申辩通道。**
	//
	// ⚠️⚠️ 但**必须防一个反模式**：**「争议」不等于「规则错」** —— 我可能只是不服气。
	//   → **所以争议是「信号」，不是「判决」**：
	//     · 它**不会自动改任何规则**（不会自动 block→warn）
	//     · 它只做两件事：**记进台账**（留痕）+ **让这条规则的画像显示争议率**
	//     · **降不降级要拿被拦那一次的记录来看**（证据说话）—— 而那是**人/审查会话**的活
	ctx.tools.register(defineTool({
		name: "guardrail_dispute",
		description: "对一条护栏规则提申辩（我认为它这次拦错了）。"
			+ "会记进台账并计入这条规则的争议率 —— 但**不会自动改规则**："
			+ "争议是信号不是判决，降级要拿被拦那次的记录来看。"
			+ "规则画像可用 guardrail_rule_profile 查。",
		parameters: {
			rule: { type: "string", description: "规则 id（如 G01 / G21 / G41）" },
			why: { type: "string", description: "为什么我认为它这次错了（**要具体到那次调用**，别只写「不服」）" },
		},
		output: {
			schema: { type: "object", additionalProperties: false, properties: { result: { type: "string" } } },
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute(args) {
			const rule = String((args && args.rule) || "").trim();
			const why = String((args && args.why) || "").trim();
			if (!rule) return { result: "缺 rule —— 要指明申辩的是哪条规则" };
			if (!why) return { result: "缺 why —— **申辩必须给理由**（只说「不服」不算申辩）" };
			// ⚠️ 只认**真实存在的规则 id** —— 防止把申辩记到不存在的规则上（那会让画像出错）
			const known = new Set([...RULES.map((r) => r.id), "G31", "G41"]);
			const warned = known.has(rule) ? "" : `\n⚠️ \`${rule}\` 不在已知规则里（${[...known].sort().join("/")}）—— 仍然记下了。`;
			// ⚠️ 2026-09-26 修（Lead 验收时点出的缺口）：
			//    原来这里传的是 `{}` → `sessionIdOf({})` 返回 null → **`disputed` 那行没有 `session`**，
			//    于是「**谁在申辩**」永远说不清 —— 而申辩恰恰是**最需要追责到人**的一类记录。
			//    **根因**：工具签名是 `execute(args)`，**拿不到 exec**。
			//    **修法**：用 guard 捕获的 `lastSessionId`（guard 对每次工具调用都跑，
			//    所以 `guardrail_dispute` 自己那次也会把它刷成"它自己那个会话"）。
			const disExec = lastSessionId
				? { agent: { session: { header: { id: lastSessionId } } } }
				: {};
			ledger(config, { kind: "disputed", rule, why: why.slice(0, 500) }, disExec);
			const st = ruleStats(config.ledgerPath, rule) || { ref: 0, warn: 0, dispute: 0 };
			const { rate } = disputeRate(st);       // ⭐ 分母 = ref + warn
			return { result: JSON.stringify({
				已记录: `申辩已进台账（kind=disputed）`,
				规则: rule,
				理由: why.slice(0, 200),
				这条规则的画像: {
					拦过: st.ref, 提示过: st.warn, 被申辩过: st.dispute,
					争议率: rate === null ? "**算不出来**（没拦过 → 分母为 0）" : `${rate.toFixed(0)}%`,
				},
				note: "⚠️ **申辩不等于规则错** —— 争议是**信号**不是判决。"
					+ " 它**不会自动改规则**；降不降级要**拿被拦那次的记录来看**（证据说话）。",
				门槛提示: st.ref >= th("dispute.minRefusals", DISPUTE_MIN_REFUSALS_FALLBACK)
					&& rate !== null
					&& rate >= th("dispute.ratePercent", DISPUTE_RATE_TENTATIVE_FALLBACK)
					? `**拦过 ${th("dispute.minRefusals", DISPUTE_MIN_REFUSALS_FALLBACK)}+ 次（幂律的「3–10 调查档」）且争议率 ≥`
					  + `${th("dispute.ratePercent", DISPUTE_RATE_TENTATIVE_FALLBACK)}%（⚠️ **这个 40% 是暂定的、没有依据**）`
					  + `→ 值得人工重审这条规则**（看那几次拒绝的 cmd 到底是什么）`
					: `暂时没到重审的门槛（拦过 ≥${th("dispute.minRefusals", DISPUTE_MIN_REFUSALS_FALLBACK)} 次 且 争议率 ≥`
					  + `${th("dispute.ratePercent", DISPUTE_RATE_TENTATIVE_FALLBACK)}%）。`
					  + `⚠️ 后一个数是**暂定**的（没有真实申辩数据可依）。`,
			}, null, 1) };
		},
	}));

	// ⭐ 规则画像：一眼看这条规则「拦过几次 / 争议率多少 / 值不值得重审」
	ctx.tools.register(defineTool({
		name: "guardrail_rule_profile",
		description: "看每条规则的画像：拦过几次、提示过几次、被申辩过几次、争议率。"
			+ "用来回答「这条规则该不该重审/降级」—— 但**画像只是信号，判决要看那几次被拦的记录**。",
		parameters: {},
		output: {
			schema: { type: "object", additionalProperties: false, properties: { result: { type: "string" } } },
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute() {
			const ids = [...new Set([...RULES.map((r) => r.id), "G31", "G41"])].sort();
			const rows = ids.map((id) => {
				const s = ruleStats(config.ledgerPath, id) || { ref: 0, warn: 0, dispute: 0 };
				const { rate, denom } = disputeRate(s);      // ⭐ 分母 = ref + warn
				return { 规则: id, 拦过: s.ref, 提示过: s.warn, 被申辩: s.dispute,
					争议率: rate === null ? "—" : `${rate.toFixed(0)}%`,
					// ⚠️ 两个数**必须有**（否则"争议率高"是拦得错还是提示得烦，分不出来）
					分母: denom,
					需重审: denom >= th("dispute.minRefusals", DISPUTE_MIN_REFUSALS_FALLBACK)
						&& rate !== null
						&& rate >= th("dispute.ratePercent", DISPUTE_RATE_TENTATIVE_FALLBACK)
						? "**是**" : "" };
			});
			return { result: JSON.stringify({
				画像: rows,
				note: "⚠️ **争议率是信号不是判决** —— 我可能只是不服气。"
					// ⚠️⚠️ 2026-09-26 修（**同一个 bug 的第三个实例**）：
					//    这句原来写「拦过 ≥5 次」，而门槛的口径**已经改成「响过几次」（ref+warn）** ——
					//    **文案没跟上口径变化。** 又一次「写死的行为描述」。
					+ ` 「需重审」的判据是**响过 ≥${th("dispute.minRefusals", DISPUTE_MIN_REFUSALS_FALLBACK)} 次`
					+ `（拦过 + 提示，见每行的「分母」）且 争议率 ≥`
					+ `${th("dispute.ratePercent", DISPUTE_RATE_TENTATIVE_FALLBACK)}%** ——`
					+ ` 前一个数**有依据**（落在幂律的「3–10 调查档」，见 rules-lifecycle.md）；`
					+ ` **后一个数是暂定的、没有依据** —— 目前申辩样本还不足以定这个率，`
					+ `所以它只是个「看起来像异常」的直觉，**不是从数据算出来的**。`
					+ "**触发的是「重审」不是「自动降级」**：要拿那几次被拦的 cmd 记录来看。",
			}, null, 1) };
		},
	}));

	// ⭐ ㊱ **功能自证（按需调）** —— 一个工具：**喂合成输入，看那些判据还活着吗**
	//    ⚠️ **为什么它不只是"锦上添花"**（Lead 改判）：
	//      **"启动时跑一次"和"我随时能调它"是两件事** ——
	//      后者让"跑一次自证"变成**可以随时做的动作**，而不是"等下次重启"。
	//    ★ **那就是那条判据**：**别靠"启动那一次"，要能主动查。**
	//
	//    ⚠️ **为什么加在"工具注册区"这个位置**（写下来，别让下一个人猜）：
	//      · **它必须在插件装载函数体内** —— 只有那里 `ctx` / `config` / `hooks` 才在作用域里
	//        （`selfCheck` 是模块级函数，可见；`hooks` 是上面那个 `const hooks = {...}`）。
	//      · ⚠️ **别挪到模块顶层**（例如 `const th = (n, fb) => {...}` 那个 `};` 后面）：
	//        那里 `ctx` **不存在**，而 **`node --check` 照样过** —— **语法闸看不见作用域**。
	ctx.tools.register(defineTool({
		name: "guardrail_selfcheck",
		description: "喂**合成输入**给那些「应该会响」的判据，看它们还活着吗。三栏："
			+ "✅ 就绪（喂了钩子、它响了）/ ⚠️ 此刻关着（**被开关关掉了，不等于坏了**）/ "
			+ "❌ 坏了（**喂了钩子而它没响 —— 那才要报**）。",
		parameters: {},
		output: {
			schema: { type: "object", additionalProperties: false,
				properties: { result: { type: "string" } } },
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute() {
			// ⚠️⚠️ **"它不写盘"不能靠声称** —— 上一版这里印的是「喂的全是内存里的合成输入」，
			//    而 **实测那句是假的**（2026-09-27）：自证里那两条走的是**真解析闸** →
			//    它会 `ledger(config, {kind:"parse_blocked", rule:"G41", ...})` → **真 append 到台账**。
			//    ★ 所以这里**量一遍再报**：**声称会随行为变化变成假话，量不会。**
			const lp = config.ledgerPath;
			// ⚠️ **`ENOENT` 不是"量不到"**（2026-09-27，第一版就在这儿错了）：
			//    `statSync` 对**还不存在的文件**抛 `ENOENT` —— 而我把那个当成了"读不到"
			//    → **首次调用（台账还没建）会印「量不到」，而它其实明明写了 2 条。**
			//    ★ **"不存在" = 0 字节（量得出来）；只有真读不了才是"量不到"** ——
			//      **和「0 处 ≠ 没数」是同一条判据的两个方向。**
			const sizeOf = () => {
				try { return statSync(lp).size; }
				catch (e) { return (e && e.code === "ENOENT") ? 0 : null; }
			};
			const before = lp ? sizeOf() : null;
			const sc = selfCheck(config, hooks);
			const after = lp ? sizeOf() : null;

			const L = [];
			L.push("【功能自证】喂了合成输入，看那些判据还活着吗");
			L.push("");
			L.push("✅ 就绪 —— 喂了钩子、它响了：" + sc.ok.length + " 条");
			for (const x of sc.ok) L.push("      · " + x);
			L.push("");
			L.push("⚠️ 此刻关着 —— **被开关关掉了，所以现在不会响（那不等于它坏了）**：" + sc.off.length + " 条");
			for (const x of sc.off) L.push("      · " + x);
			L.push("");
			L.push("❌ 坏了 —— **喂了钩子，而它没响（那才要报）**：" + sc.bad.length + " 条");
			for (const x of sc.bad) L.push("      · " + x);
			L.push("");
			L.push("⚠️ **它只报，不自动修**（「顺手修」就是「修一个出一个」的源头）。");
			L.push("⚠️ 它喂的是**合成输入**（内存里的命令串 / 文件内容 / 配置）—— **不碰你的文件**；"
				+ "而它走的是**真钩子** → **它到底有没有往台账写，看下面这个数**（**量出来的，不是我说的**）："
				+ (before === null ? "（台账路径没配，或台账**真读不了**（不是「不存在」）→ 这次量不到，所以不说写没写）"
					: after === null ? "（改完读不到台账了 → **量不到**）"
						: after > before
							? `**本次往台账 +${after - before} 字节**（那是**合成记录**，不是你真的被拦）`
							: "**本次 +0 字节**（没写）"));
			return { result: L.join("\n") };
		},
	}));

	// ⭐ ⑪ 阈值体检 —— **一眼筛出「欠依据」的那些**
	// 来由（用户 2026-09-26 问「我们那个阈值它是放在哪里了？」）：
	//   **散在三处**（文档 / 代码常量 / 测量结论）→ 收进 `thresholds.json`。
	//   而**「`source: null` 的那些就是欠依据清单」** —— 这个工具就是给那份清单用的。
	ctx.tools.register(defineTool({
		name: "guardrail_thresholds",
		description: "看全部阈值的值与它们的**依据出处**，并筛出「欠依据」（source=null）的那些。"
			+ "用来回答「这个数是从哪来的 / 哪些数是拍的」—— "
			+ "**一个没有依据的阈值，和一个没有依据的规则一样，都是「只有成本」。**",
		parameters: {},
		output: {
			schema: { type: "object", additionalProperties: false, properties: { result: { type: "string" } } },
			render: (_a, v) => [{ type: "text", text: v.result }],
		},
		async execute() {
			const rows = allThresholds();
			const noBasis = rows.filter((r) => r.待补依据);
			const st = thresholdStats();
			return { result: JSON.stringify({
				生效来源: st.usingData ? "**数据文件**（免重启生效）" : "**代码默认**（数据不可用或未配）",
				数据文件: st.path || "(未配)",
				回落原因: st.fallbackReason || null,
				读盘次数: st.reads,
				缓存命中: st.hits,
				阈值: rows,
				欠依据清单: noBasis.length
					? noBasis.map((r) => `${r.名称} = ${r.值}（${r.依据}）`)
					: "（没有 —— 全部都有出处）",
				note: "⚠️ **阈值和规则一样是数据**：改 `thresholds.json` → **下一次读就生效，不用重启**。"
					+ " 读不到/格式坏/schema 不认/条目非法 → **回落到代码默认值**"
					+ "（**不是「没有阈值」**，也不是报错 —— fail open 的方向是「仍有设防」）。",
			}, null, 1) };
		},

	}));
}
