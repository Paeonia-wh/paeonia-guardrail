// 规则表加载器 —— 让"升格一条规则"免重启。
//
// ═══ 实测依据（measure_rules_data.mjs，2026-09-26）═══
//   ① **能读到最新** ✅ —— `readFileSync` **不走模块缓存**；但**不能用 `import`**（那会被缓存）。
//   ② 4KB 规则表的三种读法（中位）：
//        A 直读        397 µs
//        B mtime+size  19 µs   ← **选它**
//        C 纯内存      0.1 µs
//      对照：现有 `evaluate()` 是 0.4 µs。19 µs = 0.019 ms，相对一次工具调用（毫秒~秒级）可忽略。
//
// ═══ 设计上的两条硬要求 ═══
//   · **形状必须和代码里的 RULES 完全一致** —— 这样 `evaluate()` 一行都不用改，行为天然等价
//   · **fail open 到"有设防"，不是"全放行"** —— 数据读不到/格式坏/schema 不认/规则非法
//     → **回落到代码默认 RULES**。（"因为它自己的 bug 就不设防"和"阻止所有编辑"一样糟。）
import { readFileSync, statSync } from "node:fs";

export const SUPPORTED_SCHEMA = 1;

let CFG = { path: "", fallback: null, shellTools: new Set() };
let cache = null;          // { mtimeMs, size, rules }
let stats = { reads: 0, hits: 0, fallbackReason: null, lastOk: null };

// ⭐ 「判据来自权威工具」的规则 id —— **它们不参与熔断**（见 rules-data.json 里的 authoritativeNote）。
// ⚠️ **代码默认的方向**：**数据读不到时，仍然认为 G41/G31 是权威的**（**不熔断**）——
//    因为两个方向的坏处不对称：
//      · 多熔断一次 → **让一个确实写坏了的文件落盘**（不可逆）
//      · 少熔断一次 → 我多被拒几次（**可逆，而且本来就该改**）
//    **→ 默认选"不熔断"。**
// ⚠️ 2026-09-27 加 G42（**丢 BOM**）—— 它是机械判据（看目标文件头 3 字节），
//    和 G41/G31 同类 → **必须也在这份代码默认名单里**。
//    ⭐ 而这一条是**真配置**逼出来的：真 profile 配置**不读 rules-data.json** →
//      `authoritative` 用的是这份默认名单 → **G42 不在里面就会连拦 5 次后熔断放行**
//      （`rules-data.json` 里我加过 G42，而那份文件在生产里根本没被读）。
const AUTHORITATIVE_DEFAULT = ["G41", "G42", "G31"];
let authoritative = new Set(AUTHORITATIVE_DEFAULT);

export function configure({ path, fallback, shellTools }) {
	if (path !== undefined) { CFG.path = path; cache = null; }
	if (fallback !== undefined) CFG.fallback = fallback;
	if (shellTools !== undefined) CFG.shellTools = shellTools;
}

export function loaderStats() {
	return { ...stats, usingData: cache !== null && cache.rules !== null,
		rulesPath: CFG.path, cachedSize: cache ? cache.size : null };
}

// ───────── 断言式读取（mtime+size 变了才读） ─────────
function readIfChanged() {
	if (!CFG.path) { stats.fallbackReason = "没配规则数据文件路径"; return null; }
	let st;
	try { st = statSync(CFG.path); } catch (e) {
		stats.fallbackReason = `statSync 失败：${e.code || e.message}`;
		return null;
	}
	if (cache && cache.mtimeMs === st.mtimeMs && cache.size === st.size) {
		stats.hits++;
		return cache;                                   // 没变 → 用缓存
	}
	let text;
	try { text = readFileSync(CFG.path, "utf8"); } catch (e) {
		stats.fallbackReason = `readFileSync 失败：${e.code || e.message}`;
		return null;
	}
	stats.reads++;
	let data;
	try { data = JSON.parse(text); } catch (e) {
		stats.fallbackReason = `JSON 解析失败：${e.message}`;
		return null;
	}
	const rules = compile(data);
	if (rules === null) return null;                    // fallbackReason 已由 compile 设好
	cache = { mtimeMs: st.mtimeMs, size: st.size, rules };
	stats.lastOk = new Date().toISOString();
	return cache;
}

// ───────── 把数据编译成**和 RULES 完全一样的形状** ─────────
function compile(data) {
	if (!data || typeof data !== "object") { stats.fallbackReason = "数据不是对象"; return null; }
	if (data.schema !== SUPPORTED_SCHEMA) {
		stats.fallbackReason = `schema 不认：${JSON.stringify(data.schema)}（只认 ${SUPPORTED_SCHEMA}）`;
		return null;
	}
	if (!Array.isArray(data.rules) || data.rules.length === 0) {
		stats.fallbackReason = "rules 不是非空数组";
		return null;
	}
	// ⭐ 顺手读「权威规则」名单（**它是这份数据的元信息，不是一条规则**）。
	//    ⚠️ 读不到/不是数组 → **保留上一次的值**（不因为一个可选字段缺失就整份回落）。
	if (Array.isArray(data.authoritativeRules)) {
		authoritative = new Set(data.authoritativeRules.map(String));
	}
	const out = [];
	for (const [i, r] of data.rules.entries()) {
		try {
			const c = compileOne(r, i);
			if (c === null) return null;                // 任一条非法 → 整份回落
			out.push(c);
		} catch (e) {
			stats.fallbackReason = `第 ${i} 条编译失败：${e.message}`;
			return null;
		}
	}
	let ids = new Set();
	let sawMeta = false;
	for (const r of out) {
		if (ids.has(r.id)) { stats.fallbackReason = `规则 id 重复：${r.id}`; return null; }
		ids.add(r.id);
	}
	return out;
}

function compileOne(r, i) {
	if (!r || typeof r !== "object") { stats.fallbackReason = `第 ${i} 条不是对象`; return null; }
	const { id, pitfall, level, why, fix, tools, when } = r;
	if (typeof id !== "string" || !/^G\d+$/.test(id)) { stats.fallbackReason = `第 ${i} 条 id 非法`; return null; }
	if (typeof pitfall !== "string") { stats.fallbackReason = `${id} 缺 pitfall`; return null; }
	if (level !== "block" && level !== "warn") { stats.fallbackReason = `${id} 的 level 非法`; return null; }
	if (typeof why !== "string" || typeof fix !== "string") { stats.fallbackReason = `${id} 缺 why/fix`; return null; }

	const toolList = Array.isArray(tools) ? tools : null;
	const isFileRule = toolList !== null && toolList.some((t) => !CFG.shellTools.has(t));

	if (isFileRule) {
		// 文件类（G21 那种）：和现有一模一样 —— {tools:Set, fileRule:true, test(exec)}
		return {
			id, pitfall, level, why, fix,
			tools: new Set(toolList),
			fileRule: true,
			test: (exec) => evalPred(when, exec, ""),
		};
	}
	// 命令类：**和现有 RULES 一样不带 tools** —— 由 evaluate 里的 SHELL_TOOLS 统一把关，
	// 这样行为**天然等价**（不动 evaluate 一行）。
	// ⚠️ 但如果数据里写了 SHELL_TOOLS 之外的 tool，命令类规则没法表达它 → **整份回落**，别静默吞掉。
	if (toolList && toolList.some((t) => !CFG.shellTools.has(t))) {
		stats.fallbackReason = `${id}：命令类规则的 tools 超出了 SHELL_TOOLS，数据表达不了 → 回落`;
		return null;
	}
	const re = whenToRegex(when);
	if (re === null) { stats.fallbackReason = `${id}：when 无法编译成命令判据`; return null; }
	return {
		id, pitfall, level, why, fix,
		test: (cmd) => re(cmd),
	};
}

/** 命令类 when → 一个 (cmd)=>bool 的函数。只支持 commandContains / commandRegex / allOf / anyOf。 */
function whenToRegex(when) {
	if (!when || typeof when !== "object") return null;
	if (typeof when.commandContains === "string") {
		const s = when.commandContains;
		return (cmd) => cmd.includes(s);
	}
	if (typeof when.commandRegex === "string") {
		let rx;
		try { rx = new RegExp(when.commandRegex, when.flags || ""); } catch { return null; }
		return (cmd) => rx.test(cmd);
	}
	if (Array.isArray(when.allOf)) {
		const parts = when.allOf.map(whenToRegex);
		if (parts.some((p) => p === null)) return null;
		return (cmd) => parts.every((p) => { try { return p(cmd); } catch { return false; } });
	}
	if (Array.isArray(when.anyOf)) {
		const parts = when.anyOf.map(whenToRegex);
		if (parts.some((p) => p === null)) return null;
		return (cmd) => parts.some((p) => { try { return p(cmd); } catch { return false; } });
	}
	return null;
}

/** 带 exec 上下文的判据（文件类用）。 */
function evalPred(when, exec, cmd) {
	if (!when || typeof when !== "object") return false;
	try {
		if (Array.isArray(when.allOf)) return when.allOf.every((w) => evalPred(w, exec, cmd));
		if (Array.isArray(when.anyOf)) return when.anyOf.some((w) => evalPred(w, exec, cmd));
		// 工具名不符 → 整条不成立
		if (typeof when.toolIs === "string" && exec.name !== when.toolIs) return false;
		// targetExists：只看 write 的目标在不在（G21 的关键判据）
		if (when.targetExists !== undefined) {
			const args = exec && exec.arguments;
			const p = args && (args.file_path || args.path);
			let exists = false;
			try { exists = !!p && statSync(p).isFile(); } catch { exists = false; }
			if (exists !== when.targetExists) return false;
		}
		if (typeof when.commandContains === "string") return cmd.includes(when.commandContains);
		if (typeof when.commandRegex === "string") {
			return new RegExp(when.commandRegex, when.flags || "").test(cmd);
		}
		return true;
	} catch { return false; }
}

/**
 * **唯一入口**：拿到"当前生效的规则"。
 * 数据可用 → 数据规则；任何问题 → **回落兜底**。
 *
 * ⚠️ `fallbackArg`：**调用方自己把兜底传进来**（`evaluate` 传 `RULES`）。
 *    为什么要这样而不是只靠 `configure()` 设的 CFG.fallback ——
 *    **那会产生顺序依赖**：谁在 `apply()` 之前调 `evaluate()`，就会拿到空规则表。
 *    （挂具 `verify_plugin.mjs` 第 ① 节就是这么失败的：5 项报错，因为那时 configure 还没跑。）
 *    真实宿主里本来没事（evaluate 只在 apply 之后被调），但**潜伏的坑要现在消掉**。
 * ⚠️ 永不抛。
 */
/** ⭐ 这条规则的判据是不是「来自权威工具」→ **是则不该熔断**。
 *  ⚠️ 读规则数据时会顺手刷新那个名单（见 `compile()`）；读不到就用代码默认（**默认不熔断**）。 */
export function isAuthoritative(ruleId) {
	try { readIfChanged(); } catch { /* 读失败就用上一次的名单 */ }
	return authoritative.has(String(ruleId));
}

/** 给状态工具看的：当前认哪些规则是权威的。 */
export function authoritativeRules() {
	try { readIfChanged(); } catch { /* 同上 */ }
	return [...authoritative];
}

export function activeRules(fallbackArg) {	try {
		const c = readIfChanged();
		if (c && Array.isArray(c.rules)) return c.rules;
	} catch (e) {
		stats.fallbackReason = `activeRules 内部异常：${e.message}`;
	}
	return CFG.fallback ?? fallbackArg ?? [];
}

// ═══════════════════════════════════════════════════════════════════
// ⭐ ⑪ 阈值登记表 —— **同一套机制，不新造**
// ═══════════════════════════════════════════════════════════════════
// 来由（用户 2026-09-26 问「我们那个阈值它是放在哪里了？」）：
//   **答案散在三处** —— ① 文档 `rules-lifecycle.md`（代码不读它）② 插件代码常量 ③ 测量结论里。
//   **而「同一个数写在两个地方，迟早不一致」这件事今晚已经吃过一次亏**
//   （文案写着「disputed 现在是 0 条」，而它刚申辩完就是 1 条）。
//
// ⚠️ **为什么复用而不新写一套**：`rules-data.json` 那套已经跑通并验过
//   （**mtime+size 判断、免重启、8 种坏数据 fail open**）。阈值是同一个模式 → **复用它的形状**。
//
// ⚠️ **fail open 的方向**：阈值读不到 → **回落到代码里的默认值** ——
//   **不是「没有阈值」**（那会变成不拦/乱拦），**也不是「报错」**（那会连累护栏本体）。
const DEFAULT_THRESHOLDS = {
	"dispute.minRefusals": { value: 5, basis: "代码默认", source: "designed" },
	"dispute.ratePercent": { value: 40, basis: "代码默认", source: null },
	"circuitBreaker.max": { value: 5, basis: "代码默认", source: "designed" },
	"lint.maxBytes": { value: 102400, basis: "代码默认", source: "measured" },
	"promote.minOccurrences": { value: 3, basis: "代码默认", source: null },
	"rescan.staleHours": { value: 24, basis: "代码默认", source: "designed" },
	"reports.unclassifiedWarnAt": { value: 1, basis: "代码默认", source: "designed" },
};
let TH = { path: "", cache: null };
const thStats = { reads: 0, hits: 0, fallbackReason: null, lastOk: null };

export function configureThresholds({ path }) {
	if (path !== undefined) { TH.path = path; TH.cache = null; }
}

function readThresholds() {
	if (!TH.path) { thStats.fallbackReason = "没配阈值数据文件路径"; return null; }
	let st;
	try { st = statSync(TH.path); } catch (e) {
		thStats.fallbackReason = `statSync 失败：${e.code || e.message}`;
		return null;
	}
	if (TH.cache && TH.cache.mtimeMs === st.mtimeMs && TH.cache.size === st.size) {
		thStats.hits++;
		return TH.cache;
	}
	let data;
	try { data = JSON.parse(readFileSync(TH.path, "utf8")); } catch (e) {
		thStats.fallbackReason = `JSON 解析失败：${e.message}`;
		return null;
	}
	// ⚠️ 校验：任一不合法 → **整份回落**（不猜、不部分采用 —— 部分采用会让"哪几个生效"说不清）
	if (!data || typeof data !== "object" || data.schema !== SUPPORTED_SCHEMA) {
		thStats.fallbackReason = `schema 不认：${data && data.schema}（只认 ${SUPPORTED_SCHEMA}）`;
		return null;
	}
	const t = data.thresholds;
	if (!t || typeof t !== "object" || Object.keys(t).length === 0) {
		thStats.fallbackReason = "thresholds 不是非空对象";
		return null;
	}
	const out = {};
	for (const [k, v] of Object.entries(t)) {
		if (!v || typeof v !== "object" || typeof v.value !== "number" || !Number.isFinite(v.value)) {
			thStats.fallbackReason = `${k} 的 value 不是有限数字`;
			return null;
		}
		out[k] = v;
	}
	thStats.reads++;
	thStats.lastOk = new Date().toISOString();
	TH.cache = { mtimeMs: st.mtimeMs, size: st.size, thresholds: out };
	return TH.cache;
}

/** 拿一个阈值（**永远是数字** —— 数据坏了就用代码默认，**绝不返回 undefined**）。 */
export function threshold(name) {
	try {
		const c = readThresholds();
		if (c && c.thresholds[name] && typeof c.thresholds[name].value === "number") {
			return c.thresholds[name].value;
		}
	} catch { /* 落到下面兜底 */ }
	return DEFAULT_THRESHOLDS[name] ? DEFAULT_THRESHOLDS[name].value : undefined;
}

/** 拿全部（给「阈值体检」工具用：**能一眼筛出 `source: null` 那些欠依据的**）。 */
export function allThresholds() {
	let live = null;
	try {
		const c = readThresholds();
		if (c) live = c.thresholds;
	} catch { /* 落到下面兜底 */ }
	const names = new Set([...Object.keys(DEFAULT_THRESHOLDS), ...Object.keys(live || {})]);
	const rows = [];
	for (const n of [...names].sort()) {
		const fromData = live && live[n] ? live[n] : null;
		const d = fromData || DEFAULT_THRESHOLDS[n] || { value: undefined, basis: "(未知)", source: null };
		const noBasis = d.source === null || d.source === undefined;
		rows.push({ 名称: n, 值: d.value, 来源: fromData ? "数据文件" : "代码默认",
			依据: d.basis || "", 出处: noBasis ? "**null（拍的）**" : d.source,
			待补依据: noBasis ? "**是**" : "" });
	}
	return rows;
}

export function thresholdStats() {
	return { ...thStats, usingData: TH.cache !== null, path: TH.path,
		count: TH.cache ? Object.keys(TH.cache.thresholds).length : null };
}
