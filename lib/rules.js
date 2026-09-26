// 护栏的规则表。
//
// ⚠️ 与坑清单的同步是硬要求：**每条规则都必须标 `pitfall`（坑清单 id）**。
//    由 sync-check.py 校验两边对得上；对不上就报错。
//
// level 只有两种，这是刻意的：
//   block —— **只给"几乎必然失败"的规则**。理由：拒绝率必须极低，才能与计划锚零撞车
//            （护栏拦"命令本身"，计划锚拦"计划动作"，本来就几乎不会同时命中）。
//   warn  —— 其余一律"放行 + 提示"。**护栏不做"风格警察"。**
//
// 判据全部来自实证：`exec.name`（工具名）+ `exec.arguments.command`（命令串）。
//
// 2026-09-26 修 G21 误报：原来"新建文件"也会提示"先读再改"，而 P09 说的是"改**已有**文件"。
//   依据（Lead）："误报正好落在『拒绝率必须极低』要防的噪声上，噪声多了这工具就废了。"
import { existsSync } from "node:fs";

/** 只在这些工具上判命令串。 */
export const SHELL_TOOLS = new Set(["pwsh", "exec", "bash", "shell"]);

/** G01 的内联形态表（**四支，每支对应数据文件里的一条 `anyOf`**）。
 *
 *  ⚠️ 为什么要扩（用户 2026-09-26 问"绕着干活是什么意思"）：
 *    原来只有 `\bpython3?\s+-c\b` —— 覆盖 `python -c` / `python3 -c`，
 *    **但 `py -c`（Windows py launcher，本机常见）、`python - <<EOF`、`| python` 全都认不出来**。
 *    而它们**做的是同一件有风险的事**，只是让规则认不出来。**换个写法风险不变 → 判据要跟上。**
 *
 *  ⚠️ 不能误伤（**下面有正反用例，两边都验**）：
 *    `python setup.py` / `python script.py` / `python -m http.server` / `python -X utf8 x.py`
 *    **全是正路，一条都不许匹配。**
 *  ⚠️ 这条与 `lib/rules-data.json` 里 G01 的 `anyOf` **必须一致** ——
 *    等价性挂具（verify_rules_data.mjs）会当场抓到漂。**改一处必须改另一处。** */
export const INLINE_PY = [
	/\b(?:python[0-9.]*|py)(?:\.exe)?\s+-c\b/i,                    // -c（含 py -c）
	/\b(?:python[0-9.]*|py)(?:\.exe)?\s+(?:-\s*)?<</i,             // heredoc（含 python - <<EOF）
	/\b(?:python[0-9.]*|py)(?:\.exe)?\s+-\s*(?:$|[|>&;\r\n])/i,    // 从 stdin 喂（`python -`；**不碰 `-m` / `-X`**）
	/\|\s*(?:python[0-9.]*|py)(?:\.exe)?\s*(?:$|[-<])/i,           // 管道喂（`… | python` / `| python -`）
];

// 规则数据化：`activeRules()` 数据优先、坏了回落 `RULES`
import { activeRules } from "./rule-loader.js";

export const RULES = [
	{
		id: "G11",
		pitfall: "P01",
		level: "warn",
		test: (cmd) => cmd.includes("2>&1"),
		why: "2>&1 合并流后，子进程写 stderr 会被 PowerShell 当成 NativeCommandError（命令其实成功了）",
		fix: "别合并 stderr；把 stderr 重定向到文件再读",
	},
	{
		id: "G12",
		pitfall: "P07",
		level: "warn",
		test: (cmd) => /-Recurse\b|rglob\(|os\.walk|Get-ChildItem\s+-Recurse/i.test(cmd),
		why: "全量递归扫描容易撞 120 秒超时上限",
		fix: "用 run_in_background: true 起后台作业，再 job_output 取回",
	},
];

// ═══════════════════════════════════════════════════════════════════
// ⚠️ **下面是这个项目自己用的另外 7 条规则 —— 默认关掉，作为例子留着。**
//
// **为什么默认关**：其中 **G01/G02/G03 是 `block` 类** ——
//   **一个刚装上的插件不该立刻开始拒绝人。**（也和「拒绝率必须极低」那条设计约束一致。）
//
// ⚠️ **而它们全是「Windows + PowerShell 5.1 + 中文环境」下的实测坑** ——
//   **在你的环境里多半不成立**。要用的话：
//     ① 先看一遍每条的 `why`（它为什么算坑）
//     ② 从注释里取消你环境里成立的那几条
//     ③ **同时**往 `lib/rules-data.json` 里加对应条目（两边一致才不会漂 ——
//        `verify/verify_rules_data.mjs` 会断言这件事）
// ═══════════════════════════════════════════════════════════════════
	//   {
	//     id: "G01",
	//     pitfall: "P02",
	//     level: "block",
	//     test: (cmd) => INLINE_PY.some((rx) => rx.test(cmd)),
	//     why: "python 内联脚本：shell 会二次解释引号/中文，几乎必然 SyntaxError 或 UnicodeEncodeError。**本条覆盖内联的各种形态**（`-c` / `py -c` / 从 stdin 喂 / heredoc / 管道喂）—— 它们做的是同一件事，**换个写法风险不变**。",
	//     fix: "把代码写成 .py 文件再跑（`python dsh-run.py 文件.py`）。**多行内联的推荐正路**：`@'…'@ | python dsh-run.py --stdin` —— 单引号 here-string **不插值、不解释内部引号，真安全**。⚠️ 别用 `echo \"…\" | …`（那和 `-c` 一样会被解释一遍引号）；也别换别的内联形态 —— 风险一样。",
	//   },
	//   {
	//     id: "G02",
	//     pitfall: "P05",
	//     level: "block",
	//     test: (cmd) => cmd.includes("&&"),
	//     why: "PowerShell 5.1 不支持 &&，会 ParserError（本机就是 5.1，见 P19）",
	//     fix: "拆成两条命令，或用 `;`，或写成 .py 文件",
	//   },
	//   {
	//     id: "G03",
	//     pitfall: "P19",
	//     level: "block",
	//     test: (cmd) => /\bpwsh\b/i.test(cmd) || /\.ps1\b/i.test(cmd),
	//     why: "本机 pwsh 不在 PATH（跑的是 PowerShell 5.1），且 ExecutionPolicy=Restricted → .ps1 一律无法执行",
	//     fix: "包装器/工具用 Python 写；不要用 .ps1",
	//   },
	//
	//   // ───────── warn：放行 + 提示（护栏的默认档） ─────────
	//   {
	//     id: "G13",
	//     pitfall: "P08",
	//     level: "warn",
	//     test: (cmd) => /(?<![\w\\.:/])python\s+(?!-)/i.test(cmd),
	//     why: "裸 python 可能不在 PATH（不同 shell 环境不一样）",
	//     fix: "用绝对路径，或先 `Get-Command python` 确认",
	//   },
	//   {
	//     id: "G14",
	//     pitfall: "P04",
	//     level: "warn",
	//     test: (cmd) => /[\u4e00-\u9fff]/.test(cmd) && /\bpython\b|\bnode\b|\.py\b/i.test(cmd),
	//     why: "命令里含中文且要跑脚本：Windows 控制台默认 GBK，中文进出都可能被改写",
	//     fix: "脚本里 `sys.stdout.reconfigure(encoding='utf-8')`，或先 `chcp 65001`",
	//   },
	//
	//   // ───────── 文件类 warn（用 file_path，不用 command） ─────────
	//   {
	//     id: "G21",
	//     pitfall: "P09",
	//     level: "warn",
	//     tools: new Set(["edit", "write"]),
	//     fileRule: true,
	//     // ⚠️ 这里曾有误报（2026-09-26 修）：
	//     //   · edit  → 改的是已有文件，**该提示**
	//     //   · write → **只有目标已存在时**才提示（那才是"覆盖已有文件"）
	//     //   · write 到不存在的路径 = 新建，**不可能踩 P09，不提示**
	//     test: (exec) => {
	//       const tool = exec && exec.name;
	//       if (tool === "edit") return true;
	//       if (tool === "write") {
	//         const p = filePathOf(exec);
	//         if (!p) return false;
	//         try { return existsSync(p); } catch { return false; }
	//       }
	//       return false;
	//     },
	//     why: "改**已有**文件前必须先在本会话读过它（否则 FS_NOT_OBSERVED）；凭记忆写 old_string 会 FS_EDIT_NOT_FOUND",
	//     fix: "先 read 该文件；old_string 用当前内容里短而独特的片段",
	//   },
	//   // ⭐ G51（P13）—— 2026-09-26 从「待升格候选」升格而来（用户点头）。
	//   //    ⚠️ **它是 warn 不是 block**：fetch 一个 PDF 不是错，只是会失败。
	//   //    ⭐ 量过：历史命令里 `.pdf` 结尾的 URL 出现 **220 次**。
	//   //    ⚠️ **误报率没测**（没有语料能判「这次会不会真失败」）—— 如实标着。
	//   {
	//     id: "G51", pitfall: "P13", level: "warn",
	//     tools: ["pwsh", "exec", "bash", "shell"],   // ⚠️ 只能放 SHELL_TOOLS 里的
	//     when: { anyOf: [
	//       { commandRegex: "https?://[^\\s\"']+\\.pdf\\b", flags: "i" },
	//       { commandContains: ".pdf" },
	//     ] },
	//     why: "**这条命令/这个动作指向一个 PDF。** fetch **不跟随跨域重定向**、**也不支持 PDF**（拿到的是二进制垃圾）。\n"
	//       + "⭐ 量过：历史里 `.pdf` 结尾的 URL 出现 **220 次** → 不是「只有成本」。",
	//     fix: "① 要内容 → 先 `web_search` 找 HTML 版/摘要；② 非要原文 → 用能下二进制的工具拿、再本地读；③ 只是顺口提到 → 忽略。",
	//   },


/** 按工具取"命令串" —— 实证出来的字段名：exec.arguments.command */
export function commandOf(exec) {
	const args = exec && exec.arguments;
	if (!args || typeof args !== "object") return "";
	return typeof args.command === "string" ? args.command : "";
}

export function filePathOf(exec) {
	const args = exec && exec.arguments;
	if (!args || typeof args !== "object") return "";
	return typeof args.file_path === "string" ? args.file_path
		: typeof args.path === "string" ? args.path : "";
}

// ───────── 裸数字检查：扫"要发出去的消息"里有没有手写的指标数字 ─────────
//
// 解决什么：口径登记表只管住"照规矩报数的人"。谁**绕过生成器手写一个数字**发出去，
// 原本机制看不见。而 **`send_message` 本身也是一次工具调用** —— 所以能在**发出去之前**扫它。
//
// ⚠️ 为什么不走 `agent/turn-stopping`（Stop 钩子）：**已实测**它存在、且能被"反对"
//    （文档原文："a listener that objects steers (agent.steer(...))"），
//    但 (a) payload 是 `{agent, turn, signal}`，**不给助手输出文本**；
//        (b) 它给的能力是"**让 AI 再跑一步**" —— 护栏已证明无上限重复会**专门惩罚诚实的 AI**。
//    扫 `send_message` 更简单、且在**动手前**，没有那条风险。
//
// ⚠️ 覆盖边界（如实，别当成堵死了）：
//    能——让"手写指标数字"**在发出去之前显形**；
//    不能——**强迫**任何人一定走生成器（换个说法、写中文数字、不给关键词，都绕得过去）。
const MARK_RE = /<!--METRIC:([^:]+):v(\d+)-->[\s\S]*?<!--\/METRIC-->/g;
const NUM_RE = /(\d+(?:\.\d+)?)\s*%|(\d+)\s*\/\s*(\d+)/g;
const NEAR = 30;

/** 剥掉走正门的标记块（生成器产出的），剩下的才算"裸数字"。 */
export function stripMarked(text) {
	const marks = [];
	const body = String(text || "").replace(MARK_RE, (mo, m, v) => {
		marks.push(`${m} v${v}`);
		return "\n";
	});
	return { body, marks };
}

/** registry: {metrics: {id: {keywords?: [], reports: [{raw:{value}, adjusted:{value}}]}}} */
export function scanBareMetricNumbers(text, registry) {
	const { body, marks } = stripMarked(text);
	const hits = [];
	const metrics = (registry && registry.metrics) || {};
	const lower = body.toLowerCase();
	for (const [mid, m] of Object.entries(metrics)) {
		const kws = (m.keywords && m.keywords.length) ? m.keywords : (() => {
			const tail = mid.split(".").pop();
			const set = new Set([tail, mid]);
			if (mid.includes("hitrate")) { set.add("命中率"); set.add("hitrate"); set.add("准确率"); }
			return [...set];
		})();
		const known = new Set();
		for (const r of (m.reports || [])) {
			if (r.raw && typeof r.raw.value === "number") known.add(Math.round(r.raw.value * 10) / 10);
			if (r.adjusted && typeof r.adjusted.value === "number") known.add(Math.round(r.adjusted.value * 10) / 10);
		}
		for (const kw of kws) {
			const k = kw.toLowerCase();
			let idx = 0;
			while ((idx = lower.indexOf(k, idx)) !== -1) {
				const win = body.slice(Math.max(0, idx - NEAR),
					Math.min(body.length, idx + k.length + NEAR));
				NUM_RE.lastIndex = 0;
				let mo;
				while ((mo = NUM_RE.exec(win)) !== null) {
					let shown, val;
					if (mo[1] !== undefined) { shown = `${mo[1]}%`; val = Number(mo[1]); }
					else {
						const a = Number(mo[2]), b = Number(mo[3]);
						if (!b) continue;
						shown = `${a}/${b}`; val = 100 * a / b;
					}
					hits.push({
						metric: mid, keyword: kw, shown,
						inRegistry: known.has(Math.round(val * 10) / 10),
					});
				}
				idx += k.length;
			}
		}
	}
	const seen = new Set();
	return hits.filter((h) => {
		const k = `${h.metric}|${h.shown}|${h.keyword}`;
		if (seen.has(k)) return false;
		seen.add(k);
		return true;
	});
}

/** 对一次调用算出命中：{blocks:[], warns:[]}
 *
 *  ⚠️ 2026-09-26 改（规则数据化）：原来遍历的是写死的 `RULES`，现在遍历 `activeRules()` ——
 *     **数据文件可用就用数据里的规则，任何问题回落到 `RULES`（代码默认）**。
 *     `activeRules()` 返回的条目**形状和 `RULES` 完全一致** → 下面这个循环**一行都没改**，
 *     所以行为**天然等价**（等价性另有挂具逐例证明）。
 */
export function evaluate(exec) {
	const blocks = [];
	const warns = [];
	if (!exec || typeof exec !== "object") return { blocks, warns };
	const tool = exec.name;
	for (const r of activeRules(RULES)) {
		if (r.fileRule) {
			if (!r.tools || !r.tools.has(tool)) continue;
			let hit = true;
			if (typeof r.test === "function") {
				try { hit = !!r.test(exec); } catch { hit = false; }
			}
			if (hit) warns.push(r);
			continue;
		}
		if (!SHELL_TOOLS.has(tool)) continue;
		const cmd = commandOf(exec);
		if (!cmd) continue;
		let hit = false;
		try { hit = r.test(cmd); } catch { hit = false; }
		if (!hit) continue;
		(r.level === "block" ? blocks : warns).push(r);
	}
	return { blocks, warns };
}
