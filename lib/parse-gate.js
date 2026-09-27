// 护栏的第 5 条规则：**写下去的东西能不能解析**。
//
// ═══ 为什么这条可以"拦"（而内容规则不行）═══
//   内容规则是**判断题**（"这个模式危险吗"）→ 必然有误报；
//   解析是**事实题**（"这段字节能不能被解析"）→ **判据不是我说的，是解析器说的**，误报率在原理上是 0。
//   本条也不需要更多样本：本会话有 **5 次真实命中**（4 次 f-string 引号 + 1 次括号不匹配）。
//
// ═══ 隔离（五条，一条都不省）═══
//   ① **代码独立文件** —— 本模块不混进 rules.js 的现有规则代码
//   ② **故障隔离** —— 导出的一切都**不会抛**；调用方（index.js）还会再包一层 try/catch
//   ④ **独立台账 + 独立计数** —— 台账 kind=`parse_blocked`、rule=`G41`，与命令类规则分开可数
//   （③⑤ 在 index.js 里：单独开关 `parseCheck`、在现有规则**之后**评估）
//
// ═══ 成本（实测中位数，因为 guard 是同步的 → 这就是宿主阻塞时间）═══
//   .json  进程内 JSON.parse      ≈ 0 ms   → **总是查**
//   .py    spawn python+ast.parse  42 ms（1KB）/ 83 ms（500KB）
//   .js    spawn node --check      48 ms（与大小无关，spawn 固定开销占大头）
//   → 所以带：**超时 + 大小上限 + 内容哈希缓存**（同样的内容不重复 spawn）
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, unlinkSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "guardrail-parse-"));
let tmpSeq = 0;

/** 支持的扩展名 → 权威解析器 */
export const PARSERS = {
	".json": "json",
	".py": "python",
	".js": "node",
	".mjs": "node",
	".cjs": "node",
};

function extOf(p) {
	const s = String(p || "").toLowerCase();
	const i = s.lastIndexOf(".");
	return i >= 0 ? s.slice(i) : "";
}

/** 内容哈希缓存：同样的内容不重复 spawn（实测 spawn 固定开销占大头） */
const cache = new Map();
let cacheHits = 0, cacheMiss = 0;
const CACHE_MAX = 500;

function hashOf(s) {
	// 便宜且够用的字符串哈希（不是加密用途）
	let h = 5381;
	for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
	return h.toString(36) + ":" + s.length;
}

/**
 * → { ok: true }                     能解析
 *   { ok: false, reason, line, msg } 不能解析（**有权威依据**）
 *   { ok: null, skipped }            **没查**（未知类型/太大/超时/解析器崩了）→ 调用方必须放行
 *
 * ⚠️ **这个函数不抛**（隔离②）。任何"我们这边出问题"都返回 ok:null → 放行。
 */
export function parseCheck(filePath, content, opts = {}) {
	try {
		const maxBytes = opts.maxBytes ?? 2 * 1024 * 1024;
		const timeoutMs = opts.timeoutMs ?? 4000;
		const kind = PARSERS[extOf(filePath)];
		if (!kind) return { ok: null, skipped: `未知类型 ${extOf(filePath) || "(无扩展名)"}` };
		if (typeof content !== "string") return { ok: null, skipped: "拿不到内容" };
		if (Buffer.byteLength(content, "utf8") > maxBytes) {
			return { ok: null, skipped: `超过大小上限 ${maxBytes} 字节（不查，放行）` };
		}

		// ── .json：进程内，免费 → 总是查 ──
		if (kind === "json") {
			try {
				JSON.parse(content);
				return { ok: true };
			} catch (e) {
				const m = /position (\d+)/.exec(String((e && e.message) || ""));
				const line = m ? content.slice(0, Number(m[1])).split("\n").length : null;
				return { ok: false, reason: "JSON 解析失败",
					line, msg: String((e && e.message) || e).slice(0, 200) };
			}
		}

		// ── .py / .js：内容哈希缓存 ──
		const key = kind + "|" + hashOf(content);
		if (cache.has(key)) { cacheHits++; return cache.get(key); }
		cacheMiss++;

		let out;
		const f = join(TMP, `c${++tmpSeq}${extOf(filePath)}`);
		try {
			writeFileSync(f, content, "utf8");
		} catch (e) {
			out = { ok: null, skipped: `写临时文件失败：${e && e.message}` };
			return out;
		}
		try {
			if (kind === "python") {
				const helper = join(TMP, "pycheck.py");
				try {
					writeFileSync(helper,
						"import ast,sys\n"
						+ "try:\n"
						+ "    ast.parse(open(sys.argv[1],encoding='utf-8',errors='replace').read())\n"
						+ "except SyntaxError as e:\n"
						+ "    sys.stderr.write(f'{e.lineno}|{e.msg}')\n"
						+ "    sys.exit(1)\n"
						+ "except Exception as e:\n"
						+ "    sys.stderr.write(f'?|{type(e).__name__}: {e}')\n"
						+ "    sys.exit(2)\n", "utf8");
				} catch { /* 已存在也行 */ }
				execFileSync(process.env.DSH_PYTHON || "python", [helper, f],
					{ stdio: ["ignore", "ignore", "pipe"], timeout: timeoutMs, encoding: "utf8" });
				out = { ok: true };
			} else {
				execFileSync(process.execPath, ["--check", f],
					{ stdio: ["ignore", "ignore", "pipe"], timeout: timeoutMs, encoding: "utf8" });
				out = { ok: true };
			}
		} catch (e) {
			if (e && (e.code === "ETIMEDOUT" || e.signal || e.code === "ENOENT")) {
				out = { ok: null, skipped: `解析器不可用/超时（${e.code || e.signal}）→ 放行` };
			} else {
				// ⚠️ 必须先归一化换行（**挂具抓出来的真 bug**）：
				//    Node 在 Windows 上的 stderr 是 `\r\n`，而我原来写的是 `(\d+)\n`
				//    → **匹配失败** → 落到"非预期结果 → 放行" → **.js/.mjs 那一路悄悄变成 skip，根本不会拦**。
				//    又一次"静默跳过"：看起来像"没发现问题"，实际是"根本没查"。
				const stderr = String((e && e.stderr) || "").replace(/\r\n/g, "\n");
				if (kind === "python") {
					const parts = stderr.trim().split("|");
					if (parts.length === 2 && parts[0] !== "?") {
						out = { ok: false, reason: "Python 语法错误（ast.parse）",
							line: Number(parts[0]) || null, msg: parts[1].slice(0, 200) };
					} else {
						out = { ok: null, skipped: `python 解析器返回非预期结果 → 放行：${stderr.slice(0, 120)}` };
					}
				} else {
					const m = /^(.*?):(\d+)\n([\s\S]*)$/m.exec(stderr.trim());
					if (m) {
						const msgLine = m[3].split("\n").find((x) => x.includes("Error")) || m[3].trim().split("\n")[0];
						out = { ok: false, reason: "JavaScript 语法错误（node --check）",
							line: Number(m[2]) || null, msg: msgLine.trim().slice(0, 200) };
					} else {
						out = { ok: null, skipped: `node 解析器返回非预期结果 → 放行：${stderr.slice(0, 120)}` };
					}
				}
			}
		} finally {
			try { unlinkSync(f); } catch { /* 临时文件删不掉也无所谓 */ }
		}
		if (cache.size >= CACHE_MAX) cache.clear();
		cache.set(key, out);
		return out;
	} catch (e) {
		// 隔离②：**这个函数永不抛** —— 兜到最外层也返回"没查"
		return { ok: null, skipped: `parseCheck 内部异常（已兜住）→ 放行：${(e && e.message) || e}` };
	}
}

/** 取出「这次要写下去的字节」。取不到 → null（调用方放行）。 */
export function contentOf(exec) {
	try {
		const args = exec && exec.arguments;
		if (!args || typeof args !== "object") return null;
		const path = args.file_path || args.path;
		if (typeof path !== "string" || !path) return null;
		if (exec.name === "write") {
			return typeof args.content === "string" ? { path, content: args.content } : null;
		}
		if (exec.name === "edit") {
			// ⚠️ edit 的 new_string 是**片段**，片段不是模块，ast.parse 不了。
			//    所以：读原文件 → 应用这次替换 → 解析**结果**。
			const oldS = args.old_string, newS = args.new_string;
			if (typeof oldS !== "string" || typeof newS !== "string") return null;
			let before;
			try { before = readFileSync(path, "utf8"); } catch { return null; }  // 读不到 → 放行
			const idx = before.indexOf(oldS);
			if (idx < 0) return null;                                            // 对不上 → 放行
			return { path, content: before.slice(0, idx) + newS + before.slice(idx + oldS.length), before };
		}
		return null;
	} catch { return null; }
}

/**
 * 规则的**唯一入口**。返回 undefined=放行 / 字符串=拒绝理由。
 * ⚠️ 不抛（隔离②）；调用方还会再包一层 try/catch。
 */
// ═══════════════════════════════════════════════════════════════════
// ⭐ ⑤ BOM 检查 —— **和解析器同一条链，但在它前面**
// ═══════════════════════════════════════════════════════════════════
// 来由：坑 P35（「写文件时的隐形污染」，2026-09-26 升格）。
//   **PowerShell 5.1 的 `-Encoding UTF8` 永远写 BOM** → 写出的 `.py` 开头多 3 个字节
//   → `ast.parse` 报 `invalid non-printable character U+FEFF`。**本会话踩了 8 次。**
//
// ⚠️⚠️ **为什么不新开一条规则，而是并进 G41**（三条理由）：
//   ① **避免重复报**：一个带 BOM 的 `.py` **两条都会命中**（BOM 也是"解析不了"的原因）
//      → 用户会看到两条、以为有两个问题；台账里也会记两条 → **"这条规则拦过几次"被虚高**。
//   ② **改法才是对的**：如果让解析器报它，它会说「**修掉那一行的语法**」——
//      **而真正该做的是去掉头 3 个字节** → **那条改法会把人带偏。**
//   ③ **G41 的通道已经是全的**（数据化 / fail open / 独立台账 / 不熔断）—— 直接复用。
//
// ⚠️ **它该不该熔断？→ 不该。** 因为它和解析器一样**是机械判据**
//   （`EF BB BF` 就是 `EF BB BF`，**不可能误判**）→ 它也是"权威判据"。
//   → 而 G41 已经在 `authoritativeRules` 里 → **自动不熔断** ✅
//
// ⚠️ **"本来就有就不拦"**：那个规矩（edit 只为"改坏了"负责）**同样适用** ——
//   否则我会**为文件里早就存在的 BOM 拦一次 edit**，而那次 edit 根本没碰开头。
const BOM = Buffer.from([0xEF, 0xBB, 0xBF]);

/** 取一段文本的**前 3 个字节**（⚠️ **不是前 3 个字符** —— 这是我第一版写错的地方）。 */
function head3(s) {
	// ⚠️⚠️ 我第一版写的是 `Buffer.from(s.slice(0, 3), "utf8")` ——
	//    **`slice` 按【字符】切，不是按字节切。**
	//    而 BOM 是**一个**字符（`\uFEFF`）→ `slice(0,3)` 拿到的是 3 个字符
	//    = `\uFEFF` + `x` + ` ` = **5 个字节**（EF BB BF 78 20）→ **永远比不中。**
	//    ★ **而"能抓"那半在 Python 探针里是对的**（那边用 `read_bytes()`）——
	//      **所以是"判据对、实现错"**。**抓住它的是那个 JS 探针（它跑的是真路径）。**
	return Buffer.from(s, "utf8").subarray(0, 3);
}

export function bomVerdict(got) {
	try {
		if (!got || typeof got.content !== "string") return undefined;
		// 只看**要写下去的最终内容**的头 3 个**字节**
		if (!head3(got.content).equals(BOM)) return undefined;
		// edit：改之前就有 BOM → **不算它头上**（和解析器那条一样的规矩）
		if (got.before && head3(String(got.before)).equals(BOM)) return undefined;
		return {
			file: got.path,
			reason: "**文件开头有 BOM**（3 个看不见的字节 `EF BB BF`）",
			line: 1,
			msg: "**这不是语法错，是字节层的污染** —— 解析器看到的第一个字符是 U+FEFF。",
			bom: true,
		};
	} catch { return undefined; }        // 永不抛（和这个模块的其它函数一致）
}

/**
 * ⭐⭐ **G42：`.ps1` 丢了 BOM**（2026-09-27，用户报的真实事故 → 用户要求升格成规则）。
 *
 * 为什么 `.ps1` 反过来管：它是**唯一一种「BOM 应该有」的文件** ——
 *   Windows PowerShell 5.1 **靠 BOM 认 UTF-8**；没有它，5.1 按系统 ANSI(GBK) 读 →
 *   **中文全乱码 + 收尾引号被吃掉** → 整个脚本报几十条语法错。
 *   （2026-09-26 实测：`D:\仓库\bin\proj.ps1` 就这么坏过一次 —— `proj.cmd audit` 立刻 exit 1。）
 *
 * ⚠️ **两半的判据不一样**（因为它们看得见的东西不一样）：
 *   · `write` → **看内容**：要写下去的字节本身就在参数里（行为无关，机械判据）。
 *   · `edit`  → **参数里看不见**：`contentOf(edit)` 是拿盘上现有字节（含 BOM）+ 替换片段算出来的
 *     → 算出来的内容**一定还带 BOM**，而工具写回时**会把它剥掉**（实测）。
 *     → 那一半靠一条**实测过的宿主行为**（环境事实类，同 G03 那条「本机 pwsh 不可用」），
 *       并且**带 `revisit_when`** —— 判据要能被复核、会过期，而不是"你说了算"。
 */
export function bomLossVerdict(got, exec) {
	try {
		if (!got || typeof got.content !== "string") return undefined;
		if (extOf(got.path) !== ".ps1") return undefined;      // ⚠️ **只管 .ps1**
		// 前提：**现在这个文件有 BOM**（没有就谈不上"丢"）
		let now;
		try { now = head3(readFileSync(got.path, "utf8")); }
		catch { return undefined; }                             // 读不到目标 → fail open
		if (!now.equals(BOM)) return undefined;                 // 原本就没 BOM → 不关这条规则的事
		// ① `edit`：参数里看不见（见上）→ 按那条实测事实判
		if (exec && exec.name === "edit") {
			return {
				rule: "G42", file: got.path, bomLoss: true, byEdit: true, line: 1,
				revisit_when: "**宿主把编辑工具改成「写回时保留原文件 BOM」的那一天** —— "
					+ "判据：造一个带 BOM 的 .ps1，用 edit 加一行，看头 3 字节还是不是 `EF BB BF`。"
					+ "（2026-09-27 实测是：变成 `23 20 E8` → 会丢。）",
				reason: "**这次编辑会让这个 `.ps1` 丢掉开头的 BOM**（3 个字节 `EF BB BF`）",
				msg: "编辑工具的写回**不带 BOM**（2026-09-27 实测：`EF BB BF` → `23 20 E8`），"
					+ "而这个文件现在**有** BOM。",
			};
		}
		// ② 其他（`write`）：看内容。内容还带 BOM → 保留了 → 放行
		if (head3(got.content).equals(BOM)) return undefined;
		return {
			rule: "G42", file: got.path, bomLoss: true, line: 1,
			reason: "**这次写入会让这个 `.ps1` 丢掉开头的 BOM**（3 个字节 `EF BB BF`）",
			msg: "目标文件现在**有** BOM，而要写下去的内容**没有**。",
		};
	} catch { return undefined; }        // 永不抛（和这个模块的其它函数一致）
}

export function gateVerdict(exec, opts = {}) {
	const got = contentOf(exec);
	if (!got) return undefined;                                  // fail open
	// ⭐⭐⭐ 2026-09-27 **`.ps1` 反过来管（G42）** —— 理由见 `bomLossVerdict` 的注释。
	//   一句话：**对 `.ps1`，BOM 是该有的状态** →
	//     写丢了 → 拦；写对了（带 BOM）→ **放行**（**不走下面那条"多 BOM"检查**）。
	if (extOf(got.path) === ".ps1") return bomLossVerdict(got, exec);
	// ⭐ ⑤ **BOM 在前**（理由见上面那段）—— 命中就直接给"具体原因"，**不走解析器**
	const bom = bomVerdict(got);
	if (bom) return bom;
	const r = parseCheck(got.path, got.content, opts);
	if (r.ok !== false) return undefined;                        // ok:true 放行 / ok:null 放行（fail open）

	// ⚠️ edit：只有"改之前是好的、改之后坏了"才算它头上 ——
	//    绝不为"文件里早就存在的问题"拦它（prior art：那样人会**绕着它干活**）。
	if (exec.name === "edit" && got.before) {
		const prev = parseCheck(got.path, got.before, opts);
		if (prev.ok === false) return undefined;
	}
	return { file: got.path, ...r };
}

export function parseGateStats() {
	return { cacheHits, cacheMiss, cacheSize: cache.size };
}
