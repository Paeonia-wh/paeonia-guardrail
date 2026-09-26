// 规则数据化的验收挂具 —— **等价性 + 免重启 + fail open**，三件都要证。
//
// Lead 的硬要求："改完必须等价：现有 4+1 条规则的行为**一个都不许变**"。
// 所以第一件就是**逐例等价**：同一批输入，数据加载的规则 vs 代码默认的规则，
// **blocks/warns 的 id 序列必须一字不差**。
//
// ⚠️ 挂具只证代码、不证部署。
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RULES, SHELL_TOOLS, evaluate } from "../lib/rules.js";
import { activeRules, configure, loaderStats } from "../lib/rule-loader.js";

let pass = 0, fail = 0;
const chk = (ok, msg) => { console.log(`  ${ok ? "[OK]  " : "[FAIL]"} ${msg}`); ok ? pass++ : fail++; };
const TMP = mkdtempSync(join(tmpdir(), "rules-data-verify-"));
const DATA = join(TMP, "rules-data.json");
const REAL = join(process.cwd(), "lib", "rules-data.json");

const ids = (r) => [...r.blocks.map((x) => x.id), "|", ...r.warns.map((x) => x.id)].join(",");

// ───────── 用同一批输入跑两遍：数据规则 vs 代码默认 ─────────
function bothWays(cases) {
	const out = [];
	for (const [desc, exec] of cases) {
		configure({ path: "", fallback: RULES, shellTools: SHELL_TOOLS });     // 代码默认
		const code = evaluate(exec);
		configure({ path: REAL, fallback: RULES, shellTools: SHELL_TOOLS });   // 数据
		const data = evaluate(exec);
		out.push([desc, ids(code), ids(data)]);
	}
	return out;
}

const EX = (name, args) => ({ name, arguments: args });
const fileExists = join(TMP, "exists.txt");
writeFileSync(fileExists, "x", "utf8");
const fileMissing = join(TMP, "nope-xyz.txt");

const CASES = [
	// 命令类：命中与不命中都覆盖
	["G01 命中", EX("pwsh", { command: 'python -c "print(1)"' })],
	["G01 不命中（python 但非 -c）", EX("pwsh", { command: "python foo.py" })],
	["G02 命中", EX("pwsh", { command: "a && b" })],
	["G02 不命中", EX("pwsh", { command: "a ; b" })],
	["G03 命中 pwsh", EX("pwsh", { command: "pwsh -NoProfile -Command x" })],
	["G03 命中 .ps1", EX("pwsh", { command: "run.ps1" })],
	["G11 命中", EX("pwsh", { command: "x 2>&1" })],
	["G12 命中", EX("pwsh", { command: "Get-ChildItem -Recurse ." })],
	["G12 命中 rglob", EX("pwsh", { command: "for p in d.rglob('*'): ..." })],
	["G13 命中裸 python", EX("pwsh", { command: "python foo.py" })],
	["G13 不命中（带路径）", EX("pwsh", { command: "C:\\py\\python.exe foo.py" })],
	["G13 不命中（-c 形式）", EX("pwsh", { command: 'python -c "x"' })],
	["G14 命中（中文+python）", EX("pwsh", { command: "chcp 65001; python 脚本.py" })],
	["G14 不命中（中文但无脚本）", EX("pwsh", { command: "Get-ChildItem 目录" })],
	["G14 不命中（脚本但无中文）", EX("pwsh", { command: "python foo.py" })],
	["多命中（G01+G13+G14）", EX("pwsh", { command: 'chcp 65001; python -c "中文"' })],
	["空命令", EX("pwsh", { command: "" })],
	["非 shell 工具（不受命令类规则影响）", EX("read", { file_path: "x" })],
	// 文件类 G21：三种情形
	["G21 edit（恒提示）", EX("edit", { file_path: fileMissing })],
	["G21 write 到已存在", EX("write", { file_path: fileExists })],
	["G21 write 到不存在（新建，不提示）", EX("write", { file_path: fileMissing })],
	["G21 无 file_path", EX("write", {})],
	// ── G01 扩表（用户 2026-09-26 问「绕着干活」）：**四种绕法 + 四种正路** ──
	["G01 绕法 py -c", EX("pwsh", { command: 'py -c "print(1)"' })],
	["G01 绕法 heredoc", EX("pwsh", { command: "python - <<EOF\nprint(1)\nEOF" })],
	["G01 绕法 管道喂", EX("pwsh", { command: 'echo "print(1)" | python' })],
	["G01 绕法 stdin", EX("pwsh", { command: "python -" })],
	["G01 正路 setup.py", EX("pwsh", { command: "python setup.py install" })],
	["G01 正路 -m", EX("pwsh", { command: "python -m http.server" })],
	["G01 正路 -X utf8", EX("pwsh", { command: "python -X utf8 x.py" })],
	["G01 正路 脚本", EX("pwsh", { command: "python script.py" })],
];

// ───────── ⓿ **非空跑**护栏：这一条必须先过，否则后面全是在自欺 ─────────
// ⚠️ 2026-09-26 补（**自己抓出来的严重缺陷**）：
//    第一版挂具在 rules-data.json **非法**的情况下也报"18 通过 / 0 失败" ——
//    因为数据解析失败 → 加载器**回落代码默认** → 两边都跑代码 → **等价性 trivially 相等**。
//    **"看起来正常、实际没查"** —— 和今晚那批 bug 一模一样的形状。
//    所以：**任何用到数据文件的断言之前，必须先证"数据真的被用上了"。**
console.log("=".repeat(76));
console.log("⓿ 非空跑护栏：数据文件必须**真的被加载**（否则后面全是自欺）");
console.log("=".repeat(76));
{
	configure({ path: REAL, fallback: RULES, shellTools: SHELL_TOOLS });
	// ⚠️ **顺序**：必须先 `activeRules()` 触发一次读取，`loaderStats()` 才有得报 ——
	//    它报的是"**上一次读取**的结果"，而 `cache` 只在 `readIfChanged()` 里填。
	//    （第一版我在触发之前就查 stats → 拿到 usingData=false 的假失败。）
	const n = activeRules(RULES).length;
	const st = loaderStats();
	chk(st.usingData === true,
		`数据文件**真的被用上**了（否则回落代码，等价性会 trivially 通过）｜usingData=${st.usingData}`);
	chk(!st.fallbackReason, `没有回落原因（实得 ${st.fallbackReason || "无"}）`);
	chk(n === RULES.length && n > 0, `生效规则条数 ${n}（代码默认 ${RULES.length}）—— 且**非零**`);
	chk(activeRules(RULES)[0] !== RULES[0], `生效规则是**数据编译出来的新对象**（不是直接拿的 RULES）`);
}
// 顺序依赖检查（**挂具抓出来的**）：没调 configure 时，evaluate 也必须能拿到 RULES
{
	const r = evaluate(EX("pwsh", { command: 'python -c "x"' }));
	chk(r.blocks.some((b) => b.id === "G01"),
		`**顺序依赖已消除**：没调 configure 时 evaluate 仍能拦 G01（实得 ${ids(r) || "空"}）`);
}

console.log();
console.log("=".repeat(76));
console.log("① **等价性**：同一批输入，数据规则 vs 代码默认，id 序列必须一字不差");
console.log("=".repeat(76));
{
	const rows = bothWays(CASES);
	let diff = 0;
	for (const [desc, code, data] of rows) {
		const same = code === data;
		if (!same) {
			diff++;
			console.log(`  [FAIL] ${desc}`);
			console.log(`         代码默认: ${code || "(空)"}`);
			console.log(`         数据规则: ${data || "(空)"}`);
		}
	}
	chk(diff === 0, `${rows.length} 个用例全部等价（不等价 ${diff} 个）`);
	const nonEmpty = rows.filter(([, c]) => c).length;
	chk(nonEmpty >= 15, `其中**有命中**的 ${nonEmpty} 个（不是全都空跑）`);
}

// ───────── ② 免重启：改数据文件后，下一次 evaluate 就应当看到最新 ─────────
console.log();
console.log("=".repeat(76));
console.log("② **免重启**：改数据文件 → 下一次 evaluate 自动看到最新");
console.log("=".repeat(76));
{
	// 先写一份"只有 G01"的最小数据
	const minimal = {
		schema: 1, rules: [{
			id: "G01", pitfall: "P02", level: "block",
			tools: ["pwsh"], when: { commandRegex: "\\bpython3?\\s+-c\\b", flags: "i" },
			why: "w", fix: "f",
		}],
	};
	writeFileSync(DATA, JSON.stringify(minimal), "utf8");
	configure({ path: DATA, fallback: RULES, shellTools: SHELL_TOOLS });
	const before = evaluate(EX("pwsh", { command: "a && b" }));      // G02 **不在**数据里 → 不该拦
	chk(before.blocks.length === 0, `改之前（数据只含 G01）：\`a && b\` **不被拦**（实得 ${ids(before) || "空"}）`);

	// 现在"升格一条规则"—— 往数据里加 G02，**不改代码、不重启**
	const grown = { ...minimal, rules: [...minimal.rules, {
		id: "G02", pitfall: "P05", level: "block", tools: ["pwsh"],
		when: { commandContains: "&&" }, why: "w", fix: "f",
	}] };
	writeFileSync(DATA, JSON.stringify(grown), "utf8");

	const after = evaluate(EX("pwsh", { command: "a && b" }));
	chk(after.blocks.some((b) => b.id === "G02"),
		`⭐ 改之后（数据里加了 G02）：\`a && b\` **被拦**（实得 ${ids(after)}）—— **没有重启、没有改代码**`);
	chk(after.blocks.length === 1 && after.blocks[0].id === "G02",
		`而且只拦 G02（G01 不命中的没被误报）`);
	const st = loaderStats();
	chk(st.reads >= 2, `加载器确实重读过（读盘次数 ${st.reads}）`);
	chk(st.usingData === true, `当前生效来源 = 数据文件`);
}

// ───────── ③ fail open：数据坏了 → 回落代码默认（不是全放行） ─────────
console.log();
console.log("=".repeat(76));
console.log("③ **fail open 到「有设防」**：数据坏 → 回落代码默认（**不是**全放行）");
console.log("=".repeat(76));
// 用辅助函数造坏数据 —— 别写内联 IIFE（**括号数不齐，`node --check` 抓了我两次**）
const mk = (name, obj) => {
	const p = join(TMP, name);
	writeFileSync(p, typeof obj === "string" ? obj : JSON.stringify(obj), "utf8");
	return p;
};
const R0 = (over = {}) => Object.assign(
	{ id: "G01", pitfall: "P02", level: "block", why: "w", fix: "f",
		tools: ["pwsh"], when: { commandContains: "x" } }, over);
const BAD = [
	["文件不存在", join(TMP, "does-not-exist.json")],
	["不是 JSON", mk("notjson.json", "{oops")],
	["schema 不认", mk("badschema.json", { schema: 99, rules: [] })],
	["rules 空数组", mk("empty.json", { schema: 1, rules: [] })],
	["规则缺 why/fix", mk("nofields.json",
		{ schema: 1, rules: [{ id: "G01", pitfall: "P02", level: "block", when: { commandContains: "x" } }] })],
	["level 非法", mk("badlevel.json", { schema: 1, rules: [R0({ level: "nope" })] })],
	["正则非法", mk("badre.json", { schema: 1, rules: [R0({ when: { commandRegex: "([unclosed" } })] })],
	["id 重复", mk("dup.json", { schema: 1, rules: [R0(), R0()] })],
];
for (const [desc, p] of BAD) {
	configure({ path: p, fallback: RULES, shellTools: SHELL_TOOLS });
	const r = evaluate(EX("pwsh", { command: 'python -c "x"' }));
	const ok = r.blocks.some((b) => b.id === "G01");
	chk(ok, `${desc} → **仍拦 G01**（回落生效，不是全放行）｜原因：${(loaderStats().fallbackReason || "").slice(0, 48)}`);
}
{
	configure({ path: "", fallback: RULES, shellTools: SHELL_TOOLS });
	chk(evaluate(EX("pwsh", { command: 'python -c "x"' })).blocks.some((b) => b.id === "G01"),
		`没配路径 → 用代码默认（**仍设防**）`);
}

// ───────── ④ G01 扩表：**能抓 + 不误抓，两边都验** ─────────
console.log();
console.log("=".repeat(76));
console.log("④ G01 扩表（覆盖内联的各形态）：**能抓 + 不误抓，两边都验**");
console.log("=".repeat(76));
{
	const firesWith = (which, cmd) => {
		configure({ path: which, fallback: RULES, shellTools: SHELL_TOOLS });
		return evaluate(EX("pwsh", { command: cmd })).blocks.some((b) => b.id === "G01");
	};
	const MUST_CATCH = [
		['python -c "print(1)"', "原来就覆盖（基础形态）"],
		['python3 -c "print(1)"', "python3"],
		['py -c "print(1)"', "**py launcher**（Windows 常见，原来漏）"],
		["python - <<EOF\nprint(1)\nEOF", "**heredoc**（原来漏）"],
		['echo "print(1)" | python', "**管道喂**（原来漏）"],
		["python -", "**从 stdin 喂**（原来漏）"],
		["py - <<EOF\nx\nEOF", "py + heredoc"],
	];
	const MUST_NOT_CATCH = [
		["python setup.py install", "正路：跑脚本"],
		["python script.py", "正路：跑脚本"],
		["python dsh-run.py zz_syntax_check.py", "正路：本项目的包装器"],
		["python -m http.server", "正路：`-m` 跑模块"],
		["python -X utf8 x.py", "正路：`-X` 是解释器开关"],
		['& "C:\\py\\python.exe" -X utf8 -B "/tmp/x.py"', "正路：绝对路径解释器 + 脚本"],
		["Get-ChildItem .", "无关命令"],
	];
	let bad = 0;
	for (const [cmd, why] of MUST_CATCH) {
		const ok = firesWith(REAL, cmd);
		if (!ok) bad++;
		chk(ok, `能抓：${JSON.stringify(cmd.slice(0, 44))} —— ${why}`);
	}
	for (const [cmd, why] of MUST_NOT_CATCH) {
		const ok = !firesWith(REAL, cmd);
		if (!ok) bad++;
		chk(ok, `不误抓：${JSON.stringify(cmd.slice(0, 44))} —— ${why}`);
	}
	chk(bad === 0, `**两边都过**（能抓 ${MUST_CATCH.length} + 不误抓 ${MUST_NOT_CATCH.length}，失败 ${bad}）`);
	// 而且**数据与代码的判据结果**必须一致（不只 id 集合一致）
	let drift = 0;
	for (const [cmd] of [...MUST_CATCH, ...MUST_NOT_CATCH]) {
		if (firesWith(REAL, cmd) !== firesWith("", cmd)) {
			drift++;
			console.log(`     ★漂了：${JSON.stringify(cmd.slice(0, 40))}`);
		}
	}
	chk(drift === 0, `数据与代码默认**判据结果一致**（漂 ${drift} 处）`);
	configure({ path: REAL, fallback: RULES, shellTools: SHELL_TOOLS });
}

// ───────── ⑤ 防漂：数据里的规则集合 = 代码里的规则集合 ─────────
console.log();
console.log("=".repeat(76));
console.log("⑤ 防漂：数据文件的规则 id 集合，必须与代码默认**完全一致**");
console.log("=".repeat(76));
{
	configure({ path: REAL, fallback: RULES, shellTools: SHELL_TOOLS });
	const dataIds = activeRules().map((r) => `${r.id}/${r.pitfall}/${r.level}`).sort();
	const codeIds = RULES.map((r) => `${r.id}/${r.pitfall}/${r.level}`).sort();
	chk(JSON.stringify(dataIds) === JSON.stringify(codeIds),
		`两边一致：数据 [${dataIds.join(" ")}]`);
	if (JSON.stringify(dataIds) !== JSON.stringify(codeIds)) {
		console.log(`         代码: [${codeIds.join(" ")}]`);
	}
	// ⚠️⚠️ **这里原来写死 `=== 8`** —— 而 2026-09-26 升格 P13（加 G51）之后它变成 9，
	//    **于是挂具自己失败了**（而"两边一致"那条是过的 —— **说明没漂，只是这个数过期了**）。
	//    ★ **这正是 P36（把会变的东西写死）的一个实例 —— 而它出现在"防漂挂具"里。**
	//    → 修法：**别写死条数，写"两边一致"**（上面那条已经在验了）。
	//      这里改成**只报数**，并把"必须 >0"作为唯一的硬条件（防"两边都是空"那种空跑通过）。
	chk(dataIds.length > 0 && dataIds.length === codeIds.length,
		`一共 ${dataIds.length} 条（代码默认也是 ${codeIds.length} 条）`
		+ ` —— **不写死条数**（写死了就会像刚才那样：升格一条规则，挂具自己先失败）`);
}
// 恢复成真实数据文件，免得影响后面的回归
configure({ path: REAL, fallback: RULES, shellTools: SHELL_TOOLS });

console.log();
console.log("=".repeat(76));
console.log(`结果：${pass} 通过 / ${fail} 失败`);
console.log("⚠️ 挂具只证代码、不证部署 —— 真实路径要等重启后 `guardrail_rules_status` 显示'生效来源=数据文件'才算数。");
console.log("=".repeat(76));
process.exit(fail === 0 ? 0 : 1);
