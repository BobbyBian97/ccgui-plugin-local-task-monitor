// 本机任务监控 —— CC GUI 插件（Tier-1，单文件 ESM，无 import / JSX）
//
// 右侧聊天面板新增「本机任务」页签：以 ccgui 主进程为根扫描子孙进程，
// 关联它们正在监听的 TCP 端口，展示 PID / 命令行 / CPU / 内存 / 运行时长。
// 只读，不提供终止操作。数据源为本机 powershell.exe：
//   Get-CimInstance Win32_Process（进程树与命令行）+ netstat -ano（监听端口）
//   + PEB 读取进程工作目录（cwd），再用 ctx.workspaces.list() 做最长前缀匹配，
//     把每个进程归属到侧栏里的项目/工作区。
// 仅在面板打开时轮询（默认 5 秒，可调，可切「手动」），窗口隐藏时跳过采集。
// 配置（面板工具栏 + 插件设置页，激活闭包内同步）：
//   刷新间隔 / 项目归属（读取 cwd，可关）/ 是否显示应用内部进程。

const STORAGE_INTERVAL = "local-task-monitor/interval-ms";
const STORAGE_SHOW_INTERNAL = "local-task-monitor/show-internal";
const STORAGE_PROJECT = "local-task-monitor/project-attribution";
const DEFAULT_INTERVAL_MS = 5000;
// 0 = 手动刷新（只在点击「刷新」时采集一次）。
const MANUAL_INTERVAL_MS = 0;
const INTERVAL_OPTIONS = [MANUAL_INTERVAL_MS, 2000, 5000, 10000, 30000, 60000];

function intervalLabel(ms) {
  return ms > 0 ? ms / 1000 + " 秒" : "手动";
}
// 采集进程自身的命令行里带这个标记，用于把它从结果里剔除。
const PROBE_MARKER = "CCGUI_TASK_MONITOR_PROBE";
// 应用自身的基础设施进程，默认折叠（可手动打开查看）。
const INTERNAL_NAMES = new Set([
  "msedgewebview2.exe",
  "conhost.exe",
  "crashpad_handler.exe",
  "werfault.exe",
  "runtimebroker.exe",
]);

const PS_SCRIPT = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$marker = 'CCGUI_TASK_MONITOR_PROBE'
# 读取进程工作目录：PEB -> ProcessParameters(+0x20) -> CurrentDirectory.DosPath(+0x38)。
# Add-Type 每次调用都要编译（约 300ms）；失败时 cwd 留空，其余采集照常。
# 项目归属关闭时跳过整段编译与读取（占位符由宿主侧替换为 $true/$false）。
$cwdEnabled = __CCGUI_CWD_ENABLED__
$cwdRead = $false
if ($cwdEnabled) {
  try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class CcguiCwdReader
{
    [StructLayout(LayoutKind.Sequential)]
    private struct PBI
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, ref PBI pbi, int pbiSize, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, int size, out IntPtr bytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static string Get(int pid)
    {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            PBI pbi = new PBI();
            int ret;
            int status = NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf(pbi), out ret);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return null;

            byte[] pointer = new byte[8];
            IntPtr read;
            if (!ReadProcessMemory(h, (IntPtr)((long)pbi.PebBaseAddress + 0x20), pointer, 8, out read)) return null;
            long parameters = BitConverter.ToInt64(pointer, 0);
            if (parameters == 0) return null;

            byte[] unicode = new byte[16];
            if (!ReadProcessMemory(h, (IntPtr)(parameters + 0x38), unicode, 16, out read)) return null;
            ushort length = BitConverter.ToUInt16(unicode, 0);
            long buffer = BitConverter.ToInt64(unicode, 8);
            if (length == 0 || length > 4096 || buffer == 0) return null;

            byte[] text = new byte[length];
            if (!ReadProcessMemory(h, (IntPtr)buffer, text, length, out read)) return null;
            return Encoding.Unicode.GetString(text);
        }
        finally
        {
            CloseHandle(h);
        }
    }
}
'@
    $cwdRead = $true
  } catch {
    $cwdRead = $false
  }
}
$all = @(Get-CimInstance Win32_Process)
$roots = @($all | Where-Object { $_.Name -match '(?i)^ccgui' })
$portsByPid = @{}
netstat -ano -p TCP | ForEach-Object {
  if ($_ -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$') {
    $opid = [int]$Matches[3]
    if (-not $portsByPid.ContainsKey($opid)) {
      $portsByPid[$opid] = New-Object System.Collections.ArrayList
    }
    [void]$portsByPid[$opid].Add([pscustomobject]@{ a = $Matches[1]; p = [int]$Matches[2] })
  }
}
$ids = New-Object System.Collections.Generic.HashSet[int]
foreach ($r in $roots) { [void]$ids.Add([int]$r.ProcessId) }
$desc = New-Object System.Collections.ArrayList
$added = $true
while ($added) {
  $added = $false
  foreach ($proc in $all) {
    $parentPid = [int]$proc.ParentProcessId
    $procPid = [int]$proc.ProcessId
    if ($ids.Contains($parentPid) -and -not $ids.Contains($procPid)) {
      [void]$ids.Add($procPid)
      [void]$desc.Add($proc)
      $added = $true
    }
  }
}
$rows = @()
foreach ($proc in $desc) {
  if ([string]$proc.CommandLine -like ('*' + $marker + '*')) { continue }
  $procPid = [int]$proc.ProcessId
  $portList = @()
  if ($portsByPid.ContainsKey($procPid)) { $portList = @($portsByPid[$procPid]) }
  $created = $null
  if ($proc.CreationDate) { $created = $proc.CreationDate.ToString('o') }
  $cwd = ''
  if ($cwdRead) {
    try { $cwd = [string][CcguiCwdReader]::Get($procPid) } catch { $cwd = '' }
  }
  $rows += [pscustomobject]@{
    pid = $procPid
    ppid = [int]$proc.ParentProcessId
    name = [string]$proc.Name
    path = [string]$proc.ExecutablePath
    cmd = [string]$proc.CommandLine
    cwd = $cwd
    ws = [long]$proc.WorkingSetSize
    cpu = [double]($proc.KernelModeTime + $proc.UserModeTime)
    created = $created
    ports = $portList
  }
}
$rootRows = @()
foreach ($r in $roots) {
  $rootRows += [pscustomobject]@{
    pid = [int]$r.ProcessId
    name = [string]$r.Name
    path = [string]$r.ExecutablePath
  }
}
$snap = [pscustomobject]@{
  ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  roots = $rootRows
  procs = $rows
}
$snap | ConvertTo-Json -Compress -Depth 6
`;

// ---- 数据规范化 ----

function toFiniteNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

// Windows 路径规范化：统一反斜杠、去掉 \\?\ 前缀与末尾分隔符（盘符根 C:\ 保留）。
function normalizeCwd(value) {
  if (typeof value !== "string") return "";
  let text = value.trim().replace(/\//g, "\\");
  if (text.startsWith("\\\\?\\")) text = text.slice(4);
  if (text.startsWith("\\??\\")) text = text.slice(4);
  if (text.length > 3) text = text.replace(/\\+$/, "");
  return text;
}

function normalizePorts(raw) {
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const seen = new Set();
  const out = [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    const port = Number(item.p);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) continue;
    const addr = typeof item.a === "string" ? item.a : "";
    const key = addr + ":" + port;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ addr, port });
  }
  out.sort((a, b) => a.port - b.port || a.addr.localeCompare(b.addr));
  return out;
}

function normalizeProcess(raw) {
  if (!raw || typeof raw !== "object") return null;
  const pid = Number(raw.pid);
  if (!Number.isInteger(pid) || pid <= 0) return null;
  return {
    pid,
    ppid: Number(raw.ppid) || 0,
    name: typeof raw.name === "string" ? raw.name : "",
    path: typeof raw.path === "string" ? raw.path : "",
    cmd: typeof raw.cmd === "string" ? raw.cmd : "",
    cwd: normalizeCwd(raw.cwd),
    ws: toFiniteNumber(raw.ws),
    cpu: toFiniteNumber(raw.cpu),
    created: typeof raw.created === "string" ? raw.created : "",
    ports: normalizePorts(raw.ports),
  };
}

function normalizeRoot(raw) {
  if (!raw || typeof raw !== "object") return null;
  const pid = Number(raw.pid);
  if (!Number.isInteger(pid) || pid <= 0) return null;
  return {
    pid,
    name: typeof raw.name === "string" ? raw.name : "",
    path: typeof raw.path === "string" ? raw.path : "",
  };
}

// ---- 项目归属 ----
// ctx.workspaces.list() 的行结构随宿主版本略有差异，按已知字段做防御性读取。

function workspacePathOf(row) {
  if (!row || typeof row !== "object") return "";
  const candidates = [row.path, row.workspacePath, row.rootPath, row.folder];
  for (const item of candidates) {
    if (typeof item === "string" && item.trim()) return normalizeCwd(item);
  }
  return "";
}

function workspaceNameOf(row, path) {
  const candidates = [row.name, row.title, row.label, row.customName];
  for (const item of candidates) {
    if (typeof item === "string" && item.trim()) return item.trim();
  }
  const parts = path.split("\\").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : path;
}

function buildWorkspaceIndex(rows) {
  const out = [];
  const seen = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    const path = workspacePathOf(row);
    if (!path) continue;
    const key = path.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    let branch = "";
    if (row.worktree && typeof row.worktree === "object" && typeof row.worktree.branch === "string") {
      branch = row.worktree.branch;
    }
    out.push({ key, path, name: workspaceNameOf(row, path), branch });
  }
  // 最长前缀优先：worktree 路径通常比主仓库更长，先匹配到更具体的项目。
  out.sort((a, b) => b.key.length - a.key.length);
  return out;
}

function matchProject(cwd, index) {
  if (!cwd || !index || index.length === 0) return null;
  const key = cwd.toLowerCase();
  for (const workspace of index) {
    if (key === workspace.key) return workspace;
    if (workspace.key.endsWith("\\")) {
      if (key.startsWith(workspace.key)) return workspace;
    } else if (key.startsWith(workspace.key + "\\")) {
      return workspace;
    }
  }
  return null;
}

function projectLabel(project) {
  if (!project) return "";
  return project.branch ? project.name + "（" + project.branch + "）" : project.name;
}

// cwd 不在任何工作区（如 adb、系统工具）时，沿父进程链继承最近的项目归属；
// 继承来的归属在 UI 上用虚线徽标区分，避免与 cwd 直接命中混淆。
function applyProjectInheritance(procs) {
  const byPid = new Map();
  for (const proc of procs) byPid.set(proc.pid, proc);
  const resolved = new Map();
  for (const proc of procs) {
    if (proc.project) {
      resolved.set(proc.pid, proc.project);
      continue;
    }
    let found = null;
    let current = byPid.get(proc.ppid);
    const chain = [proc];
    const seen = new Set([proc.pid]);
    let guard = 0;
    while (current && guard < 64) {
      if (current.project) {
        found = current.project;
        break;
      }
      if (resolved.has(current.pid)) {
        found = resolved.get(current.pid);
        break;
      }
      chain.push(current);
      seen.add(current.pid);
      const parentId = current.ppid;
      if (!parentId || parentId === current.pid || seen.has(parentId)) break;
      current = byPid.get(parentId);
      guard += 1;
    }
    for (const item of chain) resolved.set(item.pid, found);
    if (found) {
      proc.project = found;
      proc.projectInherited = true;
    }
  }
}

// 工作区快照失败（宿主无权限/旧版本）时返回 null，面板降级为不显示项目，不影响进程采集。
async function fetchWorkspaceRows(ctx) {
  try {
    if (!ctx.workspaces || typeof ctx.workspaces.list !== "function") return null;
    const rows = await ctx.workspaces.list();
    return Array.isArray(rows) ? rows : [];
  } catch {
    return null;
  }
}

function parseSnapshot(stdout) {
  const text = String(stdout || "").replace(/^\uFEFF/, "").trim();
  if (!text) throw new Error("采集命令没有输出");
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error("采集结果不是 JSON：" + text.slice(0, 200));
  }
  if (!payload || typeof payload !== "object") throw new Error("采集结果为空");
  const procsRaw = Array.isArray(payload.procs) ? payload.procs : payload.procs ? [payload.procs] : [];
  const rootsRaw = Array.isArray(payload.roots) ? payload.roots : payload.roots ? [payload.roots] : [];
  const procs = [];
  for (const item of procsRaw) {
    const proc = normalizeProcess(item);
    if (proc) procs.push(proc);
  }
  const roots = [];
  for (const item of rootsRaw) {
    const root = normalizeRoot(item);
    if (root) roots.push(root);
  }
  return { ts: toFiniteNumber(payload.ts) || Date.now(), roots, procs };
}

function isInternalProcess(proc) {
  const name = String(proc.name || "").toLowerCase();
  if (INTERNAL_NAMES.has(name)) return true;
  return String(proc.cmd || "").includes(PROBE_MARKER);
}

// 按进程树排序；被折叠的中间父进程（WebView 等）视为透明，向上找最近的可见祖先。
function orderProcesses(procs, showInternal) {
  const allByPid = new Map();
  for (const proc of procs) allByPid.set(proc.pid, proc);
  const visible = procs.filter((proc) => showInternal || !isInternalProcess(proc));
  const byPid = new Map();
  for (const proc of visible) byPid.set(proc.pid, proc);

  const children = new Map();
  const roots = [];
  for (const proc of visible) {
    let parentId = proc.ppid;
    let guard = 0;
    while (parentId && !byPid.has(parentId) && guard < 64) {
      const parent = allByPid.get(parentId);
      if (!parent) break;
      parentId = parent.ppid;
      guard += 1;
    }
    const parent = parentId && parentId !== proc.pid ? byPid.get(parentId) : null;
    if (!parent) {
      roots.push(proc);
    } else {
      if (!children.has(parent.pid)) children.set(parent.pid, []);
      children.get(parent.pid).push(proc);
    }
  }

  const byName = (a, b) => String(a.name).localeCompare(String(b.name), "zh-CN") || a.pid - b.pid;
  roots.sort(byName);
  for (const list of children.values()) list.sort(byName);

  const out = [];
  const visited = new Set();
  const walk = (proc, depth) => {
    if (visited.has(proc.pid) || depth > 32) return;
    visited.add(proc.pid);
    out.push({ proc, depth });
    for (const child of children.get(proc.pid) || []) walk(child, depth + 1);
  };
  for (const root of roots) walk(root, 0);
  for (const proc of visible) {
    if (!visited.has(proc.pid)) walk(proc, 0);
  }
  return out;
}

// CPU 百分比 = 两次采样间 CPU 时间增量 / 墙钟增量 / 逻辑核数。
function computeCpuById(snapshot, previous) {
  if (!previous) return {};
  const wallSec = (snapshot.ts - previous.ts) / 1000;
  if (!(wallSec > 0.2) || wallSec > 120) return {};
  const cores = Math.max(1, Number(navigator.hardwareConcurrency) || 8);
  const out = {};
  for (const proc of snapshot.procs) {
    const old = previous.ticks.get(proc.pid);
    if (old === undefined) continue;
    const deltaSec = (proc.cpu - old) / 1e7; // 100ns ticks → 秒
    if (!(deltaSec >= 0)) continue;
    const pct = (deltaSec / wallSec / cores) * 100;
    out[proc.pid] = Math.min(100, Math.max(0, pct));
  }
  return out;
}

// ---- 展示工具 ----

function displayName(name) {
  return String(name || "").replace(/\.exe$/i, "") || "未知进程";
}

function formatMemory(bytes) {
  const mb = toFiniteNumber(bytes) / (1024 * 1024);
  if (mb >= 1024) return (mb / 1024).toFixed(2) + " GB";
  if (mb >= 100) return mb.toFixed(0) + " MB";
  return mb.toFixed(1) + " MB";
}

function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return sec + " 秒";
  const min = Math.floor(sec / 60);
  if (min < 60) return min + " 分" + (sec % 60 ? " " + (sec % 60) + " 秒" : "");
  const hour = Math.floor(min / 60);
  if (hour < 24) return hour + " 小时 " + (min % 60) + " 分";
  return Math.floor(hour / 24) + " 天 " + (hour % 24) + " 小时";
}

function formatClock(ts) {
  try {
    return new Date(ts).toLocaleTimeString("zh-CN", { hour12: false });
  } catch {
    return "—";
  }
}

function formatDateTime(value) {
  const ts = Date.parse(value);
  if (!Number.isFinite(ts)) return "—";
  try {
    return new Date(ts).toLocaleString("zh-CN", { hour12: false });
  } catch {
    return "—";
  }
}

function uniquePortNumbers(ports) {
  const seen = new Set();
  const out = [];
  for (const item of ports || []) {
    if (seen.has(item.port)) continue;
    seen.add(item.port);
    out.push(item.port);
  }
  return out;
}

function portsDetail(ports) {
  if (!ports || ports.length === 0) return "";
  return ports.map((item) => (item.addr ? item.addr : "*") + ":" + item.port).join("，");
}

function matchesQuery(proc, query) {
  if (!query) return true;
  const ports = (proc.ports || []).map((item) => String(item.port)).join(" ");
  const project = proc.project ? proc.project.name + " " + proc.project.branch + " " + proc.project.path : "";
  const haystack = (proc.name + " " + proc.pid + " " + proc.cmd + " " + proc.path + " " + proc.cwd + " " + project + " " + ports).toLowerCase();
  return haystack.includes(query);
}

// ---- 样式（宿主语义 token，明暗主题自适应） ----

const TEXT_PRIMARY = "var(--color-text-primary)";
const TEXT_SECONDARY = "var(--color-text-secondary)";
const TEXT_TERTIARY = "var(--color-text-tertiary)";
const TEXT_ERROR = "var(--color-text-error-primary)";
const TEXT_SUCCESS = "var(--color-notification-success-foreground)";
const BORDER = "1px solid var(--color-border-button-default)";

const S = {
  root: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
    height: "100%",
    minHeight: 0,
    padding: "12px 12px 0",
    boxSizing: "border-box",
    fontSize: 12,
    lineHeight: 1.45,
    color: TEXT_PRIMARY,
  },
  titleRow: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" },
  titleLeft: { display: "flex", alignItems: "baseline", gap: 8, minWidth: 0, flex: 1, overflow: "hidden" },
  title: { fontSize: 13, fontWeight: 700, whiteSpace: "nowrap" },
  rootChip: {
    fontSize: 11,
    color: TEXT_SECONDARY,
    display: "inline-flex",
    alignItems: "center",
    gap: 5,
    minWidth: 0,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
  },
  dot: { width: 6, height: 6, borderRadius: 999, background: "currentColor", flex: "none" },
  titleRight: { display: "flex", alignItems: "center", gap: 6, flex: "none" },
  busyText: { fontSize: 11, color: TEXT_TERTIARY },
  button: {
    font: "inherit",
    padding: "3px 8px",
    borderRadius: 6,
    border: BORDER,
    background: "var(--color-background-secondary-default)",
    color: TEXT_PRIMARY,
    cursor: "pointer",
  },
  buttonActive: {
    font: "inherit",
    padding: "3px 8px",
    borderRadius: 6,
    border: "1px solid var(--color-text-tertiary)",
    background: "var(--color-background-primary-default)",
    color: TEXT_PRIMARY,
    cursor: "pointer",
  },
  stats: { display: "flex", gap: 6 },
  stat: {
    flex: 1,
    minWidth: 0,
    padding: "6px 8px",
    borderRadius: 6,
    border: BORDER,
    background: "var(--color-background-secondary-default)",
  },
  statLabel: { fontSize: 10, color: TEXT_TERTIARY, whiteSpace: "nowrap" },
  statValue: { fontSize: 13, fontWeight: 600, fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" },
  toolbar: { display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" },
  search: {
    flex: "1 1 160px",
    minWidth: 0,
    font: "inherit",
    padding: "4px 8px",
    borderRadius: 6,
    border: BORDER,
    background: "var(--color-background-primary-default)",
    color: TEXT_PRIMARY,
    outline: "none",
  },
  select: {
    font: "inherit",
    padding: "4px 6px",
    borderRadius: 6,
    border: BORDER,
    background: "var(--color-background-secondary-default)",
    color: TEXT_PRIMARY,
    cursor: "pointer",
  },
  scroll: { flex: 1, minHeight: 0, overflowY: "auto", overflowX: "hidden", paddingBottom: 8 },
  list: { border: BORDER, borderRadius: 8, overflow: "hidden", background: "var(--color-background-secondary-default)" },
  rowWrap: { borderTop: BORDER },
  rowWrapFirst: { borderTop: "none" },
  row: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "7px 10px",
    cursor: "pointer",
    boxSizing: "border-box",
  },
  rowMain: { flex: 1, minWidth: 0 },
  rowTitle: { display: "flex", alignItems: "center", gap: 6, minWidth: 0, overflow: "hidden" },
  branch: { color: TEXT_TERTIARY, fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace", flex: "none" },
  procName: { fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 180, minWidth: 0 },
  pid: { color: TEXT_TERTIARY, fontSize: 10, flex: "none", fontVariantNumeric: "tabular-nums" },
  projectChip: {
    fontSize: 10,
    padding: "0 5px",
    borderRadius: 4,
    border: BORDER,
    background: "var(--color-background-primary-default)",
    color: TEXT_SECONDARY,
    maxWidth: 110,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    flex: "none",
  },
  projectChipInherited: {
    fontSize: 10,
    padding: "0 5px",
    borderRadius: 4,
    border: "1px dashed var(--color-border-button-default)",
    background: "transparent",
    color: TEXT_TERTIARY,
    maxWidth: 110,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    flex: "none",
  },
  portChip: {
    fontSize: 10,
    padding: "0 5px",
    borderRadius: 4,
    border: BORDER,
    background: "var(--color-background-primary-default)",
    color: TEXT_SECONDARY,
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
    flex: "none",
  },
  moreChip: { fontSize: 10, color: TEXT_TERTIARY, flex: "none" },
  cmdLine: {
    marginTop: 1,
    color: TEXT_TERTIARY,
    fontSize: 11,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
  },
  metrics: { display: "flex", alignItems: "center", gap: 8, flex: "none" },
  metric: {
    minWidth: 52,
    textAlign: "right",
    color: TEXT_SECONDARY,
    fontVariantNumeric: "tabular-nums",
    whiteSpace: "nowrap",
  },
  metricMem: { minWidth: 64, textAlign: "right", color: TEXT_SECONDARY, fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" },
  detail: {
    padding: "2px 10px 10px",
    borderTop: "1px dashed var(--color-border-button-default)",
    background: "var(--color-background-primary-default)",
  },
  detailGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 12px", paddingTop: 8 },
  detailLabel: { fontSize: 10, color: TEXT_TERTIARY },
  detailValue: { fontSize: 11, color: TEXT_SECONDARY, wordBreak: "break-all" },
  cmdLabel: { fontSize: 10, color: TEXT_TERTIARY, marginTop: 8 },
  cmdBox: {
    marginTop: 2,
    fontSize: 11,
    color: TEXT_SECONDARY,
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
    maxHeight: 120,
    overflowY: "auto",
    background: "var(--color-background-secondary-default)",
    border: BORDER,
    borderRadius: 6,
    padding: "6px 8px",
  },
  error: {
    display: "flex",
    alignItems: "flex-start",
    gap: 8,
    padding: "7px 9px",
    borderRadius: 6,
    border: "1px solid var(--color-text-error-primary)",
    background: "var(--color-background-secondary-default)",
    color: TEXT_ERROR,
    fontSize: 11,
  },
  errorText: { flex: 1, minWidth: 0, wordBreak: "break-word" },
  empty: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: 6,
    padding: 24,
    textAlign: "center",
    color: TEXT_TERTIARY,
  },
  emptyTitle: { fontSize: 13, fontWeight: 600, color: TEXT_SECONDARY },
  footer: {
    display: "flex",
    justifyContent: "space-between",
    gap: 8,
    flexWrap: "wrap",
    padding: "6px 0 8px",
    fontSize: 10,
    color: TEXT_TERTIARY,
    borderTop: BORDER,
  },
};

// 设置页样式（host 设置页默认字号偏小，这里用 12–13px 与面板保持一致）。
const SET = {
  root: { display: "flex", flexDirection: "column", gap: 10, fontSize: 13, color: TEXT_PRIMARY, maxWidth: 680 },
  card: {
    display: "flex",
    alignItems: "center",
    gap: 16,
    padding: "12px 14px",
    borderRadius: 8,
    border: BORDER,
    background: "var(--color-background-secondary-default)",
  },
  cardMain: { flex: 1, minWidth: 0 },
  cardTitle: { fontSize: 13, fontWeight: 600 },
  cardDesc: { marginTop: 3, fontSize: 11, lineHeight: 1.55, color: TEXT_TERTIARY },
  cardControl: { flex: "none", display: "flex", alignItems: "center" },
  select: {
    font: "inherit",
    fontSize: 12,
    padding: "4px 6px",
    borderRadius: 6,
    border: BORDER,
    background: "var(--color-background-primary-default)",
    color: TEXT_PRIMARY,
    cursor: "pointer",
  },
  checkbox: { width: 16, height: 16, margin: 0, cursor: "pointer", accentColor: TEXT_PRIMARY },
  note: {
    padding: "10px 12px",
    borderRadius: 8,
    border: "1px dashed var(--color-border-button-default)",
    fontSize: 11,
    lineHeight: 1.7,
    color: TEXT_SECONDARY,
  },
  noteTitle: { fontWeight: 600, color: TEXT_PRIMARY, marginBottom: 2 },
  noteLine: { color: TEXT_SECONDARY },
};

export default function activate(ctx) {
  const { createElement: h, useState, useEffect, useMemo, useRef } = ctx.react;
  const supported = !ctx.host.isWeb && /Windows/i.test(String(navigator.userAgent || ""));

  // 配置广播：面板与设置页各自挂载，但同属一次激活闭包，用本地订阅者集合同步。
  // （宿主 ctx.events 在面板/设置页之间不保证送达，实测不可靠，故不用。）
  const configListeners = new Set();
  const CONFIG_EVENT = "local-task-monitor/config-changed";

  function emitConfig(patch) {
    for (const listener of Array.from(configListeners)) {
      try {
        listener(patch);
      } catch {
        // 单个订阅者出错不影响其它订阅者。
      }
    }
  }

  function subscribeConfig(handler) {
    configListeners.add(handler);
    return () => {
      configListeners.delete(handler);
    };
  }

  function TaskIcon(props) {
    return h(
      "svg",
      {
        width: 16,
        height: 16,
        viewBox: "0 0 24 24",
        fill: "none",
        stroke: "currentColor",
        strokeWidth: 2,
        strokeLinecap: "round",
        strokeLinejoin: "round",
        className: props && props.className,
      },
      h("path", { d: "M3 12h4l2.5-7 5 14 2.5-7h4" })
    );
  }

  // 宿主的面板页签条默认只画注册的 icon（label 仅作 title/无障碍名）；
  // 且会隐藏 icon 里的 HTML 文本，所以把图标和名称画进同一个 SVG 里。
  function TaskTabLabel(props) {
    return h(
      "svg",
      {
        width: 94,
        height: 16,
        viewBox: "0 0 94 16",
        fill: "none",
        className: props && props.className,
        style: { flexShrink: 0, width: 94, height: 16 },
        "aria-hidden": "true",
      },
      h(
        "g",
        {
          transform: "scale(0.667)",
          stroke: "currentColor",
          strokeWidth: 2,
          strokeLinecap: "round",
          strokeLinejoin: "round",
        },
        h("path", { d: "M3 12h4l2.5-7 5 14 2.5-7h4" })
      ),
      h(
        "text",
        {
          x: 25,
          y: 8,
          fill: "currentColor",
          fontSize: 12,
          fontFamily: "system-ui, -apple-system, 'Segoe UI', sans-serif",
          dominantBaseline: "central",
        },
        "CC GUI 任务"
      )
    );
  }

  function TaskPanel() {
    const [snapshot, setSnapshot] = useState(null);
    const [cpuById, setCpuById] = useState({});
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const [paused, setPaused] = useState(false);
    const [intervalMs, setIntervalMs] = useState(DEFAULT_INTERVAL_MS);
    const [showInternal, setShowInternal] = useState(false);
    const [projectEnabled, setProjectEnabled] = useState(true);
    const [onlyPorts, setOnlyPorts] = useState(false);
    const [query, setQuery] = useState("");
    const [expandedPid, setExpandedPid] = useState(null);
    const [reloadNonce, setReloadNonce] = useState(0);
    const [projectUnavailable, setProjectUnavailable] = useState(false);

    const previousRef = useRef(null);

    useEffect(() => {
      let alive = true;
      Promise.resolve(ctx.storage.get(STORAGE_INTERVAL))
        .then((value) => {
          if (!alive) return;
          // 空值不能走 Number()（Number(null) === 0，会误判成「手动」）。
          if (value === null || value === undefined || value === "") return;
          const n = Number(value);
          if (INTERVAL_OPTIONS.includes(n)) setIntervalMs(n);
        })
        .catch(() => {});
      Promise.resolve(ctx.storage.get(STORAGE_SHOW_INTERNAL))
        .then((value) => {
          if (!alive) return;
          if (typeof value === "boolean") setShowInternal(value);
        })
        .catch(() => {});
      Promise.resolve(ctx.storage.get(STORAGE_PROJECT))
        .then((value) => {
          if (!alive) return;
          if (typeof value === "boolean") setProjectEnabled(value);
        })
        .catch(() => {});
      return () => {
        alive = false;
      };
    }, []);

    // 设置页/工具栏任一处的改动都通过宿主事件总线同步到另一处。
    useEffect(() => subscribeConfig(applyConfigPatch), []);

    function applyConfigPatch(patch) {
      if (!patch || typeof patch !== "object") return;
      if (typeof patch.intervalMs === "number" && INTERVAL_OPTIONS.includes(patch.intervalMs)) {
        setIntervalMs(patch.intervalMs);
        if (patch.intervalMs === MANUAL_INTERVAL_MS) setPaused(false);
      }
      if (typeof patch.showInternal === "boolean") setShowInternal(patch.showInternal);
      if (typeof patch.projectEnabled === "boolean") setProjectEnabled(patch.projectEnabled);
    }

    useEffect(() => {
      if (!supported) return undefined;
      let alive = true;
      let timer = null;
      let inFlight = false;

      const schedule = (delay) => {
        if (!alive || paused || intervalMs === MANUAL_INTERVAL_MS) return;
        timer = setTimeout(poll, delay);
      };

      const onVisibilityChange = () => {
        if (!alive || paused || intervalMs === MANUAL_INTERVAL_MS) return;
        if (document.visibilityState !== "visible") return;
        if (timer) clearTimeout(timer);
        poll();
      };

      async function poll() {
        if (!alive) return;
        if (document.visibilityState === "hidden") {
          schedule(intervalMs);
          return;
        }
        if (inFlight) return;
        inFlight = true;
        setBusy(true);
        try {
          const script = PS_SCRIPT.replace("__CCGUI_CWD_ENABLED__", projectEnabled ? "$true" : "$false");
          const [res, workspaceRows] = await Promise.all([
            ctx.bridge.invoke("plugin_exec_run", {
              bin: "powershell",
              args: ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
              timeoutMs: 15000,
            }),
            projectEnabled ? fetchWorkspaceRows(ctx) : Promise.resolve(undefined),
          ]);
          if (!alive) return;
          if (!res || typeof res !== "object") throw new Error("执行通道没有返回结果");
          const code = Number(res.code);
          if (code !== 0) {
            const stderr = typeof res.stderr === "string" ? res.stderr.trim() : "";
            throw new Error(
              stderr ? "PowerShell 退出码 " + code + "：" + stderr.slice(0, 300) : "PowerShell 退出码 " + code
            );
          }
          const next = parseSnapshot(res.stdout);
          const workspaceIndex = projectEnabled && workspaceRows ? buildWorkspaceIndex(workspaceRows) : null;
          if (workspaceIndex && workspaceIndex.length) {
            for (const proc of next.procs) proc.project = matchProject(proc.cwd, workspaceIndex);
            applyProjectInheritance(next.procs);
          }
          setProjectUnavailable(projectEnabled && workspaceRows === null);
          const cpu = computeCpuById(next, previousRef.current);
          const ticks = new Map();
          for (const proc of next.procs) ticks.set(proc.pid, proc.cpu);
          previousRef.current = { ts: next.ts, ticks };
          setCpuById(cpu);
          setSnapshot(next);
          setError("");
        } catch (err) {
          if (!alive) return;
          const message = err && err.message ? String(err.message) : String(err);
          setError(message || "采集失败");
        } finally {
          inFlight = false;
          if (alive) setBusy(false);
          schedule(intervalMs);
        }
      }

      document.addEventListener("visibilitychange", onVisibilityChange);
      poll();

      return () => {
        alive = false;
        if (timer) clearTimeout(timer);
        document.removeEventListener("visibilitychange", onVisibilityChange);
      };
    }, [supported, paused, intervalMs, projectEnabled, reloadNonce]);

    const ordered = useMemo(() => orderProcesses(snapshot ? snapshot.procs : [], showInternal), [snapshot, showInternal]);

    const rows = useMemo(() => {
      const q = query.trim().toLowerCase();
      return ordered.filter(({ proc }) => {
        if (onlyPorts && proc.ports.length === 0) return false;
        if (q && !matchesQuery(proc, q)) return false;
        return true;
      });
    }, [ordered, onlyPorts, query]);

    const summary = useMemo(() => {
      const visible = snapshot ? snapshot.procs.filter((proc) => showInternal || !isInternalProcess(proc)) : [];
      let portCount = 0;
      let memory = 0;
      let cpu = 0;
      for (const proc of visible) {
        memory += proc.ws;
        cpu += Number(cpuById[proc.pid]) || 0;
        portCount += uniquePortNumbers(proc.ports).length;
      }
      return { count: visible.length, ports: portCount, memory, cpu: Math.min(100, cpu) };
    }, [snapshot, showInternal, cpuById]);

    const roots = snapshot ? snapshot.roots : [];
    const hasCpu = Object.keys(cpuById).length > 0;
    const rootLabel = roots.length
      ? roots.map((root) => displayName(root.name) + " · PID " + root.pid).join(" / ")
      : "未发现 CC GUI 主进程";

    const refresh = () => setReloadNonce((n) => n + 1);

    const refreshText = paused
      ? "自动刷新已暂停"
      : intervalMs === MANUAL_INTERVAL_MS
        ? "手动刷新 · 仅显示 CC GUI 进程树"
        : "每 " + Math.round(intervalMs / 1000) + " 秒刷新 · 仅显示 CC GUI 进程树";
    const projectText = !projectEnabled
      ? " · 项目归属已关闭"
      : projectUnavailable
        ? " · 项目归属不可用"
        : "";

    const changeInterval = (event) => {
      const next = Number(event.target.value);
      if (!INTERVAL_OPTIONS.includes(next)) return;
      setIntervalMs(next);
      if (next === MANUAL_INTERVAL_MS) setPaused(false);
      Promise.resolve(ctx.storage.set(STORAGE_INTERVAL, next)).catch(() => {});
      emitConfig({ intervalMs: next });
    };

    const toggleShowInternal = () => {
      const next = !showInternal;
      setShowInternal(next);
      Promise.resolve(ctx.storage.set(STORAGE_SHOW_INTERNAL, next)).catch(() => {});
      emitConfig({ showInternal: next });
    };

    const toggleProject = () => {
      const next = !projectEnabled;
      setProjectEnabled(next);
      Promise.resolve(ctx.storage.set(STORAGE_PROJECT, next)).catch(() => {});
      emitConfig({ projectEnabled: next });
    };

    const openSettings = () => {
      try {
        ctx.ui.openSettings("monitor");
      } catch {
        // 设置页注册失败时忽略（面板功能不受影响）。
      }
    };

    const statTile = (label, value) =>
      h(
        "div",
        { style: S.stat, key: label },
        h("div", { style: S.statLabel }, label),
        h("div", { style: S.statValue }, value)
      );

    const detailItem = (label, value, key) =>
      h(
        "div",
        { style: { minWidth: 0 }, key: key || label },
        h("div", { style: S.detailLabel }, label),
        h("div", { style: S.detailValue }, value)
      );

    if (!supported) {
      return h(
        "div",
        { style: S.root },
        h(
          "div",
          { style: S.empty },
          h("div", { style: S.emptyTitle }, "需要 Windows 桌面端"),
          h("div", null, "本插件通过 PowerShell 采集本机进程树，Web 端或非 Windows 平台不可用。")
        )
      );
    }

    const listContent = [];
    if (snapshot) {
      for (let i = 0; i < rows.length; i += 1) {
        const { proc, depth } = rows[i];
        const cpu = cpuById[proc.pid];
        const isExpanded = expandedPid === proc.pid;
        const shownPorts = uniquePortNumbers(proc.ports);
        listContent.push(
          h(
            "div",
            { key: proc.pid, style: i === 0 ? S.rowWrapFirst : S.rowWrap },
            h(
              "div",
              {
                style: { ...S.row, paddingLeft: 10 + depth * 16 },
                onClick: () => setExpandedPid(isExpanded ? null : proc.pid),
                title: isExpanded ? "收起详情" : "展开详情",
              },
              h(
                "div",
                { style: S.rowMain },
                h(
                  "div",
                  { style: S.rowTitle },
                  depth > 0 ? h("span", { style: S.branch }, "└") : null,
                  h("span", { style: { ...S.dot, color: proc.ports.length ? TEXT_SUCCESS : TEXT_TERTIARY, background: "currentColor" } }),
                  h("span", { style: S.procName }, displayName(proc.name)),
                  h("span", { style: S.pid }, "PID " + proc.pid),
                  proc.project
                    ? h(
                        "span",
                        {
                          style: proc.projectInherited ? S.projectChipInherited : S.projectChip,
                          title:
                            (proc.projectInherited ? "继承自上级进程 · 项目：" : "所属项目：") + proc.project.path,
                        },
                        projectLabel(proc.project)
                      )
                    : null,
                  shownPorts.slice(0, 3).map((port) => h("span", { key: port, style: S.portChip }, ":" + port)),
                  shownPorts.length > 3 ? h("span", { style: S.moreChip }, "+" + (shownPorts.length - 3)) : null
                ),
                h("div", { style: S.cmdLine }, proc.cmd || proc.path || "—")
              ),
              h(
                "div",
                { style: S.metrics },
                h("span", { style: S.metric }, cpu === undefined ? "—" : cpu.toFixed(1) + "%"),
                h("span", { style: S.metricMem }, formatMemory(proc.ws))
              )
            ),
            isExpanded
              ? h(
                  "div",
                  { style: S.detail },
                  h(
                    "div",
                    { style: S.detailGrid },
                    detailItem(
                      "所属项目",
                      proc.project
                        ? projectLabel(proc.project) + (proc.projectInherited ? "（继承自上级进程）" : "")
                        : proc.cwd
                          ? "未匹配侧栏工作区"
                          : "未知（工作目录不可读）",
                      "project"
                    ),
                    detailItem("工作目录", proc.cwd || "—", "cwd"),
                    detailItem("父进程", "PID " + proc.ppid),
                    detailItem("已运行", proc.created ? formatDuration(snapshot.ts - Date.parse(proc.created)) : "—"),
                    detailItem("启动时间", formatDateTime(proc.created)),
                    detailItem("可执行文件", proc.path || "—"),
                    detailItem("监听端口", portsDetail(proc.ports) || "未监听", "ports"),
                    detailItem("CPU 时间", (proc.cpu / 1e7).toFixed(1) + " 秒", "cputime")
                  ),
                  h("div", { style: S.cmdLabel }, "命令行"),
                  h("div", { style: S.cmdBox }, proc.cmd || "—")
                )
              : null
          )
        );
      }
    }

    let emptyView = null;
    if (!snapshot && !error) {
      emptyView = h(
        "div",
        { style: S.empty },
        h("div", { style: S.emptyTitle }, busy ? "正在采集…" : "等待采集"),
        h("div", null, "首次打开面板时会启动一次本机进程扫描。")
      );
    } else if (snapshot && rows.length === 0) {
      const filtered = query.trim() || onlyPorts;
      emptyView = h(
        "div",
        { style: S.empty },
        h("div", { style: S.emptyTitle }, filtered ? "没有匹配的任务" : "暂无本地任务"),
        h(
          "div",
          null,
          filtered
            ? "试试清空搜索或关闭「仅服务」过滤。"
            : "CC GUI 启动 CLI 会话、脚本或服务后，进程会出现在这里。"
        )
      );
    }

    return h(
      "div",
      { style: S.root },
      h(
        "div",
        { style: S.titleRow },
        h(
          "div",
          { style: S.titleLeft },
          h("span", { style: S.title }, "CC GUI 任务"),
          h(
            "span",
            { style: { ...S.rootChip, color: roots.length ? TEXT_SUCCESS : TEXT_TERTIARY } },
            h("span", { style: S.dot }),
            rootLabel
          )
        ),
        h(
          "div",
          { style: S.titleRight },
          busy ? h("span", { style: S.busyText }, "采集中…") : null,
          h("button", { style: S.button, onClick: refresh, disabled: busy, title: "立即刷新" }, "刷新"),
          intervalMs === MANUAL_INTERVAL_MS
            ? null
            : h(
                "button",
                {
                  style: paused ? S.buttonActive : S.button,
                  onClick: () => setPaused((value) => !value),
                  title: paused ? "继续自动刷新" : "暂停自动刷新",
                },
                paused ? "继续" : "暂停"
              ),
          h("button", { style: S.button, onClick: openSettings, title: "打开插件设置" }, "设置")
        )
      ),
      h(
        "div",
        { style: S.stats },
        statTile("任务", String(summary.count)),
        statTile("监听端口", String(summary.ports)),
        statTile("CPU", snapshot && hasCpu ? summary.cpu.toFixed(1) + "%" : "—"),
        statTile("内存", formatMemory(summary.memory))
      ),
      h(
        "div",
        { style: S.toolbar },
        h("input", {
          style: S.search,
          value: query,
          placeholder: "搜索名称 / PID / 端口 / 命令行",
          onChange: (event) => setQuery(event.target.value),
          spellCheck: false,
        }),
        h(
          "select",
          { style: S.select, value: String(intervalMs), onChange: changeInterval, title: "自动刷新间隔（手动 = 只在点击刷新时采集）" },
          INTERVAL_OPTIONS.map((ms) => h("option", { key: ms, value: String(ms) }, intervalLabel(ms)))
        ),
        h(
          "button",
          {
            style: projectEnabled ? S.buttonActive : S.button,
            onClick: toggleProject,
            title: "项目归属：读取进程工作目录并匹配侧栏工作区；关闭可降低采集开销",
          },
          "项目"
        ),
        h(
          "button",
          { style: onlyPorts ? S.buttonActive : S.button, onClick: () => setOnlyPorts((value) => !value), title: "只看监听端口的进程" },
          "仅服务"
        ),
        h(
          "button",
          { style: showInternal ? S.buttonActive : S.button, onClick: toggleShowInternal, title: "显示 WebView / conhost 等应用内部进程" },
          "内部进程"
        )
      ),
      error
        ? h(
            "div",
            { style: S.error },
            h("span", { style: S.errorText }, error),
            h("button", { style: S.button, onClick: refresh, disabled: busy }, "重试")
          )
        : null,
      h("div", { style: S.scroll }, emptyView || h("div", { style: S.list }, listContent)),
      h(
        "div",
        { style: S.footer },
        h("span", null, snapshot ? "更新于 " + formatClock(snapshot.ts) : "等待首次采集"),
        h("span", null, refreshText + projectText)
      )
    );
  }

  function SettingsSection() {
    const [intervalMs, setIntervalMs] = useState(DEFAULT_INTERVAL_MS);
    const [projectEnabled, setProjectEnabled] = useState(true);
    const [showInternal, setShowInternal] = useState(false);

    useEffect(() => {
      let alive = true;
      Promise.all([
        Promise.resolve(ctx.storage.get(STORAGE_INTERVAL)).catch(() => null),
        Promise.resolve(ctx.storage.get(STORAGE_PROJECT)).catch(() => null),
        Promise.resolve(ctx.storage.get(STORAGE_SHOW_INTERNAL)).catch(() => null),
      ]).then(([interval, project, internal]) => {
        if (!alive) return;
        if (interval !== null && interval !== undefined && interval !== "") {
          const n = Number(interval);
          if (INTERVAL_OPTIONS.includes(n)) setIntervalMs(n);
        }
        if (typeof project === "boolean") setProjectEnabled(project);
        if (typeof internal === "boolean") setShowInternal(internal);
      });
      return () => {
        alive = false;
      };
    }, []);

    useEffect(() => subscribeConfig(applyPatch), []);

    function applyPatch(patch) {
      if (!patch || typeof patch !== "object") return;
      if (typeof patch.intervalMs === "number" && INTERVAL_OPTIONS.includes(patch.intervalMs)) {
        setIntervalMs(patch.intervalMs);
      }
      if (typeof patch.projectEnabled === "boolean") setProjectEnabled(patch.projectEnabled);
      if (typeof patch.showInternal === "boolean") setShowInternal(patch.showInternal);
    }

    const changeIntervalSetting = (event) => {
      const next = Number(event.target.value);
      if (!INTERVAL_OPTIONS.includes(next)) return;
      setIntervalMs(next);
      Promise.resolve(ctx.storage.set(STORAGE_INTERVAL, next)).catch(() => {});
      emitConfig({ intervalMs: next });
    };

    const changeProject = (event) => {
      const next = !!event.target.checked;
      setProjectEnabled(next);
      Promise.resolve(ctx.storage.set(STORAGE_PROJECT, next)).catch(() => {});
      emitConfig({ projectEnabled: next });
    };

    const changeInternal = (event) => {
      const next = !!event.target.checked;
      setShowInternal(next);
      Promise.resolve(ctx.storage.set(STORAGE_SHOW_INTERNAL, next)).catch(() => {});
      emitConfig({ showInternal: next });
    };

    const settingCard = (key, title, description, control) =>
      h(
        "div",
        { style: SET.card, key },
        h(
          "div",
          { style: SET.cardMain },
          h("div", { style: SET.cardTitle }, title),
          h("div", { style: SET.cardDesc }, description)
        ),
        h("div", { style: SET.cardControl }, control)
      );

    return h(
      "div",
      { style: SET.root },
      settingCard(
        "interval",
        "自动刷新间隔",
        "面板打开时按此间隔采集本机进程。手动 = 只在点击「刷新」或重新打开面板时采集一次。",
        h(
          "select",
          { style: SET.select, value: String(intervalMs), onChange: changeIntervalSetting },
          INTERVAL_OPTIONS.map((ms) => h("option", { key: ms, value: String(ms) }, intervalLabel(ms)))
        )
      ),
      settingCard(
        "project",
        "项目归属",
        "读取每个进程的工作目录，匹配侧栏工作区并显示所属项目。关闭后每次采集约省 0.3 秒，也不再读取其他进程内存。",
        h("input", { type: "checkbox", style: SET.checkbox, checked: projectEnabled, onChange: changeProject })
      ),
      settingCard(
        "internal",
        "显示应用内部进程",
        "在任务列表中显示 WebView、conhost、crashpad 等 CC GUI 自身的基础设施进程。",
        h("input", { type: "checkbox", style: SET.checkbox, checked: showInternal, onChange: changeInternal })
      ),
      h(
        "div",
        { style: SET.note, key: "tips" },
        h("div", { style: SET.noteTitle }, "建议"),
        h("div", { style: SET.noteLine }, "· 日常监控用 10 秒；正在排查服务时用 2–5 秒。"),
        h("div", { style: SET.noteLine }, "· 长时间挂着、笔记本省电或远程连接时，用 30–60 秒或「手动」。"),
        h("div", { style: SET.noteLine }, "· 窗口隐藏、面板关闭或手动模式下完全不会采集。"),
        h("div", { style: SET.noteLine }, "· 项目归属默认开启；对终端安全策略敏感的环境可关闭。")
      )
    );
  }

  ctx.ui.registerPanelTab({
    key: "monitor",
    label: () => "CC GUI 任务",
    icon: TaskTabLabel,
    component: TaskPanel,
    order: 30,
  });

  try {
    if (ctx.ui && typeof ctx.ui.registerSettingsSection === "function") {
      ctx.ui.registerSettingsSection({
        key: "monitor",
        label: () => "本机任务监控",
        icon: TaskIcon,
        component: SettingsSection,
      });
    }
  } catch {
    // 设置页不可用时面板与工具栏配置仍然可用。
  }

  // 一次性激活标记：便于排查插件是否真的被宿主加载（不参与界面逻辑）。
  Promise.resolve(ctx.storage.set("local-task-monitor/activated-at", Date.now())).catch(() => {});
}
