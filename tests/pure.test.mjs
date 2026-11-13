import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeCwd,
  normalizePorts,
  buildWorkspaceIndex,
  matchProject,
  matchWorkspaceInText,
  attributeExternalServices,
  sortExternalServices,
  parseSnapshot,
  buildActionScript,
  parseActionResult,
} from "../src/main.js";

test("normalizeCwd 统一分隔符并去掉设备前缀/尾部分隔符", () => {
  assert.equal(normalizeCwd("\\\\?\\D:/workspace/AI-Email/"), "D:\\workspace\\AI-Email");
  assert.equal(normalizeCwd("C:\\"), "C:\\");
  assert.equal(normalizeCwd(null), "");
});

test("normalizePorts 去重、过滤非法端口并按端口排序", () => {
  const ports = normalizePorts([
    { a: "0.0.0.0", p: "8918" },
    { a: "0.0.0.0", p: 8918 },
    { a: "[::]", p: 8917 },
    { a: "bad", p: 0 },
    { a: "bad", p: 70000 },
  ]);
  assert.deepEqual(ports, [
    { addr: "[::]", port: 8917 },
    { addr: "0.0.0.0", port: 8918 },
  ]);
});

test("工作区索引最长前缀优先", () => {
  const index = buildWorkspaceIndex([
    { path: "D:\\workspace" },
    { path: "D:\\workspace\\AI-Email", name: "AI-Email" },
  ]);
  assert.equal(matchProject("D:\\workspace\\AI-Email\\tools", index).name, "AI-Email");
  assert.equal(matchProject("D:\\workspace\\Other", index).name, "workspace");
  assert.equal(matchProject("E:\\elsewhere", index), null);
});

test("命令行/路径匹配有边界且最长优先", () => {
  const index = buildWorkspaceIndex([
    { path: "D:\\workspace" },
    { path: "D:\\workspace\\AI-Email", name: "AI-Email" },
  ]);
  const cmd = '"D:\\Python\\pythonw.exe" "D:\\workspace\\AI-Email\\tools\\mumu-transfer\\mumu_transfer.py"';
  assert.equal(matchWorkspaceInText(cmd, index).name, "AI-Email");
  assert.equal(matchWorkspaceInText("D:\\workspace\\AI-Email2\\tools\\x.py", index).name, "workspace");
  assert.equal(matchWorkspaceInText("D:\\workspace\\AI-Email2\\tools\\x.py", buildWorkspaceIndex([{ path: "D:\\workspace\\AI-Email" }])), null);
  assert.equal(matchWorkspaceInText("D:\\workspace\\x.py", buildWorkspaceIndex([{ path: "D:\\" }])).path, "D:\\");
  assert.equal(matchWorkspaceInText("C:\\Windows\\System32\\svchost.exe", index), null);
});

test("外部服务归属优先级 cwd > path > cmd，未归属与系统进程丢弃", () => {
  const index = buildWorkspaceIndex([{ path: "D:\\workspace\\AI-Email", name: "AI-Email" }]);
  const list = ["a", "b", "c", "d", "e"].map((key) => ({
    pid: key.charCodeAt(0),
    name: "pythonw.exe",
    cwd: "",
    path: "",
    cmd: "",
    ports: [{ addr: "0.0.0.0", port: 8917 }],
  }));
  list[0].cwd = "D:\\workspace\\AI-Email\\tools";
  list[1].path = "D:\\workspace\\AI-Email\\tools\\svc.exe";
  list[2].cmd = '"D:\\Python\\pythonw.exe" "D:\\workspace\\AI-Email\\svc.py"';
  list[3].cmd = "C:\\Windows\\System32\\notepad.exe";
  list[4].name = "svchost.exe";
  list[4].cmd = '"C:\\Windows\\System32\\svchost.exe" "D:\\workspace\\AI-Email\\x.exe"';

  const out = attributeExternalServices(list, index);
  assert.equal(out.length, 3);
  assert.equal(out[0].projectSource, "cwd");
  assert.equal(out[1].projectSource, "path");
  assert.equal(out[2].projectSource, "cmd");
  assert.ok(out.every((proc) => proc.project.name === "AI-Email"));
});

test("sortExternalServices 按项目、名称、PID 排序", () => {
  const project = { name: "AI-Email", path: "D:\\workspace\\AI-Email" };
  const sorted = sortExternalServices([
    { pid: 30, name: "b.exe", project },
    { pid: 10, name: "a.exe", project },
    { pid: 20, name: "a.exe", project },
  ]);
  assert.deepEqual(sorted.map((proc) => proc.pid), [10, 20, 30]);
});

test("parseSnapshot 兼容 external 数组/单对象/缺失", () => {
  const row = { pid: 5, ppid: 4, ppidName: "svchost.exe", name: "pythonw.exe", ports: [{ a: "0.0.0.0", p: 8917 }] };
  const single = parseSnapshot(JSON.stringify({ ts: 1, roots: [], procs: [], external: row }));
  assert.equal(single.external.length, 1);
  assert.equal(single.external[0].pid, 5);
  assert.equal(single.external[0].ppidName, "svchost.exe");
  assert.equal(single.external[0].ports[0].port, 8917);

  const missing = parseSnapshot(JSON.stringify({ ts: 1, roots: [], procs: [] }));
  assert.deepEqual(missing.external, []);
});

test("buildActionScript 用 base64 传参，不把原始命令行拼进脚本文本", () => {
  const payload = {
    action: "restart",
    pid: 1234,
    name: "pythonw.exe",
    path: "D:\\Python\\pythonw.exe",
    cmd: '"D:\\Python\\pythonw.exe" "D:\\workspace\\AI-Email\\任务.py"',
    cwd: "D:\\workspace\\AI-Email",
    created: "2026-11-12T00:00:00.0000000+08:00",
    ports: [8917],
    workspace: "D:\\workspace\\AI-Email",
    evil: "x'); Remove-Item C:\\ -Recurse; ('",
  };
  const script = buildActionScript(payload);
  const match = script.match(/FromBase64String\('([^']+)'\)/);
  assert.ok(match, "脚本应包含 base64 占位替换结果");
  const decoded = JSON.parse(Buffer.from(match[1], "base64").toString("utf8"));
  assert.deepEqual(decoded, payload);
  assert.ok(!script.includes(payload.evil));
  assert.ok(!script.includes("pythonw.exe\" \"D:"));
});

test("parseActionResult 从警告/噪声中取最后一条结果", () => {
  const ok = parseActionResult('WARNING: something\r\n{"ok":true,"action":"stop","pid":5,"newPid":0,"message":"已停止","warning":false,"ports":[]}\n');
  assert.equal(ok.ok, true);
  assert.equal(ok.action, "stop");
  assert.equal(ok.message, "已停止");

  const failed = parseActionResult('{"ok":false,"action":"restart","pid":7,"newPid":0,"message":"拒绝：PID 可能被复用","warning":false,"ports":[]}');
  assert.equal(failed.ok, false);
  assert.match(failed.message, /PID/);

  assert.equal(parseActionResult("no json here"), null);
});
