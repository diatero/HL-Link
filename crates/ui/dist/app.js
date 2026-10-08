if (!window.__TAURI__) {
  document.body.innerHTML =
    '<div style="padding:40px;color:#e03131;font-size:15px">Tauri API 未注入：请确认 tauri.conf.json 已开启 withGlobalTauri 并重新构建。</div>';
  throw new Error("__TAURI__ is not available");
}
const { invoke } = window.__TAURI__.core;
const { open } = window.__TAURI__.dialog;
const { listen } = window.__TAURI__.event;

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

function fmtSize(n) {
  if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GiB";
  if (n >= 1048576) return (n / 1048576).toFixed(1) + " MiB";
  if (n >= 1024) return (n / 1024).toFixed(1) + " KiB";
  return n + " B";
}

let toastTimer;
function toast(msg, isError = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.style.background = isError ? "#c92a2a" : "#1c2333";
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 3500);
}

async function safe(label, fn) {
  try {
    return await fn();
  } catch (e) {
    toast(`${label}: ${e}`, true);
    throw e;
  }
}

// —— 标签页 ——
$$(".tab").forEach((btn) =>
  btn.addEventListener("click", () => {
    $$(".tab").forEach((b) => b.classList.remove("active"));
    $$(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`#tab-${btn.dataset.tab}`).classList.add("active");
  })
);

// —— 设备 ——
async function refreshDevices() {
  const devices = await invoke("get_devices");
  const el = $("#device-list");
  if (!devices.length) {
    el.innerHTML = `<div class="empty">尚未配对任何设备。<br>点击「附近配对」，并先在手机 App 上点「添加设备」。</div>`;
    return;
  }
  el.innerHTML = devices
    .map(
      (d) => `
    <div class="card">
      <div class="avatar">${d.name.slice(0, 1).toUpperCase()}</div>
      <div class="info">
        <div class="title">${escapeHtml(d.name)}${d.revoked ? "（信任已失效）" : ""}</div>
        <div class="sub">${d.node_id.slice(0, 16)}… · ${escapeHtml(d.last_addr)}</div>
      </div>
      <button class="danger" data-remove="${d.node_id}">删除</button>
    </div>`
    )
    .join("");
  el.querySelectorAll("[data-remove]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("删除后需要重新配对；请同时在手机上解除对这台电脑的信任。")) return;
      await safe("删除失败", () => invoke("remove_device", { nodeId: b.dataset.remove }));
      refreshDevices();
    })
  );
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// —— 附近配对（两阶段）——
const pairModal = $("#pair-modal");

$("#btn-pair-near").addEventListener("click", async () => {
  pairModal.classList.remove("hidden");
  $("#pair-code-box").classList.add("hidden");
  $("#pair-error").classList.add("hidden");
  $("#pair-status").textContent = "正在扫描附近设备…（请先在手机上点「添加设备」）";
  try {
    const r = await invoke("pair_near_start", { scanSecs: 12 });
    $("#pair-status").textContent = `发现「${r.label}」`;
    $("#pair-sas").textContent = r.sas;
    $("#pair-code-box").classList.remove("hidden");
  } catch (e) {
    $("#pair-status").classList.add("hidden");
    const err = $("#pair-error");
    err.textContent = String(e);
    err.classList.remove("hidden");
  }
});

$("#btn-pair-confirm").addEventListener("click", async () => {
  $("#btn-pair-confirm").disabled = true;
  $("#pair-status").textContent = "等待手机端确认…（请在手机上批准）";
  try {
    const name = await invoke("pair_near_confirm");
    pairModal.classList.add("hidden");
    toast(`已与「${name}」配对成功`);
    refreshDevices();
  } catch (e) {
    pairModal.classList.add("hidden");
    toast(`配对失败: ${e}`, true);
  } finally {
    $("#btn-pair-confirm").disabled = false;
  }
});

$("#btn-pair-cancel").addEventListener("click", async () => {
  await invoke("pair_near_cancel").catch(() => {});
  pairModal.classList.add("hidden");
});

$("#btn-pair-import").addEventListener("click", async () => {
  const file = await open({ multiple: false, filters: [{ name: "配对信息", extensions: ["json", "txt", "*"] }] });
  if (!file) return;
  const json = await fetch(file).then((r) => r.text()).catch(() => null);
  if (json == null) {
    // WebView 无法直接读本地文件路径时，走 Rust 读文件
    const content = await invoke("read_pairing_file", { path: file }).catch((e) => { toast(String(e), true); return null; });
    if (content == null) return;
    return doImport(content);
  }
  doImport(json);
});

async function doImport(json) {
  await safe("导入配对失败", async () => {
    const name = await invoke("import_pairing", { json });
    toast(`已与「${name}」配对成功（请删除导出文件）`);
    refreshDevices();
  });
}

// —— 接收 ——
async function refreshPulls() {
  const pulls = await invoke("get_pulls");
  const pending = pulls.filter((p) => p.state === "pending");
  const badge = $("#pull-count");
  badge.textContent = pending.length;
  badge.classList.toggle("hidden", pending.length === 0);
  const el = $("#pull-list");
  if (!pulls.length) {
    el.innerHTML = `<div class="empty">暂无接收记录。<br>手机发来的文件会出现在这里，接受前不会传输任何数据。</div>`;
    return;
  }
  el.innerHTML = pulls
    .map(
      (p) => `
    <div class="card">
      <div class="avatar">↓</div>
      <div class="info">
        <div class="title">${escapeHtml(p.name)}</div>
        <div class="sub">来自 ${escapeHtml(p.node_name)} · ${fmtSize(p.size)}</div>
      </div>
      <span class="state ${p.state}">${stateText(p.state)}</span>
      ${p.state === "pending" ? `
        <button class="primary" data-accept="${p.transfer_id}">接收</button>
        <button class="danger" data-deny="${p.transfer_id}">拒绝</button>` : ""}
    </div>`
    )
    .join("");
  el.querySelectorAll("[data-accept]").forEach((b) =>
    b.addEventListener("click", async () => {
      b.disabled = true;
      b.textContent = "传输中…";
      await safe("接收失败", () => invoke("accept_pull", { transferId: b.dataset.accept }));
      refreshPulls();
    })
  );
  el.querySelectorAll("[data-deny]").forEach((b) =>
    b.addEventListener("click", async () => {
      await safe("操作失败", () => invoke("deny_pull", { transferId: b.dataset.deny }));
      refreshPulls();
    })
  );
}

function stateText(s) {
  return { pending: "待确认", accepted: "传输中", completed: "已完成", denied: "已拒绝", cancelled: "已取消", queued: "排队中", sending: "发送中", failed: "失败" }[s] || s;
}

// —— 发送 ——
$("#btn-send-files").addEventListener("click", async () => {
  const files = await open({ multiple: true });
  if (!files || (Array.isArray(files) && !files.length)) return;
  await safe("发送失败", () => invoke("send_files", { paths: Array.isArray(files) ? files : [files] }));
  toast("已加入发送队列");
  refreshSends();
});

$("#btn-send-text").addEventListener("click", async () => {
  const text = $("#text-input").value.trim();
  if (!text) return;
  await safe("发送失败", () => invoke("send_text", { text }));
  $("#text-input").value = "";
  toast("已发送");
  refreshSends();
});

async function refreshSends() {
  const sends = await invoke("get_sends");
  const el = $("#send-list");
  if (!sends.length) {
    el.innerHTML = `<div class="empty">暂无发送记录。任务由后台 Agent 串行执行，断线自动续传。</div>`;
    return;
  }
  el.innerHTML = sends
    .map(
      (s) => `
    <div class="card">
      <div class="avatar">↑</div>
      <div class="info">
        <div class="title">${escapeHtml(s.name)}</div>
        <div class="sub">${fmtSize(s.size)}${s.error ? " · " + escapeHtml(s.error) : ""}</div>
      </div>
      <span class="state ${s.state}">${stateText(s.state)}</span>
    </div>`
    )
    .join("");
}

// —— 设置 ——
$("#btn-save-name").addEventListener("click", async () => {
  const v = $("#name-input").value.trim();
  await safe("保存失败", () => invoke("set_name", { name: v || null }));
  toast("已保存，下次连接时同步到手机");
});
$("#btn-reset-name").addEventListener("click", async () => {
  $("#name-input").value = "";
  await safe("操作失败", () => invoke("set_name", { name: null }));
  toast("已恢复跟随系统名称");
});

// —— 轮询与初始化 ——
async function tick() {
  try {
    const running = await invoke("daemon_running");
    const badge = $("#daemon-badge");
    badge.textContent = running ? "Agent 运行中" : "Agent 未运行（直连模式）";
    badge.className = "badge " + (running ? "on" : "off");
    await Promise.all([refreshDevices(), refreshPulls(), refreshSends()]);
  } catch (_) {}
}

listen("pair-done", (e) => toast(`配对完成：${e.payload}`));

tick();
setInterval(tick, 2000);
invoke("get_name").then((r) => {
  $("#name-input").value = r.custom ? r.name : "";
  $("#name-input").placeholder = `跟随系统名称（${r.name}）`;
});
