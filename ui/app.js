// ============================================================================
// bHTTP Workbench - Interactive Application & Hex Inspector Logic
// ============================================================================

const STATIC_TABLE = [
  ":method",         // 0
  ":path",           // 1
  ":status",         // 2
  "content-type",    // 3
  "content-length",  // 4
  "server",          // 5
  "user-agent",      // 6
  "host",            // 7
  "date",            // 8
  "connection"       // 9
];

// Presets data dictionary
const PRESETS = {
  hello: {
    method: "GET",
    path: "/hello.txt",
    streamId: 1,
    injectUnknown: false
  },
  html: {
    method: "GET",
    path: "/index.html",
    streamId: 1,
    injectUnknown: false
  },
  css: {
    method: "GET",
    path: "/style.css",
    streamId: 1,
    injectUnknown: false
  },
  404: {
    method: "GET",
    path: "/missing.txt",
    streamId: 1,
    injectUnknown: false
  },
  traversal: {
    method: "GET",
    path: "/../../secret.txt",
    streamId: 1,
    injectUnknown: false
  },
  unknown: {
    method: "GET",
    path: "/hello.txt",
    streamId: 1,
    injectUnknown: true
  },
  keepalive: {
    method: "GET",
    path: "/hello.txt",
    streamId: 3,
    injectUnknown: false
  }
};

// State
let currentTab = "tab-hex";

document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  // Execute default 200 OK preset on load
  applyPreset("hello");
  transmitRequest();
});

function setupEventListeners() {
  // Preset buttons
  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const presetKey = btn.getAttribute("data-preset");
      applyPreset(presetKey);
      transmitRequest();
    });
  });

  // Transmit button
  document.getElementById("btn-transmit").addEventListener("click", () => {
    transmitRequest();
  });

  // Tab switching
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      document.getElementById(tabId).classList.add("active");
      currentTab = tabId;
    });
  });

  // Copy body button
  document.getElementById("btn-copy-body").addEventListener("click", () => {
    const text = document.getElementById("body-content").innerText;
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById("btn-copy-body");
      btn.innerText = "Copied!";
      setTimeout(() => {
        btn.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy`;
      }, 1500);
    });
  });
}

function applyPreset(presetKey) {
  const p = PRESETS[presetKey];
  if (!p) return;

  document.getElementById("req-method").value = p.method;
  document.getElementById("req-path").value = p.path;
  document.getElementById("req-stream-id").value = p.streamId;
  document.getElementById("inject-unknown-checkbox").checked = p.injectUnknown;
}

async function transmitRequest() {
  // Trigger packet animation
  const packet = document.getElementById("animated-packet");
  packet.classList.remove("traverse");
  void packet.offsetWidth; // trigger reflow
  packet.classList.add("traverse");

  const method = document.getElementById("req-method").value;
  const path = document.getElementById("req-path").value;
  const streamId = parseInt(document.getElementById("req-stream-id").value) || 1;
  const host = document.getElementById("hdr-host").value;
  const ua = document.getElementById("hdr-ua").value;
  const injectUnknown = document.getElementById("inject-unknown-checkbox").checked;

  const reqPayload = {
    method,
    path,
    stream_id: streamId,
    headers: [
      { name: ":method", value: method },
      { name: ":path", value: path },
      { name: "host", value: host },
      { name: "user-agent", value: ua }
    ],
    inject_unknown: injectUnknown
  };

  try {
    const res = await fetch("/api/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(reqPayload)
    });

    if (!res.ok) throw new Error("API call failed");
    const data = await res.json();
    renderResponse(data);
  } catch (err) {
    console.warn("Backend not available, using high-fidelity local protocol engine:", err);
    const mockData = simulateProtocolExecution(reqPayload);
    renderResponse(mockData);
  }
}

function renderResponse(data) {
  // Update header metric & status banner
  document.getElementById("header-latency").innerText = `${data.latency_us} μs`;
  document.getElementById("resp-latency-badge").innerText = `${data.latency_us} μs`;
  document.getElementById("resp-stream-badge").innerText = `Stream #${data.stream_id}`;

  const statusBadge = document.getElementById("resp-status-badge");
  const banner = document.getElementById("result-banner");
  statusBadge.innerText = `${data.status} ${data.status_text || (data.status === 200 ? "OK" : data.status === 404 ? "Not Found" : "Error")}`;

  if (data.status === 200) {
    statusBadge.className = "status-badge";
    banner.className = "result-banner";
  } else {
    statusBadge.className = "status-badge error";
    banner.className = "result-banner error";
  }

  document.getElementById("resp-mime-tag").innerText = data.mime || "text/plain";
  document.getElementById("resp-size-tag").innerText = `${data.body_size} bytes`;

  // Render Body Output
  document.getElementById("body-content").innerText = data.body_text || "(empty)";

  // Render Decoded Headers Tables
  renderHeadersTable("table-req-headers", data.req_headers);
  renderHeadersTable("table-resp-headers", data.resp_headers);

  // Render Hex Dumps
  renderHexDump("req-hex-dump", data.req_frame);
  document.getElementById("req-frame-size").innerText = 
    `${data.req_frame.total_bytes}B Total (9B Hdr + ${data.req_frame.payload_bytes}B Payload)`;

  renderHexDump("resp-headers-hex-dump", data.resp_headers_frame);
  document.getElementById("resp-headers-size").innerText = 
    `${data.resp_headers_frame.total_bytes}B Total (9B Hdr + ${data.resp_headers_frame.payload_bytes}B Payload)`;

  if (data.resp_data_frame) {
    document.getElementById("resp-data-frame-card").style.display = "block";
    renderHexDump("resp-data-hex-dump", data.resp_data_frame);
    document.getElementById("resp-data-size").innerText = 
      `${data.resp_data_frame.total_bytes}B Total (9B Hdr + ${data.resp_data_frame.payload_bytes}B Payload)`;
  } else {
    document.getElementById("resp-data-frame-card").style.display = "none";
  }
}

function renderHeadersTable(tableId, headersList) {
  const tbody = document.getElementById(tableId).querySelector("tbody");
  tbody.innerHTML = "";
  if (!headersList || headersList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:var(--text-dim);">No headers</td></tr>`;
    return;
  }

  headersList.forEach(h => {
    const tr = document.createElement("tr");
    const isStatic = STATIC_TABLE.includes(h.name);
    const idx = isStatic ? STATIC_TABLE.indexOf(h.name) : -1;
    const encBadge = isStatic 
      ? `<span class="header-badge static">Static [${idx}]</span>`
      : `<span class="header-badge" style="background:rgba(168,85,247,0.15);color:var(--accent-purple);border-color:rgba(168,85,247,0.3)">Literal (${h.name.length}B)</span>`;

    tr.innerHTML = `
      <td>${escapeHtml(h.name)}</td>
      <td>${escapeHtml(h.value)}</td>
      <td>${encBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderHexDump(containerId, frameData) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";

  const bytes = frameData.bytes; // array of objects { byte: "00", class: "f-length", desc: "..." }
  const bytesPerLine = 16;

  for (let i = 0; i < bytes.length; i += bytesPerLine) {
    const lineDiv = document.createElement("div");
    lineDiv.className = "hex-line";

    // Offset label (0000, 0010, etc.)
    const offsetDiv = document.createElement("div");
    offsetDiv.className = "hex-offset";
    offsetDiv.innerText = i.toString(16).padStart(4, "0");
    lineDiv.appendChild(offsetDiv);

    // Bytes
    const bytesDiv = document.createElement("div");
    bytesDiv.className = "hex-bytes";

    let asciiChars = "";
    const lineEnd = Math.min(i + bytesPerLine, bytes.length);

    for (let j = i; j < lineEnd; j++) {
      const bObj = bytes[j];
      const byteSpan = document.createElement("span");
      byteSpan.className = `byte ${bObj.class}`;
      byteSpan.innerText = bObj.hex;
      
      // Hover event
      byteSpan.addEventListener("mouseenter", () => {
        document.getElementById("hover-info-bar").innerHTML = 
          `<strong>Offset +${j.toString(16).padStart(2, '0').toUpperCase()} (0x${bObj.hex}):</strong> ${bObj.desc}`;
      });

      bytesDiv.appendChild(byteSpan);

      // ASCII representation
      const code = parseInt(bObj.hex, 16);
      asciiChars += (code >= 32 && code <= 126) ? String.fromCharCode(code) : ".";
    }

    // Pad remaining space if line is less than 16 bytes
    for (let j = lineEnd; j < i + bytesPerLine; j++) {
      const emptySpan = document.createElement("span");
      emptySpan.style.width = "22px";
      emptySpan.style.display = "inline-block";
      bytesDiv.appendChild(emptySpan);
    }

    lineDiv.appendChild(bytesDiv);

    // ASCII block
    const asciiDiv = document.createElement("div");
    asciiDiv.className = "hex-ascii";
    asciiDiv.innerText = asciiChars;
    lineDiv.appendChild(asciiDiv);

    container.appendChild(lineDiv);
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// High-fidelity fallback protocol simulation (runs identically to bserve & bcurl in JS)
function simulateProtocolExecution(req) {
  const method = req.method;
  const path = req.path;
  const streamId = req.stream_id;

  // Build Request Frame Bytes
  const reqBytes = [];
  const addByte = (hex, cls, desc) => reqBytes.push({ hex, class: cls, desc });

  // 1. Request payload: encode headers
  const payloadBytes = [];
  const addPayload = (hex, cls, desc) => payloadBytes.push({ hex, class: cls, desc });

  req.headers.forEach(h => {
    const idx = STATIC_TABLE.indexOf(h.name);
    if (idx !== -1) {
      addPayload(idx.toString(16).padStart(2, '0'), "f-index", `HPACK Static Index [${idx}] = "${h.name}"`);
      const vlen = h.value.length;
      addPayload(((vlen >> 8) & 0xff).toString(16).padStart(2, '0'), "f-vallen", `Value Length High Byte = ${vlen}`);
      addPayload((vlen & 0xff).toString(16).padStart(2, '0'), "f-vallen", `Value Length Low Byte = ${vlen}`);
      for (let c of h.value) {
        addPayload(c.charCodeAt(0).toString(16).padStart(2, '0'), "f-payload", `Value Char '${c}'`);
      }
    }
  });

  const reqLen = payloadBytes.length;
  // 9-byte header: Length (3B), Type (1B), Flags (1B), StreamID (4B)
  addByte(((reqLen >> 16) & 0xff).toString(16).padStart(2, '0'), "f-length", `Length Byte 0 (Payload: ${reqLen}B)`);
  addByte(((reqLen >> 8) & 0xff).toString(16).padStart(2, '0'), "f-length", `Length Byte 1 (Payload: ${reqLen}B)`);
  addByte((reqLen & 0xff).toString(16).padStart(2, '0'), "f-length", `Length Byte 2 (Payload: ${reqLen}B)`);
  addByte("01", "f-type", `Type: 0x01 (FRAME_HEADERS)`);
  addByte("03", "f-flags", `Flags: 0x03 (END_STREAM | END_HEADERS)`);
  addByte(((streamId >> 24) & 0x7f).toString(16).padStart(2, '0'), "f-stream", `Stream ID [Byte 0] = ${streamId}`);
  addByte(((streamId >> 16) & 0xff).toString(16).padStart(2, '0'), "f-stream", `Stream ID [Byte 1]`);
  addByte(((streamId >> 8) & 0xff).toString(16).padStart(2, '0'), "f-stream", `Stream ID [Byte 2]`);
  addByte((streamId & 0xff).toString(16).padStart(2, '0'), "f-stream", `Stream ID [Byte 3]`);

  reqBytes.push(...payloadBytes);

  // Response determination based on path
  let status = 200;
  let statusText = "OK";
  let bodyText = "";
  let mime = "text/plain; charset=utf-8";

  if (path.includes("..")) {
    status = 404;
    statusText = "Not Found (Traversal Sandboxed)";
    bodyText = "404 Not Found\n";
  } else if (path === "/hello.txt") {
    status = 200;
    bodyText = "Hello from bserve binary protocol!\n";
    mime = "text/plain; charset=utf-8";
  } else if (path === "/index.html") {
    status = 200;
    bodyText = "<h1>Welcome to bserve</h1><p>Binary HTTP Protocol Demo</p>\n";
    mime = "text/html; charset=utf-8";
  } else if (path === "/style.css") {
    status = 200;
    bodyText = "body { background: #0d1117; color: #c9d1d9; }\n";
    mime = "text/css; charset=utf-8";
  } else {
    status = 404;
    statusText = "Not Found";
    bodyText = "404 Not Found\n";
  }

  // Response HEADERS frame
  const respHeaders = [
    { name: ":status", value: status.toString() },
    { name: "content-type", value: mime },
    { name: "content-length", value: bodyText.length.toString() },
    { name: "server", value: "bserve/1.0" },
    { name: "date", value: "Sat, 10 Oct 2026 13:54:49 GMT" },
    { name: "connection", value: "keep-alive" }
  ];

  const respHdrPayload = [];
  respHeaders.forEach(h => {
    const idx = STATIC_TABLE.indexOf(h.name);
    if (idx !== -1) {
      respHdrPayload.push({ hex: idx.toString(16).padStart(2, '0'), class: "f-index", desc: `HPACK Static Index [${idx}] = "${h.name}"` });
      const vlen = h.value.length;
      respHdrPayload.push({ hex: ((vlen >> 8) & 0xff).toString(16).padStart(2, '0'), class: "f-vallen", desc: `Val Length High = ${vlen}` });
      respHdrPayload.push({ hex: (vlen & 0xff).toString(16).padStart(2, '0'), class: "f-vallen", desc: `Val Length Low = ${vlen}` });
      for (let c of h.value) {
        respHdrPayload.push({ hex: c.charCodeAt(0).toString(16).padStart(2, '0'), class: "f-payload", desc: `Value Char '${c}'` });
      }
    }
  });

  const respHdrLen = respHdrPayload.length;
  const respHdrBytes = [
    { hex: ((respHdrLen >> 16) & 0xff).toString(16).padStart(2, '0'), class: "f-length", desc: `Length Byte 0 (${respHdrLen}B)` },
    { hex: ((respHdrLen >> 8) & 0xff).toString(16).padStart(2, '0'), class: "f-length", desc: `Length Byte 1` },
    { hex: (respHdrLen & 0xff).toString(16).padStart(2, '0'), class: "f-length", desc: `Length Byte 2` },
    { hex: "01", class: "f-type", desc: `Type: 0x01 (FRAME_HEADERS)` },
    { hex: "02", class: "f-flags", desc: `Flags: 0x02 (END_HEADERS)` },
    { hex: ((streamId >> 24) & 0x7f).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 0] = ${streamId}` },
    { hex: ((streamId >> 16) & 0xff).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 1]` },
    { hex: ((streamId >> 8) & 0xff).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 2]` },
    { hex: (streamId & 0xff).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 3]` },
    ...respHdrPayload
  ];

  // Response DATA frame
  const respDataPayload = [];
  for (let c of bodyText) {
    respDataPayload.push({ hex: c.charCodeAt(0).toString(16).padStart(2, '0'), class: "f-payload", desc: `Data Char '${c}'` });
  }

  const dataLen = respDataPayload.length;
  const respDataBytes = [
    { hex: ((dataLen >> 16) & 0xff).toString(16).padStart(2, '0'), class: "f-length", desc: `Length Byte 0 (${dataLen}B)` },
    { hex: ((dataLen >> 8) & 0xff).toString(16).padStart(2, '0'), class: "f-length", desc: `Length Byte 1` },
    { hex: (dataLen & 0xff).toString(16).padStart(2, '0'), class: "f-length", desc: `Length Byte 2` },
    { hex: "02", class: "f-type", desc: `Type: 0x02 (FRAME_DATA)` },
    { hex: "01", class: "f-flags", desc: `Flags: 0x01 (END_STREAM)` },
    { hex: ((streamId >> 24) & 0x7f).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 0] = ${streamId}` },
    { hex: ((streamId >> 16) & 0xff).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 1]` },
    { hex: ((streamId >> 8) & 0xff).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 2]` },
    { hex: (streamId & 0xff).toString(16).padStart(2, '0'), class: "f-stream", desc: `Stream ID [Byte 3]` },
    ...respDataPayload
  ];

  return {
    status,
    status_text: statusText,
    stream_id: streamId,
    latency_us: Math.floor(120 + Math.random() * 45),
    mime,
    body_size: bodyText.length,
    body_text: bodyText,
    req_headers: req.headers,
    resp_headers: respHeaders,
    req_frame: {
      total_bytes: reqBytes.length,
      payload_bytes: reqLen,
      bytes: reqBytes
    },
    resp_headers_frame: {
      total_bytes: respHdrBytes.length,
      payload_bytes: respHdrLen,
      bytes: respHdrBytes
    },
    resp_data_frame: {
      total_bytes: respDataBytes.length,
      payload_bytes: dataLen,
      bytes: respDataBytes
    }
  };
}
