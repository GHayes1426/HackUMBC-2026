// Close / Reopen port buttons, live refresh, and notifications.
//
// Each button carries data-kind ("close" | "reopen") and data-port. Clicking
// POSTs to app.py's /api/ports/<port>/<kind>. The backend triggers the OS's
// admin prompt (macOS password / Windows UAC), so the request can take a
// while. Afterwards refresh() re-fetches "/" (which re-runs every check) and
// swaps in the new <main>, so the page updates in place without a reload.
// Results and errors appear as toasts in #toasts, fixed on screen so
// they're seen wherever the user has scrolled to.

const ICONS = { success: "✓", info: "…", warning: "!", error: "×" };
const STATUS_TAGS = { warning: "RISK", review: "REVIEW", info: "IN USE", ok: "SAFE", error: "UNKNOWN" };
const STATUS_ICONS = { warning: "!", review: "?", info: "i", ok: "✓", error: "–" };
let activeAssistantAudio;
let assistantSpeechGenerating = false;
const AGENT_PAIRING_STORAGE_KEY = "portAPottyAgentDeviceId";
const AGENT_PACKAGE_STORAGE_KEY = "portAPottyAgentPackageId";
const AGENT_COLLAPSED_STORAGE_KEY = "portAPottyAgentSetupCollapsed";

function setReadAloudButtonsDisabled(disabled, label = "Read aloud with ElevenLabs") {
  document.querySelectorAll(".assistant-read-answer").forEach((button) => {
    button.disabled = disabled;
    button.textContent = disabled ? label : "Read aloud with ElevenLabs";
  });
}

function stopAssistantVoice() {
  if (activeAssistantAudio) {
    activeAssistantAudio.pause();
    URL.revokeObjectURL(activeAssistantAudio.src);
    activeAssistantAudio = undefined;
  }
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
  assistantSpeechGenerating = false;
  setReadAloudButtonsDisabled(false);
  const stop = document.getElementById("assistant-stop-voice");
  if (stop) stop.disabled = true;
}

function toast(message, level = "info") {
  const el = document.createElement("div");
  el.className = `toast ${level}`;
  el.setAttribute("role", level === "error" || level === "warning" ? "alert" : "status");

  const icon = document.createElement("span");
  icon.className = "toast-icon";
  icon.textContent = ICONS[level];
  const text = document.createElement("span");
  text.className = "toast-text";
  text.textContent = message;
  const close = document.createElement("button");
  close.type = "button";
  close.className = "toast-close";
  close.setAttribute("aria-label", "Dismiss");
  close.textContent = "×";
  close.addEventListener("click", () => el.remove());

  el.append(icon, text, close);
  document.getElementById("toasts").append(el);
  // Successes fade on their own; problems stay until dismissed.
  if (level === "success") setTimeout(() => el.remove(), 6000);
  return el;
}

async function refresh() {
  const main = document.getElementById("dashboard");
  main.classList.add("refreshing");
  try {
    const response = await fetch("/", { cache: "no-store" });
    if (!response.ok) throw new Error(`Rescan failed (${response.status})`);
    const page = new DOMParser().parseFromString(await response.text(), "text/html");
    main.replaceChildren(...page.getElementById("dashboard").childNodes);
    window.portAPottyRefreshHelper?.();
  } finally {
    main.classList.remove("refreshing");
  }
}

async function portAction(button) {
  const { kind, port } = button.dataset;
  if (kind === "close" && !confirm(
    `Close port ${port}?\n\nA firewall rule will block connections to it. ` +
    `If a program you use needs this port, it will stop working until you reopen it here.`
  )) return;

  button.disabled = true;
  button.textContent = kind === "close" ? "Closing…" : "Reopening…";
  const waiting = toast("Waiting for administrator approval. Approve the password or permission prompt on this computer.", "info");

  let data;
  try {
    const response = await fetch(`/api/ports/${port}/${kind}`, {
      method: "POST",
      headers: { "X-Dashboard": "1" },
    });
    data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  } catch (err) {
    waiting.remove();
    const reason = err instanceof TypeError ? "Can't reach the dashboard server. Is app.py running?" : err.message;
    toast(`Couldn't ${kind} port ${port}: ${reason}`, "error");
    await refresh().catch(() => {});
    return;
  }

  waiting.remove();
  try {
    await refresh();
  } catch (err) {
    toast(err.message, "error");
  }
  toast(data.message, data.level || "success");
}

async function saveDetectionSettings(form) {
  const values = Object.fromEntries(new FormData(form));
  const payload = Object.fromEntries(Object.entries(values).map(([name, value]) => [name, Number(value)]));
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const response = await fetch("/api/settings/detection", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Dashboard": "1" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Couldn't save thresholds");
    await refresh();
    toast("Detection thresholds saved and scan refreshed.", "success");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function saveLogSource(select) {
  select.disabled = true;
  try {
    const response = await fetch("/api/settings/log-source", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Dashboard": "1" },
      body: JSON.stringify({ source: select.value }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Couldn't change log source");
    await refresh();
    toast("Log source changed and scan refreshed.", "success");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    select.disabled = false;
  }
}

async function uploadLog(form) {
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const response = await fetch("/api/logs/upload", {
      method: "POST", headers: { "X-Dashboard": "1" }, body: new FormData(form),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Couldn't upload log");
    await refresh();
    toast(`${data.name} is selected and being analyzed.`, "success");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    button.disabled = false;
  }
}

document.addEventListener("click", (event) => {
  if (event.target.closest("#assistant-stop-voice")) {
    stopAssistantVoice();
    return;
  }
  const button = event.target.closest(".port-action");
  if (button) {
    portAction(button);
    return;
  }
  if (event.target.closest("#rescan")) {
    event.preventDefault();
    refresh()
      .then(() => toast("Rescan complete.", "success"))
      .catch((err) => toast(err.message, "error"));
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("#detection-settings");
  if (form) { event.preventDefault(); saveDetectionSettings(form); return; }
  const upload = event.target.closest("#log-upload");
  if (upload) { event.preventDefault(); uploadLog(upload); }
});

document.addEventListener("change", (event) => {
  const select = event.target.closest("#log-source");
  if (select) saveLogSource(select);
});

function addAssistantMessage(text, role = "assistant") {
  const messages = document.getElementById("assistant-messages");
  if (!messages) return;
  const isAnswer = role === "assistant-answer";
  const message = document.createElement(isAnswer ? "div" : "p");
  message.className = `assistant-message ${role}`;
  if (isAnswer) {
    const content = document.createElement("span");
    content.textContent = text;
    const read = document.createElement("button");
    read.type = "button";
    read.className = "assistant-read-answer";
    read.textContent = "Read aloud with ElevenLabs";
    read.addEventListener("click", () => {
      window.portAPottyVoiceEnabled = true;
      speakAssistantAnswer(text);
    });
    message.append(content, read);
  } else {
    message.textContent = text;
  }
  messages.append(message);
  messages.scrollTop = messages.scrollHeight;
  return message;
}

async function speakAssistantAnswer(text) {
  if (!window.portAPottyVoiceEnabled) return;
  if (assistantSpeechGenerating || activeAssistantAudio) {
    toast("A response is already being read aloud.", "info");
    return;
  }
  window.portAPottySetVoiceState?.("responding", "Responding with ElevenLabs…");
  assistantSpeechGenerating = true;
  setReadAloudButtonsDisabled(true);
  try {
    const response = await fetch("/api/assistant/speak", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!response.ok) throw new Error("ElevenLabs voice unavailable");
    activeAssistantAudio = new Audio(URL.createObjectURL(await response.blob()));
    setReadAloudButtonsDisabled(true, "Voice is playing…");
    const stop = document.getElementById("assistant-stop-voice");
    if (stop) stop.disabled = false;
    activeAssistantAudio.addEventListener("ended", stopAssistantVoice, { once: true });
    await activeAssistantAudio.play();
    await new Promise((resolve) => activeAssistantAudio.addEventListener("ended", resolve, { once: true }));
  } catch {
    stopAssistantVoice();
    toast("ElevenLabs voice is unavailable. The response is available as text.", "error");
  }
}

async function askAssistant(form) {
  const input = form.querySelector("#assistant-input");
  const question = input.value.trim();
  if (!question) return;
  const submit = form.querySelector("button[type=submit]");
  addAssistantMessage(question, "user");
  const pending = addAssistantMessage("Port a Potty is analyzing the findings…", "assistant pending");
  window.portAPottySetVoiceState?.("thinking", "Thinking with Gemini…");
  input.value = "";
  submit.disabled = true;
  try {
    const response = await fetch("/api/assistant", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question,
        helper_package_id: localStorage.getItem(AGENT_PACKAGE_STORAGE_KEY) || undefined,
        helper_device_id: localStorage.getItem(AGENT_PAIRING_STORAGE_KEY) || undefined,
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "The assistant could not respond.");
    pending.remove();
    addAssistantMessage(data.answer, "assistant-answer");
    if (data.fallback) addAssistantMessage("Using Port a Potty's built-in analysis while Gemini is unavailable.", "assistant fallback");
    await speakAssistantAnswer(data.answer);
    window.portAPottyResumeSpeechMode?.();
  } catch (err) {
    pending.remove();
    addAssistantMessage(err.message, "assistant error");
    window.portAPottyResumeSpeechMode?.();
  } finally {
    submit.disabled = false;
    input.focus();
  }
}

function setupVoiceInput() {
  const button = document.getElementById("assistant-talk");
  const dictate = document.getElementById("assistant-dictate");
  const textMode = document.getElementById("assistant-text-mode");
  const input = document.getElementById("assistant-input");
  const form = document.getElementById("assistant-form");
  const voiceStatus = document.getElementById("assistant-voice-status");
  const voiceIndicator = document.getElementById("assistant-voice-indicator");
  const voiceState = document.getElementById("assistant-voice-state");
  const canRecord = Boolean(navigator.mediaDevices?.getUserMedia && window.MediaRecorder);
  let stream, recorder, monitor, audioContext, speechMode = false;
  let dictationStream, dictationRecorder;
  window.portAPottyVoiceEnabled = false;
  if (!button || !dictate || !input || !canRecord) {
    button.textContent = "Voice unavailable";
    button.disabled = true;
    if (dictate) dictate.disabled = true;
    return;
  }
  const setStatus = (message) => { if (voiceStatus) voiceStatus.textContent = message; };
  const setVoiceState = (state, label) => {
    if (!voiceIndicator || !voiceState) return;
    voiceIndicator.hidden = !speechMode;
    voiceIndicator.dataset.state = state;
    voiceState.textContent = label;
  };
  const setModeControls = (active) => {
    button.hidden = active;
    dictate.hidden = active;
    textMode.hidden = !active;
    textMode.disabled = !active;
  };
  function stopMonitor() {
    clearInterval(monitor);
    audioContext?.close();
    audioContext = undefined;
  }
  async function toggleDictation() {
    if (dictationRecorder?.state === "recording") {
      dictationRecorder.stop();
      return;
    }
    try {
      setStatus("Requesting microphone permission for text dictation…");
      dictationStream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const chunks = [];
      dictationRecorder = new MediaRecorder(dictationStream);
      dictationRecorder.ondataavailable = (event) => { if (event.data.size) chunks.push(event.data); };
      dictationRecorder.onstop = async () => {
        dictationStream.getTracks().forEach((track) => track.stop());
        dictate.classList.remove("recording");
        dictate.textContent = "Dictate text with ElevenLabs";
        dictate.disabled = true;
        try {
          setStatus("Transcribing your dictated text with ElevenLabs…");
          const data = new FormData();
          data.append("audio", new Blob(chunks, { type: dictationRecorder.mimeType || "audio/webm" }), "dictation.webm");
          const response = await fetch("/api/assistant/transcribe", { method: "POST", body: data });
          const result = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(result.error || "Could not transcribe the recording.");
          input.value = result.text;
          input.focus();
          setStatus("Dictation is ready. Edit it or press Send.");
        } catch (err) {
          toast(err.message, "error");
          setStatus("Text mode is on. Type a question below.");
        } finally {
          dictate.disabled = false;
        }
      };
      dictationRecorder.start();
      dictate.classList.add("recording");
      dictate.textContent = "Stop dictation and transcribe";
      setStatus("Dictation is recording. Click again when you finish speaking.");
    } catch (err) {
      const reason = err?.name || "UnknownError";
      setStatus(`Microphone request failed (${reason}). Check Edge and Windows microphone permissions.`);
      toast("Microphone access is required for dictation.", "error");
    }
  }
  async function transcribeTurn(chunks, mimeType) {
    setStatus("Transcribing with ElevenLabs…");
    setVoiceState("thinking", "Transcribing with ElevenLabs…");
    const data = new FormData();
    data.append("audio", new Blob(chunks, { type: mimeType || "audio/webm" }), "speech-mode.webm");
    const response = await fetch("/api/assistant/transcribe", { method: "POST", body: data });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "ElevenLabs could not transcribe that turn.");
    input.value = result.text;
    setStatus("Sending your question to Port a Potty…");
    setVoiceState("thinking", "Thinking with Gemini…");
    form.requestSubmit();
  }
  function listenForTurn() {
    if (!speechMode || !stream || recorder?.state === "recording") return;
    const chunks = [];
    let heardSpeech = false;
    let quietSince = 0;
    recorder = new MediaRecorder(stream);
    recorder.ondataavailable = (event) => { if (event.data.size) chunks.push(event.data); };
    recorder.onstop = async () => {
      stopMonitor();
      if (!speechMode || !chunks.length) return;
      try { await transcribeTurn(chunks, recorder.mimeType); }
      catch (err) { toast(err.message, "error"); if (speechMode) listenForTurn(); }
    };
    audioContext = new AudioContext();
    audioContext.resume();
    const analyser = audioContext.createAnalyser();
    audioContext.createMediaStreamSource(stream).connect(analyser);
    const samples = new Uint8Array(analyser.fftSize);
    recorder.start();
    setStatus("Conversation mode is on — speak naturally. I will respond after you pause.");
    setVoiceState("listening", "Listening…");
    monitor = setInterval(() => {
      analyser.getByteTimeDomainData(samples);
      const volume = samples.reduce((sum, value) => sum + Math.abs(value - 128), 0) / samples.length / 128;
      if (volume > 0.018) { heardSpeech = true; quietSince = 0; }
      else if (heardSpeech) {
        quietSince ||= Date.now();
        if (Date.now() - quietSince > 900 && recorder?.state === "recording") recorder.stop();
      }
    }, 100);
  }
  async function startSpeechMode() {
    try {
      if (dictationRecorder?.state === "recording") dictationRecorder.stop();
      setStatus("Requesting microphone permission…");
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      speechMode = true;
      window.portAPottyVoiceEnabled = true;
      setModeControls(true);
      setVoiceState("listening", "Listening…");
      listenForTurn();
    } catch (err) {
      const reason = err?.name || "UnknownError";
      setStatus(`Microphone request failed (${reason}). Check Edge and Windows microphone permissions.`);
      toast("Microphone access is required for speech mode.", "error");
    }
  }
  function stopSpeechMode() {
    speechMode = false;
    stopMonitor();
    if (recorder?.state === "recording") recorder.stop();
    stream?.getTracks().forEach((track) => track.stop());
    stream = undefined;
    window.portAPottyVoiceEnabled = false;
    stopAssistantVoice();
    setModeControls(false);
    if (voiceIndicator) voiceIndicator.hidden = true;
    setStatus("Text mode is on. Type a question below.");
  }
  window.portAPottyResumeSpeechMode = () => { if (speechMode) listenForTurn(); };
  window.portAPottySetVoiceState = setVoiceState;
  button.addEventListener("click", startSpeechMode);
  dictate.addEventListener("click", toggleDictation);
  textMode.addEventListener("click", stopSpeechMode);
}

function setupAssistantResize() {
  const dock = document.querySelector(".assistant-dock");
  const handle = document.querySelector(".assistant-resize-handle");
  if (!dock || !handle) return;
  handle.addEventListener("pointerdown", (event) => {
    if (window.matchMedia("(max-width: 560px)").matches) return;
    event.preventDefault();
    handle.setPointerCapture(event.pointerId);
    const startX = event.clientX;
    const startY = event.clientY;
    const startWidth = dock.getBoundingClientRect().width;
    const startHeight = dock.getBoundingClientRect().height;
    const resize = (move) => {
      const width = Math.max(360, Math.min(window.innerWidth - 32, startWidth - (move.clientX - startX)));
      const height = Math.max(250, Math.min(window.innerHeight - 32, startHeight - (move.clientY - startY)));
      dock.style.width = `${width}px`;
      dock.style.height = `${height}px`;
    };
    const stop = () => {
      handle.removeEventListener("pointermove", resize);
      handle.removeEventListener("pointerup", stop);
      handle.removeEventListener("pointercancel", stop);
    };
    handle.addEventListener("pointermove", resize);
    handle.addEventListener("pointerup", stop);
    handle.addEventListener("pointercancel", stop);
  });
}

function setupLocalHelper() {
  const form = document.getElementById("agent-pairing");
  const input = document.getElementById("agent-device-id");
  const refreshButton = document.getElementById("agent-refresh");
  const toggleButton = document.getElementById("agent-toggle");
  const panel = document.getElementById("agent-panel");
  const downloadButton = document.getElementById("agent-download");
  const status = document.getElementById("agent-status");
  if (!form || !input || !refreshButton || !downloadButton || !toggleButton || !panel || !status) return;
  const containers = () => ({
    primary: document.getElementById("agent-results-primary"),
    secondary: document.getElementById("agent-results-secondary"),
  });

  input.value = localStorage.getItem(AGENT_PAIRING_STORAGE_KEY) || "";
  const setCollapsed = (collapsed, persist = true) => {
    panel.classList.toggle("is-collapsed", collapsed);
    toggleButton.setAttribute("aria-expanded", String(!collapsed));
    toggleButton.textContent = collapsed ? "Expand setup" : "Collapse setup";
    if (persist) localStorage.setItem(AGENT_COLLAPSED_STORAGE_KEY, String(collapsed));
  };
  setCollapsed(localStorage.getItem(AGENT_COLLAPSED_STORAGE_KEY) === "true", false);
  const setStatus = (message) => { status.textContent = message; };
  const statusTag = (level) => {
    const safeLevel = STATUS_TAGS[level] ? level : "error";
    const tag = document.createElement("span");
    tag.className = "tag";
    const icon = document.createElement("span");
    icon.className = "tag-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = STATUS_ICONS[safeLevel];
    tag.append(icon, document.createTextNode(STATUS_TAGS[safeLevel]));
    return tag;
  };
  const render = (scan) => {
    const { primary, secondary } = containers();
    if (!primary || !secondary) return;
    primary.replaceChildren();
    secondary.replaceChildren();
    const observed = new Date(scan.observed_at);
    setStatus(`Latest scan from ${scan.hostname} at ${Number.isNaN(observed.valueOf()) ? "an unknown time" : observed.toLocaleString()}.`);
    setCollapsed(true);
    const order = ["Local Port Assessor", "Listening Services", "System Hardening"];
    const results = [...(scan.results || [])].sort((left, right) => order.indexOf(left.name) - order.indexOf(right.name));
    for (const result of results) {
      const level = STATUS_TAGS[result.status] ? result.status : "error";
      const card = document.createElement("section");
      card.className = `panel agent-result status-${level}`;
      const head = document.createElement("div");
      head.className = "panel-head";
      const title = document.createElement("h2");
      title.textContent = result.name || "Local check";
      head.append(title, statusTag(level));
      const description = document.createElement("p");
      description.className = "description";
      description.textContent = result.description || "";
      const summary = document.createElement("p");
      summary.className = "summary";
      summary.textContent = result.summary || "";
      const list = document.createElement("ul");
      list.className = "agent-result-list";
      for (const item of result.items || []) {
        const itemLevel = STATUS_TAGS[item.status] ? item.status : "error";
        const row = document.createElement("li");
        row.className = `item status-${itemLevel}`;
        row.append(statusTag(itemLevel));
        const label = document.createElement("span");
        label.className = "label";
        label.textContent = item.label || "";
        const detail = document.createElement("span");
        detail.className = "detail";
        detail.textContent = item.detail || "";
        row.append(label, detail);
        list.append(row);
      }
      card.append(head, description, summary, list);
      // Match the local dashboard's order: port and listening panels sit
      // before IOC/CVE, while the hardening panel follows it.
      (result.name === "System Hardening" ? secondary : primary).append(card);
    }
  };
  const load = async () => {
    const deviceId = input.value.trim();
    const packageId = localStorage.getItem(AGENT_PACKAGE_STORAGE_KEY);
    if (!deviceId && !packageId) {
      setStatus("Download the ready-to-run helper, or paste a pairing ID from an existing helper.");
      const { primary, secondary } = containers();
      primary?.replaceChildren();
      secondary?.replaceChildren();
      return;
    }
    refreshButton.disabled = true;
    refreshButton.textContent = "Refreshing…";
    setStatus("Checking for the latest local scan…");
    try {
      const endpoint = deviceId
        ? `/api/agent/scan/${encodeURIComponent(deviceId)}`
        : `/api/agent/package/${encodeURIComponent(packageId)}`;
      const response = await fetch(endpoint, { cache: "no-store" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Could not load scan (${response.status}).`);
      localStorage.setItem(AGENT_PAIRING_STORAGE_KEY, deviceId);
      render(data);
    } catch (err) {
      const { primary, secondary } = containers();
      primary?.replaceChildren();
      secondary?.replaceChildren();
      setStatus(err.message || "Could not load the local helper scan.");
    } finally {
      refreshButton.disabled = false;
      refreshButton.textContent = "Refresh local scan";
    }
  };
  form.addEventListener("submit", (event) => { event.preventDefault(); load(); });
  refreshButton.addEventListener("click", load);
  toggleButton.addEventListener("click", () => setCollapsed(!panel.classList.contains("is-collapsed")));
  downloadButton.addEventListener("click", async () => {
    downloadButton.disabled = true;
    downloadButton.textContent = "Preparing download…";
    setStatus("Creating a device-scoped helper package…");
    try {
      const response = await fetch("/api/agent/package", {
        method: "POST",
        headers: { "X-Dashboard": "1" },
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || "Could not create the helper package.");
      }
      const packageId = response.headers.get("X-Port-A-Potty-Package-ID");
      if (!packageId) throw new Error("The server did not return a package ID.");
      const blob = await response.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "Port-a-Potty-Local-Helper.zip";
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
      localStorage.setItem(AGENT_PACKAGE_STORAGE_KEY, packageId);
      localStorage.removeItem(AGENT_PAIRING_STORAGE_KEY);
      input.value = "";
      setStatus("Downloaded. Extract the ZIP and double-click Port-a-Potty-Helper.exe; this panel will connect automatically after its first scan.");
    } catch (err) {
      setStatus(err.message || "Could not download the local helper.");
    } finally {
      downloadButton.disabled = false;
      downloadButton.textContent = "Download ready-to-run Windows helper";
    }
  });
  window.portAPottyRefreshHelper = load;
  if (input.value || localStorage.getItem(AGENT_PACKAGE_STORAGE_KEY)) load();
}

document.addEventListener("submit", (event) => {
  const assistantForm = event.target.closest("#assistant-form");
  if (assistantForm) { event.preventDefault(); askAssistant(assistantForm); }
});

setupVoiceInput();
setupAssistantResize();
setupLocalHelper();
