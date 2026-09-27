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
const ASSISTANT_MINIMIZED_STORAGE_KEY = "portAPottyAssistantMinimized";

// localStorage can throw in private windows or with blocked site data; the
// page must still work, just without remembering these small preferences.
function readSetting(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function writeSetting(key, value) {
  try { localStorage.setItem(key, value); } catch { /* not remembered */ }
}
function removeSetting(key) {
  try { localStorage.removeItem(key); } catch { /* not remembered */ }
}

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
    toast("Example log changed and analyzed.", "success");
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
        helper_package_id: readSetting(AGENT_PACKAGE_STORAGE_KEY) || undefined,
        helper_device_id: readSetting(AGENT_PAIRING_STORAGE_KEY) || undefined,
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
        dictate.textContent = "Dictate";
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
      dictate.textContent = "Stop & transcribe";
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
  // Minimizing the assistant turns the microphone off, so it never listens unseen.
  window.portAPottyStopVoiceInput = () => {
    if (dictationRecorder?.state === "recording") dictationRecorder.stop();
    if (speechMode) stopSpeechMode();
  };
  button.addEventListener("click", startSpeechMode);
  dictate.addEventListener("click", toggleDictation);
  textMode.addEventListener("click", stopSpeechMode);
}

// The assistant starts minimized to a small button (it's a helper, not the
// main event) and remembers whether the user opened it.
function setupAssistantDock() {
  const dock = document.getElementById("assistant-dock");
  const panel = document.getElementById("assistant-window");
  const launcher = document.getElementById("assistant-open");
  const minimize = document.getElementById("assistant-minimize");
  const handle = document.querySelector(".assistant-resize-handle");
  if (!dock || !panel || !launcher || !minimize || !handle) return;

  const setMinimized = (minimized, persist = true) => {
    dock.classList.toggle("is-minimized", minimized);
    launcher.setAttribute("aria-expanded", String(!minimized));
    if (minimized) window.portAPottyStopVoiceInput?.();
    if (persist) writeSetting(ASSISTANT_MINIMIZED_STORAGE_KEY, String(minimized));
  };
  setMinimized(readSetting(ASSISTANT_MINIMIZED_STORAGE_KEY) !== "false", false);
  launcher.addEventListener("click", () => {
    setMinimized(false);
    document.getElementById("assistant-input")?.focus();
  });
  minimize.addEventListener("click", () => {
    setMinimized(true);
    launcher.focus();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !dock.classList.contains("is-minimized") && panel.contains(document.activeElement)) {
      setMinimized(true);
      launcher.focus();
    }
  });

  // Never let the window be shorter than its heading + controls + a few lines
  // of messages, so buttons can't be squeezed out of view.
  const minimumHeight = () => {
    const heading = panel.querySelector(".assistant-heading");
    const form = panel.querySelector(".assistant-form");
    const style = getComputedStyle(panel);
    const chrome = parseFloat(style.paddingTop) + parseFloat(style.paddingBottom) + 20;
    return Math.ceil((heading?.offsetHeight || 0) + (form?.offsetHeight || 0) + 96 + chrome);
  };
  const clampToViewport = () => {
    if (!panel.style.height) return;
    const height = Math.min(parseFloat(panel.style.height), window.innerHeight - 32);
    panel.style.height = `${Math.max(minimumHeight(), height)}px`;
    if (panel.style.width) panel.style.width = `${Math.min(parseFloat(panel.style.width), window.innerWidth - 32)}px`;
  };
  window.addEventListener("resize", clampToViewport);

  handle.addEventListener("pointerdown", (event) => {
    if (window.matchMedia("(max-width: 560px)").matches) return;
    event.preventDefault();
    handle.setPointerCapture(event.pointerId);
    const startX = event.clientX;
    const startY = event.clientY;
    const startWidth = panel.getBoundingClientRect().width;
    const startHeight = panel.getBoundingClientRect().height;
    const minHeight = Math.min(minimumHeight(), window.innerHeight - 32);
    const resize = (move) => {
      const width = Math.max(340, Math.min(window.innerWidth - 32, startWidth - (move.clientX - startX)));
      const height = Math.max(minHeight, Math.min(window.innerHeight - 32, startHeight - (move.clientY - startY)));
      panel.style.width = `${width}px`;
      panel.style.height = `${height}px`;
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

// Lessons for "Port <n> ..." findings, embedded by the template (checks/port_lessons.py).
let portLessons;
function lessonForLabel(label) {
  if (portLessons === undefined) {
    try {
      portLessons = JSON.parse(document.getElementById("port-lessons-data")?.textContent || "{}");
    } catch {
      portLessons = {};
    }
  }
  const match = /^Port (\d{1,5})\b/.exec(label || "");
  return match ? portLessons[match[1]] : undefined;
}

// Same markup as the template's lesson_body() macro.
function lessonDetails(lesson) {
  const details = document.createElement("details");
  details.className = "lesson";
  const summary = document.createElement("summary");
  summary.textContent = "How attackers use this port";
  const list = document.createElement("dl");
  list.className = "lesson-list";
  for (const [term, text, extra] of [
    ["How attackers use it", lesson.how],
    ["Real example", lesson.example],
    ["Think of it like this", lesson.analogy],
    ["How to keep it closed", lesson.protect, "lesson-protect"],
  ]) {
    const row = document.createElement("div");
    if (extra) row.className = extra;
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = text;
    row.append(dt, dd);
    list.append(row);
  }
  details.append(summary, list);
  return details;
}

// "windows" | "mac" | "ios" | "android" | "other", from what the browser reports.
function detectDevice() {
  const agent = navigator.userAgent || "";
  const platform = navigator.userAgentData?.platform || navigator.platform || "";
  if (/android/i.test(agent)) return "android";
  if (/iphone|ipad|ipod/i.test(agent)) return "ios";
  // iPadOS reports itself as a Mac but has a touch screen.
  if (/mac/i.test(platform) && navigator.maxTouchPoints > 1) return "ios";
  if (/mac/i.test(platform) || /macintosh/i.test(agent)) return "mac";
  if (/win/i.test(platform) || /windows/i.test(agent)) return "windows";
  return "other";
}

function setupLocalHelper() {
  const form = document.getElementById("agent-pairing");
  const input = document.getElementById("agent-device-id");
  const refreshButton = document.getElementById("agent-refresh");
  const toggleButton = document.getElementById("agent-toggle");
  const panel = document.getElementById("agent-panel");
  const downloadButtons = [...document.querySelectorAll(".agent-download")];
  const status = document.getElementById("agent-status");
  const macSteps = document.getElementById("mac-steps");
  if (!form || !input || !refreshButton || !downloadButtons.length || !toggleButton || !panel || !status) return;
  const containers = () => ({
    primary: document.getElementById("agent-results-primary"),
    secondary: document.getElementById("agent-results-secondary"),
  });

  // Put this computer's download first; on phones, point to the no-download check.
  const device = detectDevice();
  const phoneNote = document.getElementById("agent-phone-note");
  if (phoneNote) phoneNote.hidden = !(device === "ios" || device === "android");
  for (const button of downloadButtons) {
    const mine = button.dataset.platform === device;
    button.classList.toggle("is-secondary", !mine && (device === "windows" || device === "mac"));
    if (mine) button.parentElement.prepend(button);
  }
  document.getElementById("mac-copy")?.addEventListener("click", async (event) => {
    const command = document.getElementById("mac-command")?.textContent || "";
    try {
      await navigator.clipboard.writeText(command);
      event.target.textContent = "Copied";
    } catch {
      event.target.textContent = "Select and copy";
    }
    setTimeout(() => { event.target.textContent = "Copy"; }, 2000);
  });

  input.value = readSetting(AGENT_PAIRING_STORAGE_KEY) || "";
  const setCollapsed = (collapsed, persist = true) => {
    panel.classList.toggle("is-collapsed", collapsed);
    toggleButton.setAttribute("aria-expanded", String(!collapsed));
    toggleButton.textContent = collapsed ? "Expand setup" : "Collapse setup";
    if (persist) writeSetting(AGENT_COLLAPSED_STORAGE_KEY, String(collapsed));
  };
  setCollapsed(readSetting(AGENT_COLLAPSED_STORAGE_KEY) === "true", false);
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
        const lesson = lessonForLabel(item.label);
        if (lesson) row.append(lessonDetails(lesson));
        list.append(row);
      }
      card.append(head, description, summary, list);
      // Match the local dashboard's order: port and listening panels sit
      // before IOC/CVE, while the hardening panel follows it.
      (result.name === "System Hardening" ? secondary : primary).append(card);
    }
  };
  let waitTimer;
  const stopWaiting = () => { clearInterval(waitTimer); waitTimer = undefined; };
  const load = async ({ quiet = false } = {}) => {
    const deviceId = input.value.trim();
    const packageId = readSetting(AGENT_PACKAGE_STORAGE_KEY);
    if (!deviceId && !packageId) {
      setStatus("Download the ready-to-run helper, or paste a pairing ID from an existing helper.");
      const { primary, secondary } = containers();
      primary?.replaceChildren();
      secondary?.replaceChildren();
      return false;
    }
    refreshButton.disabled = true;
    refreshButton.textContent = "Refreshing…";
    if (!quiet) setStatus("Checking for the latest local scan…");
    try {
      const endpoint = deviceId
        ? `/api/agent/scan/${encodeURIComponent(deviceId)}`
        : `/api/agent/package/${encodeURIComponent(packageId)}`;
      const response = await fetch(endpoint, { cache: "no-store" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Could not load scan (${response.status}).`);
      writeSetting(AGENT_PAIRING_STORAGE_KEY, deviceId);
      stopWaiting();
      if (macSteps) macSteps.hidden = true;
      render(data);
      return true;
    } catch (err) {
      if (!quiet) {
        const { primary, secondary } = containers();
        primary?.replaceChildren();
        secondary?.replaceChildren();
        setStatus(err.message || "Could not load the local helper scan.");
      }
      return false;
    } finally {
      refreshButton.disabled = false;
      refreshButton.textContent = "Refresh local scan";
    }
  };
  // After a download, check every 10 seconds (for up to 15 minutes) so the
  // results appear on their own once the helper sends its first scan.
  const waitForFirstScan = () => {
    stopWaiting();
    const started = Date.now();
    waitTimer = setInterval(() => {
      if (Date.now() - started > 15 * 60 * 1000) { stopWaiting(); return; }
      load({ quiet: true });
    }, 10000);
  };
  form.addEventListener("submit", (event) => { event.preventDefault(); load(); });
  refreshButton.addEventListener("click", () => load());
  toggleButton.addEventListener("click", () => setCollapsed(!panel.classList.contains("is-collapsed")));
  for (const downloadButton of downloadButtons) {
    const platform = downloadButton.dataset.platform;
    const idleLabel = downloadButton.textContent;
    downloadButton.addEventListener("click", async () => {
      downloadButton.disabled = true;
      downloadButton.textContent = "Preparing download…";
      setStatus("Creating a device-scoped helper package…");
      try {
        const response = await fetch(`/api/agent/package?platform=${encodeURIComponent(platform)}`, {
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
        link.download = platform === "mac" ? "Port-a-Potty-Mac-Helper.zip" : "Port-a-Potty-Local-Helper.zip";
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
        writeSetting(AGENT_PACKAGE_STORAGE_KEY, packageId);
        removeSetting(AGENT_PAIRING_STORAGE_KEY);
        input.value = "";
        if (macSteps) macSteps.hidden = platform !== "mac";
        setStatus(platform === "mac"
          ? "Downloaded. Run the helper using the steps above; your results will appear here automatically after its first scan."
          : "Downloaded. Extract the ZIP and double-click Port-a-Potty-Helper.exe; your results will appear here automatically after its first scan.");
        waitForFirstScan();
      } catch (err) {
        setStatus(err.message || "Could not download the local helper.");
      } finally {
        downloadButton.disabled = false;
        downloadButton.textContent = idleLabel;
      }
    });
  }
  window.portAPottyRefreshHelper = load;
  if (input.value || readSetting(AGENT_PACKAGE_STORAGE_KEY)) load();
}

// "Check this device": pick the visitor's device tab and count ticked steps.
function setupDeviceCheck() {
  const section = document.getElementById("device-check");
  if (!section) return;
  const tabs = [...section.querySelectorAll(".device-tab")];
  const guides = [...section.querySelectorAll(".device-guide")];
  const select = (device, focus = false) => {
    for (const tab of tabs) {
      const selected = tab.dataset.device === device;
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
      if (selected && focus) tab.focus();
    }
    for (const guide of guides) guide.hidden = guide.dataset.device !== device;
  };
  const detected = detectDevice();
  select(tabs.some((tab) => tab.dataset.device === detected) ? detected : tabs[0]?.dataset.device);
  for (const tab of tabs) {
    tab.addEventListener("click", () => select(tab.dataset.device));
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      const step = event.key === "ArrowRight" ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + step + tabs.length) % tabs.length];
      select(next.dataset.device, true);
    });
  }
  section.addEventListener("change", (event) => {
    const guide = event.target.closest(".device-guide");
    if (!guide) return;
    const checks = [...guide.querySelectorAll(".device-step-check")];
    const done = checks.filter((check) => check.checked).length;
    const progress = guide.querySelector(".device-progress");
    if (progress) {
      progress.textContent = done === checks.length
        ? `All ${checks.length} steps done. Nice work: fewer open doors on this device.`
        : `${done} of ${checks.length} steps done`;
    }
  });
}

document.addEventListener("submit", (event) => {
  const assistantForm = event.target.closest("#assistant-form");
  if (assistantForm) { event.preventDefault(); askAssistant(assistantForm); }
});

setupVoiceInput();
setupAssistantDock();
setupLocalHelper();
setupDeviceCheck();
