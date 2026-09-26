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
let activeAssistantAudio;

function stopAssistantVoice() {
  if (activeAssistantAudio) {
    activeAssistantAudio.pause();
    URL.revokeObjectURL(activeAssistantAudio.src);
    activeAssistantAudio = undefined;
  }
  if ("speechSynthesis" in window) window.speechSynthesis.cancel();
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
  const message = document.createElement("p");
  message.className = `assistant-message ${role}`;
  message.textContent = text;
  messages.append(message);
  messages.scrollTop = messages.scrollHeight;
  return message;
}

async function speakAssistantAnswer(text) {
  if (!window.portAPottyVoiceEnabled) return;
  window.portAPottySetVoiceState?.("responding", "Responding with ElevenLabs…");
  stopAssistantVoice();
  try {
    const response = await fetch("/api/assistant/speak", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!response.ok) throw new Error("ElevenLabs voice unavailable");
    activeAssistantAudio = new Audio(URL.createObjectURL(await response.blob()));
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
      body: JSON.stringify({ question }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "The assistant could not respond.");
    pending.remove();
    addAssistantMessage(data.answer, "assistant");
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
  const textMode = document.getElementById("assistant-text-mode");
  const input = document.getElementById("assistant-input");
  const form = document.getElementById("assistant-form");
  const voiceStatus = document.getElementById("assistant-voice-status");
  const voiceIndicator = document.getElementById("assistant-voice-indicator");
  const voiceState = document.getElementById("assistant-voice-state");
  const canRecord = Boolean(navigator.mediaDevices?.getUserMedia && window.MediaRecorder);
  let stream, recorder, monitor, audioContext, speechMode = false;
  window.portAPottyVoiceEnabled = false;
  if (!button || !input || !canRecord) {
    button.textContent = "Voice unavailable";
    button.disabled = true;
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
    textMode.hidden = !active;
    textMode.disabled = !active;
  };
  function stopMonitor() {
    clearInterval(monitor);
    audioContext?.close();
    audioContext = undefined;
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
    setStatus("Speech mode is on — speak naturally. I will respond after you pause.");
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

document.addEventListener("submit", (event) => {
  const assistantForm = event.target.closest("#assistant-form");
  if (assistantForm) { event.preventDefault(); askAssistant(assistantForm); }
});

setupVoiceInput();
setupAssistantResize();
