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
  try {
    const response = await fetch("/api/assistant/speak", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!response.ok) throw new Error("ElevenLabs voice unavailable");
    const audio = new Audio(URL.createObjectURL(await response.blob()));
    audio.addEventListener("ended", () => URL.revokeObjectURL(audio.src), { once: true });
    await audio.play();
  } catch {
    // The browser voice keeps the conversation usable if the TTS quota is gone.
    if (!("speechSynthesis" in window)) return;
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = "en-US";
    window.speechSynthesis.speak(utterance);
  }
}

async function askAssistant(form) {
  const input = form.querySelector("#assistant-input");
  const question = input.value.trim();
  if (!question) return;
  const submit = form.querySelector("button[type=submit]");
  addAssistantMessage(question, "user");
  const pending = addAssistantMessage("Port a Potty is analyzing the findings…", "assistant pending");
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
    speakAssistantAnswer(data.answer);
  } catch (err) {
    pending.remove();
    addAssistantMessage(err.message, "assistant error");
  } finally {
    submit.disabled = false;
    input.focus();
  }
}

function setupVoiceInput() {
  const button = document.getElementById("assistant-talk");
  const input = document.getElementById("assistant-input");
  const form = document.getElementById("assistant-form");
  const voiceStatus = document.getElementById("assistant-voice-status");
  if (!button || !input) return;
  const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  let recognition;
  let listening = false;
  let recorder;
  let stream;
  const canRecord = Boolean(navigator.mediaDevices?.getUserMedia && window.MediaRecorder);
  window.portAPottyVoiceEnabled = false;
  if (!Recognition && !(navigator.mediaDevices?.getUserMedia && window.MediaRecorder)) {
    button.textContent = "Voice unavailable";
    button.disabled = true;
    button.title = "Use a current Chrome or Edge browser and allow microphone access.";
    return;
  }
  function resetButton() {
    listening = false;
    button.textContent = "Talk to assistant";
    button.setAttribute("aria-pressed", "false");
  }
  function setVoiceStatus(message, state = "ready") {
    if (!voiceStatus) return;
    voiceStatus.textContent = message;
    voiceStatus.dataset.state = state;
  }
  if (Recognition) {
    recognition = new Recognition();
    recognition.lang = "en-US";
    recognition.interimResults = false;
    recognition.continuous = false;
    recognition.onresult = (event) => {
      input.value = event.results[0][0].transcript;
      input.focus();
      form.requestSubmit();
    };
    recognition.onerror = () => toast("Microphone input was unavailable. Check browser microphone permission.", "error");
    recognition.onend = resetButton;
  }
  function startBrowserFallback() {
    if (!recognition) {
      toast("Voice recording is not supported by this browser.", "error");
      return;
    }
    toast("ElevenLabs is unavailable, so the browser voice fallback is listening.", "info");
    setVoiceStatus("Using browser voice fallback.", "fallback");
    listening = true;
    button.textContent = "Listening…";
    button.setAttribute("aria-pressed", "true");
    recognition.start();
  }
  async function startElevenLabsRecording() {
    try {
      setVoiceStatus("Requesting microphone permission…", "requesting");
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      setVoiceStatus("Microphone enabled — recording for ElevenLabs.", "active");
      const chunks = [];
      recorder = new MediaRecorder(stream);
      recorder.ondataavailable = (event) => chunks.push(event.data);
      recorder.onstop = async () => {
        stream.getTracks().forEach((track) => track.stop());
        resetButton();
        button.textContent = "Transcribing…";
        button.disabled = true;
        setVoiceStatus("Sending your recording to ElevenLabs…", "processing");
        let browserFallbackActive = false;
        try {
          const data = new FormData();
          data.append("audio", new Blob(chunks, { type: recorder.mimeType || "audio/webm" }), "question.webm");
          const response = await fetch("/api/assistant/transcribe", { method: "POST", body: data });
          const result = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(result.error || "Could not transcribe the recording.");
          input.value = result.text;
          setVoiceStatus("ElevenLabs transcript ready — asking Port a Potty…", "processing");
          form.requestSubmit();
        } catch (err) {
          if (recognition) {
            browserFallbackActive = true;
            startBrowserFallback();
          } else {
            toast(err.message, "error");
          }
        } finally {
          button.disabled = false;
          if (!browserFallbackActive) {
            resetButton();
            setVoiceStatus("Click Talk to assistant to record another question.", "ready");
          }
        }
      };
      recorder.start();
      listening = true;
      button.textContent = "Recording… click to stop";
      button.setAttribute("aria-pressed", "true");
    } catch (err) {
      const denied = err?.name === "NotAllowedError" || err?.name === "SecurityError";
      setVoiceStatus(denied ? "Microphone blocked. Allow it in this site’s browser permissions, then retry." : "Microphone is unavailable in this browser.", "blocked");
      toast("Microphone permission was denied or unavailable. Allow microphone access in this browser, then try again.", "error");
      resetButton();
    }
  }
  button.addEventListener("click", () => {
    window.portAPottyVoiceEnabled = true;
    if (recorder?.state === "recording") {
      recorder.stop();
      return;
    }
    if (canRecord) {
      startElevenLabsRecording();
      return;
    }
    if (listening && recognition) {
      recognition.stop();
      return;
    }
    startBrowserFallback();
  });
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
