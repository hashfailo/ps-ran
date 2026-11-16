import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  CirclePause,
  CirclePlay,
  CircleStop,
  FileWarning,
  Gauge,
  Radio,
  RotateCcw,
  ShieldCheck,
  Wifi,
  WifiOff,
} from "lucide-react";

type Sample = {
  sample_id: string;
  class_label: "benign" | "ransomware";
  relative_report_path: string;
};

type Model = {
  id: string;
  name: string;
  status: string;
  threshold?: number;
  vocabulary_size?: number;
  metadata?: {
    architecture?: string;
    config?: { sequence_length?: number; embedding_dim?: number; hidden_dim?: number; layers?: number; heads?: number };
    training_summary?: { test_recall?: number; test_false_alarm_rate?: number; best_epoch?: number };
  };
};
type EventItem = {
  position: number;
  total: number;
  api: string;
  operation_kind: string;
  process_id: string;
  status: boolean | null;
  file_related: boolean;
  arguments: string[];
};
type ActivityCounts = { writes: number; reads: number; deletes: number; renames: number; file_information: number };

const emptyActivity: ActivityCounts = { writes: 0, reads: 0, deletes: 0, renames: 0, file_information: 0 };

function formatApi(api: string) {
  return api.replace(/^nt/, "Nt").replace(/([a-z])([A-Z])/g, "$1 $2");
}

function Metric({ label, value, tone = "text-slate-100" }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel/80 px-4 py-3">
      <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  );
}

export default function App() {
  const [samples, setSamples] = useState<Sample[]>([]);
  const [models, setModels] = useState<Model[]>([]);
  const [sampleId, setSampleId] = useState("");
  const [modelId, setModelId] = useState("bag_of_apis");
  const [speed, setSpeed] = useState(20);
  const [status, setStatus] = useState("idle");
  const [connection, setConnection] = useState<"connected" | "offline">("offline");
  const [selected, setSelected] = useState<Sample | null>(null);
  const [event, setEvent] = useState<EventItem | null>(null);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [score, setScore] = useState(0.5);
  const [threshold, setThreshold] = useState(0.5);
  const [firstAlert, setFirstAlert] = useState<{ event_position: number; trace_fraction: number; score: number } | null>(null);
  const [activity, setActivity] = useState<ActivityCounts>(emptyActivity);
  const [generations, setGenerations] = useState(0);
  const [ambiguities, setAmbiguities] = useState(0);
  const [error, setError] = useState("");
  const socket = useRef<WebSocket | null>(null);
  const sessionId = useRef(crypto.randomUUID());

  useEffect(() => {
    Promise.all([fetch("/api/samples").then((response) => response.json()), fetch("/api/models").then((response) => response.json())])
      .then(([sampleData, modelData]) => {
        setSamples(sampleData.samples);
        setModels(modelData.models);
        const preferred = sampleData.samples.find((item: Sample) => item.class_label === "ransomware");
        if (preferred) setSampleId(preferred.sample_id);
      })
      .catch(() => setError("Backend unavailable. Start FastAPI before opening the dashboard."));
  }, []);

  const selectedModel = models.find((item) => item.id === modelId);
  const progress = event ? (event.position / Math.max(1, event.total)) * 100 : 0;
  const alertState = firstAlert !== null || (status !== "idle" && status !== "ready" && score >= threshold);
  const latestEvents = useMemo(() => events.slice(-28).reverse(), [events]);

  function connect() {
    if (socket.current && socket.current.readyState === WebSocket.OPEN) return;
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${protocol}://${window.location.host}/ws/replay/${sessionId.current}`);
    socket.current = ws;
    ws.onopen = () => {
      setConnection("connected");
      setError("");
    };
    ws.onclose = () => setConnection("offline");
    ws.onerror = () => setError("WebSocket connection failed.");
    ws.onmessage = (message) => {
      const payload = JSON.parse(message.data);
      if (payload.type === "configured") {
        setSelected(payload.sample);
        setThreshold(payload.threshold);
        setStatus("ready");
        setEvents([]);
        setEvent(null);
        setScore(0.5);
        setFirstAlert(null);
        setActivity(emptyActivity);
        setGenerations(0);
        setAmbiguities(0);
      } else if (payload.type === "event") {
        setEvent(payload.event);
        setEvents((current) => [...current.slice(-100), payload.event]);
        setScore(payload.prediction.score);
        setThreshold(payload.prediction.threshold);
        setStatus("running");
        if (payload.prediction.alert && !firstAlert) {
          setFirstAlert({
            event_position: payload.prediction.events_seen,
            trace_fraction: payload.prediction.trace_fraction,
            score: payload.prediction.score,
          });
        }
        setActivity(payload.activity);
        setGenerations(payload.lifecycle.candidate_generations);
        setAmbiguities(payload.lifecycle.ambiguous_observations);
      } else if (payload.type === "complete") {
        setStatus("completed");
        if (payload.result.first_alert) setFirstAlert(payload.result.first_alert);
      } else if (payload.type === "status") {
        setStatus(payload.status);
      } else if (payload.type === "error") {
        setError(payload.message);
        setStatus("error");
      }
    };
  }

  function send(command: string, extra: Record<string, unknown> = {}) {
    connect();
    window.setTimeout(() => socket.current?.send(JSON.stringify({ command, ...extra })), 100);
  }

  function configureAndStart() {
    setError("");
    send("configure", { sample_id: sampleId, speed, model_id: modelId });
    window.setTimeout(() => send("start"), 250);
  }

  return (
    <main className="min-h-screen bg-ink">
      <header className="border-b border-line bg-[#081625]">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="rounded-lg border border-cyan/40 bg-cyan/10 p-2 text-cyan"><Radio size={20} /></div>
            <div>
              <div className="text-sm font-semibold tracking-[0.28em] text-cyan">SENTINEL</div>
              <div className="text-xs text-slate-500">EN2025 recorded-trace intelligence</div>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            {connection === "connected" ? <Wifi size={15} className="text-signal" /> : <WifiOff size={15} />}
            {connection === "connected" ? "LIVE SOCKET" : "OFFLINE"}
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1600px] px-6 py-6">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="mb-2 text-xs uppercase tracking-[0.25em] text-slate-500">Streaming replay console</p>
            <h1 className="text-3xl font-semibold tracking-tight text-white">Behavioral signal, one event at a time.</h1>
            <p className="mt-2 max-w-2xl text-sm text-slate-400">Recorded CAPE telemetry only. Scores are model output; file activity is observable evidence, not confirmed physical damage.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <select value={sampleId} onChange={(e) => setSampleId(e.target.value)} className="min-w-[280px] rounded-lg border border-line bg-panel px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan">
              <option value="">Select a recorded sample</option>
              {samples.map((sample) => <option value={sample.sample_id} key={sample.sample_id}>{sample.class_label.toUpperCase()} · {sample.sample_id.slice(0, 12)}</option>)}
            </select>
            <select value={modelId} onChange={(e) => setModelId(e.target.value)} className="rounded-lg border border-line bg-panel px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan">
              {models.map((item) => <option value={item.id} key={item.id} disabled={item.status !== "ready"}>{item.name}{item.status !== "ready" ? " · unavailable" : ""}</option>)}
            </select>
            <button onClick={configureAndStart} disabled={!sampleId || selectedModel?.status !== "ready"} className="flex items-center gap-2 rounded-lg bg-cyan px-4 py-2 text-sm font-semibold text-ink transition hover:bg-sky-300 disabled:cursor-not-allowed disabled:opacity-40"><CirclePlay size={16} /> Start replay</button>
          </div>
        </div>

        {error && <div className="mb-5 flex items-center gap-2 rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-rose-200"><AlertTriangle size={16} />{error}</div>}

        {selectedModel && <div className="mb-5 flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-line bg-panel/70 px-5 py-3 text-xs text-slate-400">
          <span className="font-semibold text-slate-200">{selectedModel.name}</span>
          <span>{selectedModel.metadata?.config?.sequence_length ? `sequence ${selectedModel.metadata.config.sequence_length}` : "331-token vocabulary"}</span>
          {selectedModel.metadata?.config?.hidden_dim && <span>hidden {selectedModel.metadata.config.hidden_dim}</span>}
          {selectedModel.metadata?.training_summary?.test_recall !== undefined && <span>test recall {(selectedModel.metadata.training_summary.test_recall * 100).toFixed(1)}%</span>}
          {selectedModel.metadata?.training_summary?.test_false_alarm_rate !== undefined && <span>test FAR {(selectedModel.metadata.training_summary.test_false_alarm_rate * 100).toFixed(2)}%</span>}
          {selectedModel.metadata?.training_summary?.best_epoch && <span>best epoch {selectedModel.metadata.training_summary.best_epoch}</span>}
        </div>}

        <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-5">
          <Metric label="Replay status" value={status.toUpperCase()} tone={status === "running" ? "text-signal" : "text-slate-100"} />
          <Metric label="Event position" value={event ? `${event.position.toLocaleString()} / ${event.total.toLocaleString()}` : "—"} />
          <Metric label="Current score" value={`${(score * 100).toFixed(1)}%`} tone={alertState ? "text-danger" : "text-cyan"} />
          <Metric label="Threshold" value={`${(threshold * 100).toFixed(1)}%`} tone="text-amber" />
          <Metric label="First alert" value={firstAlert ? `${(firstAlert.trace_fraction * 100).toFixed(1)}%` : "Not yet"} tone={firstAlert ? "text-danger" : "text-slate-400"} />
        </div>

        <div className="mb-5 grid gap-5 xl:grid-cols-[1.4fr_0.8fr]">
          <section className="overflow-hidden rounded-xl border border-line bg-panel/70">
            <div className="flex items-center justify-between border-b border-line px-5 py-4">
              <div><h2 className="font-semibold text-white">Live event stream</h2><p className="text-xs text-slate-500">Stored process-call order · newest first</p></div>
              <div className="flex items-center gap-2"><button onClick={() => send("pause")} className="rounded-md border border-line p-2 text-slate-300 hover:bg-slate-800"><CirclePause size={16} /></button><button onClick={() => send("resume")} className="rounded-md border border-line p-2 text-slate-300 hover:bg-slate-800"><CirclePlay size={16} /></button><button onClick={() => send("reset")} className="rounded-md border border-line p-2 text-slate-300 hover:bg-slate-800"><RotateCcw size={16} /></button></div>
            </div>
            <div className="h-[430px] overflow-y-auto">
              {latestEvents.length === 0 ? <div className="flex h-full items-center justify-center text-sm text-slate-600">Start a replay to inspect incoming telemetry.</div> : latestEvents.map((item) => (
                <div key={`${item.position}-${item.api}`} className={`flex items-center gap-4 border-b border-line/60 px-5 py-3 text-sm ${item.file_related ? "bg-cyan/[0.04]" : ""}`}>
                  <span className="w-12 text-right font-mono text-xs text-slate-600">#{item.position}</span>
                  <span className={`h-2 w-2 rounded-full ${item.file_related ? "bg-cyan" : "bg-slate-700"}`} />
                  <span className="min-w-0 flex-1 truncate font-mono text-slate-200">{formatApi(item.api)}</span>
                  <span className="hidden text-xs text-slate-500 sm:block">{item.operation_kind}</span>
                  <span className="text-xs text-slate-600">P:{item.process_id}</span>
                  <ChevronRight size={14} className="text-slate-700" />
                </div>
              ))}
            </div>
          </section>

          <section className="space-y-5">
            <div className={`rounded-xl border p-5 ${alertState ? "border-danger/60 bg-danger/[0.08]" : "border-line bg-panel/70"}`}>
              <div className="flex items-center justify-between"><div className="flex items-center gap-2 text-sm font-semibold text-white"><Gauge size={17} className={alertState ? "text-danger" : "text-cyan"} /> Detection signal</div><span className={`rounded-full px-2 py-1 text-[10px] font-semibold tracking-wider ${alertState ? "bg-danger/15 text-rose-200" : "bg-signal/10 text-lime-200"}`}>{alertState ? "ALERT" : "NO ALERT"}</span></div>
              <div className="mt-6 h-3 overflow-hidden rounded-full bg-slate-800"><div className={`h-full rounded-full transition-all ${alertState ? "bg-danger" : "bg-cyan"}`} style={{ width: `${Math.min(100, score * 100)}%` }} /></div>
              <div className="mt-2 flex justify-between text-xs text-slate-500"><span>0</span><span>threshold {(threshold * 100).toFixed(1)}%</span><span>100</span></div>
              {firstAlert && <div className="mt-5 grid grid-cols-2 gap-3"><Metric label="Alert event" value={`#${firstAlert.event_position}`} tone="text-danger" /><Metric label="Score at alert" value={`${(firstAlert.score * 100).toFixed(1)}%`} tone="text-danger" /></div>}
            </div>
            <div className="rounded-xl border border-line bg-panel/70 p-5">
              <div className="flex items-center gap-2 text-sm font-semibold text-white"><Activity size={17} className="text-cyan" /> Observable activity</div>
              <p className="mt-1 text-xs text-slate-500">Telemetry counters · not confirmed physical damage</p>
              <div className="mt-4 grid grid-cols-2 gap-3">
                <Metric label="Writes" value={activity.writes} tone="text-rose-200" /><Metric label="Reads" value={activity.reads} tone="text-cyan" />
                <Metric label="Deletes" value={activity.deletes} tone="text-amber" /><Metric label="Renames" value={activity.renames} tone="text-amber" />
                <Metric label="File information" value={activity.file_information} /><Metric label="Candidate generations" value={generations} />
              </div>
              <div className="mt-4 flex items-center gap-2 text-xs text-slate-500"><FileWarning size={14} /> {ambiguities.toLocaleString()} ambiguous or unresolved observations</div>
            </div>
          </section>
        </div>

        <section className="rounded-xl border border-line bg-panel/70 p-5">
          <div className="mb-4 flex items-center justify-between"><div><h2 className="font-semibold text-white">Trace timeline</h2><p className="text-xs text-slate-500">Progress through the selected recorded report</p></div><div className="text-sm tabular-nums text-slate-300">{progress.toFixed(1)}%</div></div>
          <div className="relative h-3 overflow-hidden rounded-full bg-slate-800"><div className="h-full bg-cyan transition-all" style={{ width: `${progress}%` }} />{firstAlert && <div className="absolute top-0 h-full w-1 bg-danger" style={{ left: `${firstAlert.trace_fraction * 100}%` }} />}</div>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500"><span className="flex items-center gap-2"><ShieldCheck size={14} className="text-signal" /> Ground truth: {selected?.class_label ?? "not selected"} (dataset label)</span><span>Speed: {speed} events/sec <input aria-label="replay speed" type="range" min="0" max="100" value={speed} onChange={(e) => { setSpeed(Number(e.target.value)); send("set_speed", { speed: Number(e.target.value) }); }} className="ml-2 align-middle accent-cyan" /></span><span>{selected?.relative_report_path ?? "No trace selected"}</span></div>
        </section>
      </div>
    </main>
  );
}
