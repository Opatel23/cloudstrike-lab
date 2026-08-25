'use client';

import { useEffect, useMemo, useState } from 'react';

type NodeRecord = { id: string; kind: string; name: string; trust: string; critical?: boolean };
type PathStep = { source: string; target: string; relation: string; actor: string; evidence: string; actions: string[] };
type EventRecord = { event_name: string; event_source: string; actor: string; target: string; allowed: boolean; error: string | null; authorization_action: string | null };
type Replay = { status: string; stopped_at: number | null; reason: string | null; events: EventRecord[] };
type Report = {
  lab_id: string;
  inventory: { nodes: NodeRecord[] };
  summary: { before: string; after: string; path_length: number; detections_triggered: number; blocked_at_step: number; blocked_reason: string };
  attack_path: { nodes: string[]; steps: PathStep[] };
  before: Replay;
  after: Replay;
  detections: { rule_id: string; severity: string; mitre_techniques: string[]; event: EventRecord }[];
  remediation: { finding: string; remove_actions: string[]; replacement: string; terraform_file: string };
};

const relationLabels: Record<string, string> = { CAN_ASSUME: 'AssumeRole', CAN_PASS_ROLE: 'PassRole grant', CAN_CREATE_FUNCTION: 'CreateFunction', CAN_READ: 'GetSecretValue' };
const techniqueByEvent: Record<string, string> = { AssumeRole: 'T1078', CreateFunction20150331: 'T1548', GetSecretValue: 'T1552.005' };

function tone(node: NodeRecord): string {
  if (node.critical || node.trust === 'untrusted') return 'red';
  if (node.kind === 'capability') return 'violet';
  if (node.kind === 'lambda') return 'blue';
  return 'amber';
}

export default function Home() {
  const [mode, setMode] = useState<'before' | 'after'>('before');
  const [report, setReport] = useState<Report | null>(null);
  const [loadError, setLoadError] = useState('');
  useEffect(() => {
    fetch('/demo-report.json', { cache: 'no-store' }).then((response) => {
      if (!response.ok) throw new Error(`report request failed (${response.status})`);
      return response.json();
    }).then(setReport).catch((error: Error) => setLoadError(error.message));
  }, []);
  const nodeIndex = useMemo(() => new Map(report?.inventory.nodes.map((node) => [node.id, node]) ?? []), [report]);
  if (loadError) return <main className="loading"><b>Report unavailable</b><span>{loadError}</span><code>Run .\run-demo.ps1 from the project root.</code></main>;
  if (!report) return <main className="loading"><span className="pulse" /> Loading verified scenario report…</main>;

  const replay = mode === 'before' ? report.before : report.after;
  const blocked = replay.status === 'BLOCKED';
  const pathNodes = report.attack_path.nodes.map((id) => nodeIndex.get(id) ?? { id, kind: 'unknown', name: id, trust: 'unknown' });
  const criticalAssets = report.inventory.nodes.filter((node) => node.critical).length;
  return (
    <main className="shell">
      <header className="topbar"><div className="brand"><span className="brandmark">CS</span><span>CloudStrike <b>Lab</b></span></div><nav aria-label="Primary"><a className="active" href="#overview">Overview</a><a href="#path">Attack graph</a><a href="#detections">Telemetry</a><a href="#remediation">Remediation</a></nav><div className="lab-status"><span className="pulse" /> {report.lab_id}</div></header>
      <section id="overview" className="hero"><div><p className="kicker">SCENARIO 001 · IAM PRIVILEGE ESCALATION</p><h1>One attack path.<br /><span>Proven broken.</span></h1><p className="lede">Trace a controlled AWS breach from a compromised workload to a critical secret, then prove least privilege stops the replay.</p></div><div className="verdict-card"><div className="segmented" role="group" aria-label="Replay state"><button aria-pressed={mode === 'before'} className={mode === 'before' ? 'selected danger' : ''} onClick={() => setMode('before')}>Before fix</button><button aria-pressed={mode === 'after'} className={mode === 'after' ? 'selected safe' : ''} onClick={() => setMode('after')}>After fix</button></div><div className={`verdict ${blocked ? 'blocked' : 'success'}`}><span className="verdict-icon">{blocked ? '×' : '→'}</span><div><small>ATTACK REPLAY</small><strong>{replay.status}</strong><p>{blocked ? replay.reason : 'Critical asset reached'}</p></div></div></div></section>
      <section className="metrics" aria-label="Scenario metrics"><article><small>PATH LENGTH</small><strong>{report.summary.path_length}</strong><span>evidence-backed edges</span></article><article><small>DETECTIONS</small><strong>{report.summary.detections_triggered}</strong><span>ATT&CK mapped</span></article><article><small>CRITICAL ASSETS</small><strong>{criticalAssets}</strong><span>demo secret only</span></article><article><small>REMEDIATION</small><strong className="green">100%</strong><span>critical path reduction</span></article></section>
      <section id="path" className="panel graph-panel"><div className="panel-heading"><div><p className="kicker">DISCOVERED PATH</p><h2>Attack graph</h2></div><span className="evidence-chip">{pathNodes.length} nodes · {report.attack_path.steps.length} edges</span></div><div className="graph" data-mode={mode}>{pathNodes.map((node, index) => <div className="graph-unit" key={node.id}><article title={node.id} className={`node ${tone(node)} ${blocked && index >= report.summary.blocked_at_step ? 'muted' : ''}`}><span className="node-index">{String(index + 1).padStart(2, '0')}</span><small>{node.kind.replaceAll('_', ' ').toUpperCase()}</small><strong>{node.name}</strong><p>{node.trust}</p></article>{index < report.attack_path.steps.length && <div title={report.attack_path.steps[index].evidence} className={`edge ${blocked && index + 1 === report.summary.blocked_at_step ? 'denied' : ''}`}><span>{relationLabels[report.attack_path.steps[index].relation] ?? report.attack_path.steps[index].relation}</span><i>{blocked && index + 1 === report.summary.blocked_at_step ? '×' : '›'}</i></div>}</div>)}</div>{blocked && <div className="block-banner"><b>Path severed at edge {report.summary.blocked_at_step}</b><span>{report.summary.blocked_reason}</span></div>}</section>
      <div className="two-col"><section id="detections" className="panel"><div className="panel-heading"><div><p className="kicker">CLOUDTRAIL-SHAPED TELEMETRY</p><h2>Replay timeline</h2></div><span className="live-dot">{replay.events.length} events</span></div><div className="timeline">{replay.events.map((event, index) => <div className="event" key={`${event.event_name}-${index}`}><span className={!event.allowed || event.event_name === 'GetSecretValue' ? 'critical' : event.event_name === 'CreateFunction20150331' ? 'high' : 'info'} /><div><strong>{event.event_name}</strong><p>{event.event_source} · {event.actor}</p></div><code>{!event.allowed ? 'DENIED' : techniqueByEvent[event.event_name] ?? 'INFO'}</code></div>)}</div></section><section id="remediation" className="panel remediation"><div className="panel-heading"><div><p className="kicker">ROOT-CAUSE FIX</p><h2>Least-privilege patch</h2></div><span className="risk">HIGH</span></div><p className="finding">{report.remediation.finding}</p><div className="code-card"><div className="code-title">{report.remediation.terraform_file}</div><pre>{report.remediation.remove_actions.map((action) => <span className="remove" key={action}>- &quot;{action}&quot;{'\n'}</span>)}<span className="keep">  {report.remediation.replacement}</span></pre></div><button className="replay" onClick={() => setMode('after')}>Apply modeled fix &amp; replay <span>→</span></button></section></div>
      <footer><span>CloudStrike Lab · Local authorized simulation · report-driven</span><span>Scenario state: <b>{blocked ? 'Remediated' : 'Vulnerable'}</b></span></footer>
    </main>
  );
}
