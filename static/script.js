/* =========================================================
   Incident Dashboard – client script
   ========================================================= */

/* ---------- DOM helpers ---------- */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

/* ---------- Application state ---------- */

let incidents = [];
let selected = null; // currently opened incident (or null)
let blastRadiusResults = {}; // Blast Radius results, keyed by incident id

/* ---------- Generic utilities ---------- */

/** Escape a value so it is safe to insert into HTML. */
const ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function safe(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ESCAPE_MAP[ch]);
}

/** Convert a date string into "just now", "5m ago", "3h ago", "2d ago". */
function timeAgo(value) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return '—';

  const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60000));

  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return `${Math.floor(minutes / 1440)}d ago`;
}

/** Map a severity label to its CSS class. */
function severityClass(severity) {
  const classes = {
    Critical: 'critical',
    High: 'high',
    Medium: 'medium',
    Low: 'low',
    Informational: 'info',
  };
  return classes[severity] || 'info';
}

/** Map a status label to its CSS class. */
function statusClass(status) {
  if (status === 'Resolved') return 'resolved';
  if (status === 'Monitoring') return 'monitoring';
  return 'active';
}

/** fetch() wrapper that sends/receives JSON and throws on error responses. */
async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await response.json();

  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

/** Show a temporary toast message. */
function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2900);
}

/* ---------- Data loading ---------- */

async function load() {
  try {
    const data = await api('/api/incidents');
    incidents = data.incidents;

    renderMetrics();
    renderRows();
    renderCrew();
    renderReports();

    const statusIncidentId = selected?.id || incidents[0]?.id;
    if (statusIncidentId) {
      await refreshAgentStatuses(statusIncidentId);
    }

    // Keep the open detail view in sync with fresh data
    if (selected) {
      const updated = incidents.find((i) => i.id === selected.id);
      if (updated) {
        selected = updated;
        renderDetail();
      }
    }
  } catch (error) {
    toast(error.message);
  }
}

/** Load the latest saved Blast Radius assessment for an incident. */
async function loadBlastRadiusAssessment(incidentId) {
  try {
    const data = await api(`/api/incidents/${encodeURIComponent(incidentId)}/blast-radius`);

    // Prevent an old request from updating another incident
    if (selected?.id !== incidentId) return;

    if (data.assessment) {
      blastRadiusResults[incidentId] = data.assessment;
    } else {
      delete blastRadiusResults[incidentId];
    }

    renderDetail(); // display the saved assessment
  } catch (error) {
    console.error('Unable to load saved Blast Radius assessment:', error);
  }
}

/* ---------- Dashboard: metrics ---------- */

function renderMetrics() {
  const criticalOrHigh = incidents.filter(
    (i) => i.severity === 'Critical' || i.severity === 'High'
  ).length;
  const active = incidents.filter((i) => i.status !== 'Resolved').length;
  const resolved = incidents.filter((i) => i.status === 'Resolved').length;

  // [label, value, footnote, icon, color]
  const metrics = [
    ['TOTAL INCIDENTS', incidents.length, 'All sample alerts', '◈', 'blue'],
    ['CRITICAL / HIGH', criticalOrHigh, 'Requires attention', '↗', 'red'],
    ['ACTIVE / MONITORING', active, 'Awaiting or in verification', '◷', 'amber'],
    ['VERIFIED RESOLVED', resolved, 'Follow-up evidence checked', '✓', 'green'],
  ];

  $('#metrics').innerHTML = metrics
    .map(
      ([label, value, footnote, icon, color]) => `
        <article class="metric-card">
          <div class="metric-top">
            <span>${label}</span>
            <i class="metric-icon ${color}">${icon}</i>
          </div>
          <div class="metric-value">${value}</div>
          <div class="metric-foot">
            <span class="metric-dot ${color}"></span>${footnote}
          </div>
        </article>`
    )
    .join('');

  $('#incidentNavCount').textContent = incidents.length;
}

/* ---------- Dashboard: incident table ---------- */

function getFilteredIncidents() {
  const query = ($('#searchInput')?.value || '').toLowerCase();
  const severity = $('#severityFilter')?.value || '';

  return incidents.filter((i) => {
    const matchesSeverity = !severity || i.severity === severity;
    const haystack = `${i.id} ${i.title} ${i.source} ${i.asset}`.toLowerCase();
    return matchesSeverity && haystack.includes(query);
  });
}

function incidentRowHtml(i) {
  return `
    <tr class="incident-row" data-id="${safe(i.id)}">
      <td>
        <div class="incident-name">
          <span class="alert-glyph ${severityClass(i.severity)}">⌁</span>
          <span>
            <strong>${safe(i.title)}</strong>
            <small>${safe(i.id)} <em>· SAMPLE</em></small>
          </span>
        </div>
      </td>
      <td>
        <span class="severity ${severityClass(i.severity)}"><i></i>${safe(i.severity)}</span>
      </td>
      <td>
        <span class="source-cell">${safe(i.source)}</span>
        <small class="asset-cell">${safe(i.asset)}</small>
      </td>
      <td>
        <span class="status ${statusClass(i.status)}"><i></i>${safe(i.status)}</span>
      </td>
      <td class="time-cell">${timeAgo(i.created_at)}</td>
      <td><button class="row-arrow" aria-label="Open incident">→</button></td>
    </tr>`;
}

function renderRows() {
  const list = getFilteredIncidents();

  $('#tableCount').textContent = `${list.length} incident${list.length === 1 ? '' : 's'}`;
  $('#emptyState').classList.toggle('hidden', list.length > 0);
  $('#incidentRows').innerHTML = list.map(incidentRowHtml).join('');
  // Row clicks are handled by one delegated listener (see "Event wiring").
}

/* ---------- Incident detail view ---------- */

function openIncident(id) {
  selected = incidents.find((i) => i.id === id);
  if (!selected) return;

  showView('incident');
  renderDetail();
  window.location.hash = `incident/${id}`;

  // Retrieve previously saved Blast Radius assessment
  loadBlastRadiusAssessment(id);
}

/* Section 01 – Evidence & investigation + detection/analysis findings */
function evidencePanelHtml(i) {
  const findings = i.findings || {};
  const detection = findings.detection || {};
  const investigation = findings.investigation || {};
  const analysis = findings.analysis || {};

  const eventsHtml = i.evidence
    .map(
      (e) => `
        <div class="event-row">
          <span class="event-time">${safe(e.time || '—')}</span>
          <span class="event-type">${safe(e.type || 'event')}</span>
          <code>${safe(e.source || i.source)}${e.account ? ` · ${safe(e.account)}` : ''}</code>
        </div>`
    )
    .join('');

  const reasoningHtml = (analysis.reasoning || [])
    .map((line) => `<li>${safe(line)}</li>`)
    .join('');

  return `
    <article class="panel">
      <div class="panel-heading">
        <div><span class="panel-index">01</span><h2>Evidence & investigation</h2></div>
        <span class="mini-tag">${investigation.event_count || i.evidence.length} EVENTS</span>
      </div>
      <p class="panel-copy">${safe(investigation.evidence_limit || 'Review of supplied event data only.')}</p>

      <div class="event-list">${eventsHtml}</div>

      <div class="finding-box">
        <div class="finding-label">DETECTION AGENT</div>
        <strong>${safe(detection.alert_title || 'Activity requires review')}</strong>
        <p>${safe(detection.uncertainty || 'Limited sample evidence.')}</p>
      </div>

      <div class="finding-box analysis-box">
        <div class="finding-label">ANALYSIS · ${safe(analysis.confidence || 'low')} confidence</div>
        <strong>${safe(analysis.incident_type || i.incident_type)}</strong>
        <p>${safe(analysis.impact || 'Potential impact requires review.')}</p>
        <ul>${reasoningHtml}</ul>
        <p class="uncertainty">${safe(analysis.uncertainty || 'Evidence is limited.')}</p>
      </div>
    </article>`;
}

/* Section 02 – Triage assessment
   Reads i.triage (if the API provides it) and falls back to values
   derived from severity / analysis so the panel is never empty. */
const PRIORITY_BY_SEVERITY = {
  Critical: 'P1',
  High: 'P2',
  Medium: 'P3',
  Low: 'P4',
  Informational: 'P4',
};

function triagePanelHtml(i) {
  const triage = i.triage || {};
  const analysis = (i.findings || {}).analysis || {};

  const priority = triage.priority || PRIORITY_BY_SEVERITY[i.severity] || 'P4';
  const urgency =
    triage.urgency || (priority === 'P1' || priority === 'P2' ? 'Immediate' : 'Scheduled');
  const confidence = triage.confidence || analysis.confidence || 'low';
  const owner = triage.owner || 'Security on-call';
  const summary =
    triage.summary || analysis.impact || 'Triage requires analyst review of the supplied evidence.';

  const factorsHtml = (triage.factors || analysis.reasoning || [])
    .map((factor) => `<li>${safe(factor)}</li>`)
    .join('');

  return `
    <article class="panel triage-panel">
      <div class="panel-heading">
        <div><span class="panel-index">02</span><h2>Triage assessment</h2></div>
        <span class="mini-tag">${safe(priority)}</span>
      </div>

      <div class="triage-grid">
        <div><small>PRIORITY</small><strong>${safe(priority)}</strong></div>
        <div><small>URGENCY</small><strong>${safe(urgency)}</strong></div>
        <div><small>CONFIDENCE</small><strong>${safe(confidence)}</strong></div>
        <div><small>SUGGESTED OWNER</small><strong>${safe(owner)}</strong></div>
      </div>

      <p class="panel-copy">${safe(summary)}</p>
      ${factorsHtml ? `<ul class="triage-factors">${factorsHtml}</ul>` : ''}
    </article>`;
}

/* Section 03 – Fix proposal
   Reads i.fix_proposal (if the API provides it) and falls back to the
   recommended actions. Proposal only – nothing is executed. */
function fixProposalPanelHtml(i) {
  const fix = i.fix_proposal || {};
  const fallbackSteps = ((i.actions || {}).actions || []).map((a) => a.action);

  const summary =
    fix.summary || 'Proposed remediation based on the analysis. Review before approving.';
  const risk = fix.risk || 'Unknown';
  const rollback = fix.rollback || 'No rollback plan supplied.';

  const stepsHtml = (fix.steps || fallbackSteps)
    .map(
      (step, n) => `
        <li class="fix-step">
          <span class="action-number">0${n + 1}</span>
          <span>${safe(step)}</span>
        </li>`
    )
    .join('');

  return `
    <article class="panel fix-panel">
      <div class="panel-heading">
        <div><span class="panel-index">03</span><h2>Fix proposal</h2></div>
        <span class="mini-tag">PROPOSAL ONLY</span>
      </div>

      <p class="panel-copy">${safe(summary)}</p>
      ${stepsHtml ? `<ol class="fix-steps">${stepsHtml}</ol>` : '<p class="panel-copy">No fix steps available.</p>'}

      <div class="fix-meta">
        <div><small>RISK</small><strong>${safe(risk)}</strong></div>
        <div><small>ROLLBACK</small><strong>${safe(rollback)}</strong></div>
      </div>
      <p class="safe-note">Simulated proposal. No real system will be changed.</p>
    </article>`;
}

/* Section 04 – Blast Radius Analysis */

/** SVG dependency graph: target service on top, direct dependents below. */
function blastRadiusGraphHtml(assessment) {
  if (!assessment) return '';

  const target = assessment.target_service || 'Unknown';
  const dependents = assessment.direct_dependents || [];
  const affected = assessment.affected_services || [];

  const width = 600;
  const rowHeight = 65;
  const height = Math.max(180, 120 + dependents.length * rowHeight);

  const centerX = 300;
  const targetY = 45;
  const targetWidth = 230;
  const nodeWidth = 230;

  let nodes = '';
  let edges = '';

  dependents.forEach((service, index) => {
    const y = 125 + index * rowHeight;

    edges += `
      <line
        x1="${centerX}"
        y1="${targetY + 25}"
        x2="${centerX}"
        y2="${y}"
        stroke="#38bdf8"
        stroke-width="2"
        stroke-dasharray="5 4"
      />`;

    nodes += `
      <rect
        x="${centerX - nodeWidth / 2}"
        y="${y}"
        width="${nodeWidth}"
        height="38"
        rx="8"
        fill="#123c55"
        stroke="#38bdf8"
      />
      <text
        x="${centerX}"
        y="${y + 24}"
        fill="#ffffff"
        text-anchor="middle"
        font-size="13"
      >${safe(service)}</text>`;
  });

  return `
    <div class="finding-box blast-graph">
      <div class="finding-label">SERVICE DEPENDENCY GRAPH</div>

      <svg
        viewBox="0 0 ${width} ${height}"
        width="100%"
        role="img"
        aria-label="Blast radius service dependency graph"
      >
        <rect
          x="${centerX - targetWidth / 2}"
          y="${targetY}"
          width="${targetWidth}"
          height="42"
          rx="8"
          fill="#164e63"
          stroke="#22d3ee"
          stroke-width="2"
        />
        <text
          x="${centerX}"
          y="${targetY + 26}"
          fill="#ffffff"
          text-anchor="middle"
          font-size="14"
          font-weight="bold"
        >${safe(target)}</text>

        ${edges}
        ${nodes}
      </svg>

      <p>Direct dependents: ${dependents.length}</p>
      <p>Total affected services: ${affected.length}</p>
      <small>Simulation only. No infrastructure changes executed.</small>
    </div>`;
}

function blastRadiusPanelHtml(i) {
  const assessment = blastRadiusResults[i.id];

  const services = [
    'authentication-service',
    'admin-portal',
    'finance-api',
    'user-dashboard',
    'notification-service',
  ];

  let resultHtml = '';

  if (assessment) {
    const affected = assessment.affected_services || [];

    resultHtml = `
      <div class="finding-box">
        <div class="finding-label">BLAST RADIUS RESULT</div>
        <strong>Risk Level: ${safe(assessment.risk_level || 'Unknown')}</strong>
        <p>Target: ${safe(assessment.target_service || 'Unknown')}</p>
        <p>Affected Services (${affected.length})</p>
        <ul>${affected.map((service) => `<li>${safe(service)}</li>`).join('')}</ul>
        <small>Simulation only. No infrastructure changes executed.</small>
      </div>`;
  }

  const optionsHtml = services
    .map((service) => `<option value="${safe(service)}">${safe(service)}</option>`)
    .join('');

  return `
    <article class="panel blast-radius-panel">
      <div class="panel-heading">
        <div><span class="panel-index">04</span><h2>Blast Radius Analysis</h2></div>
        <span class="mini-tag">SIMULATION ONLY</span>
      </div>

      <p class="panel-copy">
        Identify dependent services and estimate the potential impact of an incident.
      </p>

      <label class="field-label" for="blastRadiusTarget">Select target service</label>
      <select id="blastRadiusTarget">
        <option value="">Choose a service</option>
        ${optionsHtml}
      </select>

      <button class="button primary full" id="runBlastRadius" type="button">
        Run Blast Radius Analysis →
      </button>

      <div id="blastRadiusResult">${resultHtml}</div>
      ${blastRadiusGraphHtml(assessment)}
    </article>`;
}

/* Section 05 – Workflow timeline */
function timelinePanelHtml(i) {
  const itemsHtml = i.timeline
    .map(
      (t) => `
        <div class="timeline-item">
          <span class="timeline-dot"></span>
          <div>
            <strong>${safe(t.label)}</strong>
            <p>${safe(t.detail)}</p>
            <time>${new Date(t.at).toLocaleString()}</time>
          </div>
        </div>`
    )
    .join('');

  return `
    <article class="panel">
      <div class="panel-heading">
        <div><span class="panel-index">05</span><h2>Workflow timeline</h2></div>
      </div>
      <div class="timeline">${itemsHtml}</div>
    </article>`;
}

/* Section 06 – Response plan (approval) */
function responsePanelHtml(i) {
  const actions = i.actions || {};
  const approved = Boolean(i.approved_at);

  const actionsHtml = (actions.actions || [])
    .map(
      (x, n) => `
        <div class="action-item">
          <div class="action-number">0${n + 1}</div>
          <div>
            <strong>${safe(x.action)}</strong>
            <p>${safe(x.reason)}</p>
            <small>Risk: ${safe(x.risk)}</small>
          </div>
        </div>`
    )
    .join('');

  const approveButton = approved
    ? ''
    : `<button class="button primary full" id="approveAction">Approve simulated response <span>→</span></button>`;

  return `
    <article class="panel response-panel">
      <div class="panel-heading">
        <div><span class="panel-index">06</span><h2>Response plan</h2></div>
      </div>

      <div class="approval-banner ${approved ? 'approved' : ''}">
        <span>${approved ? '✓' : '!'}</span>
        <div>
          <strong>${approved ? 'Simulated approval recorded' : 'Approval required'}</strong>
          <small>${approved ? 'No real system was changed.' : 'Actions will not execute against real systems.'}</small>
        </div>
      </div>

      <div class="action-list">${actionsHtml}</div>
      ${approveButton}
      <p class="safe-note">${safe(actions.note || 'Simulated recommendation only; no external action is available.')}</p>
    </article>`;
}

/* Section 07 – Verification */
function verificationPanelHtml(i) {
  const approved = Boolean(i.approved_at);

  const resultHtml = i.verification
    ? `<div class="verification-result ${i.verification.result.toLowerCase().replace(' ', '-')}">
         <strong>${safe(i.verification.result)}</strong>
         <span>${safe(i.verification.explanation)}</span>
       </div>`
    : '';

  return `
    <article class="panel verification-panel">
      <div class="panel-heading">
        <div><span class="panel-index">07</span><h2>Verify response</h2></div>
      </div>
      <p class="panel-copy">Provide follow-up sample events to assess whether matching source activity continues.</p>

      <label class="field-label" for="followupEvents">Follow-up events (JSON array)</label>
      <textarea id="followupEvents" rows="5" placeholder='[{"type":"login_failed","source":"198.51.100.24"}]'>[]</textarea>

      ${resultHtml}

      <button class="button secondary full" id="verifyAction" ${approved ? '' : 'disabled'}>
        Run verification <span>→</span>
      </button>
      ${approved ? '' : '<small class="disabled-hint">Approval is required before verification.</small>'}
    </article>`;
}

function renderDetail() {
  const i = selected;
  if (!i) return;

  $('#crumb').textContent = i.id;

  $('#incidentDetail').innerHTML = `
    <div class="detail-heading">
      <div>
        <div class="eyebrow">
          INCIDENT DETAIL <span>·</span> ${safe(i.id)} <span class="sample-pill">SAMPLE</span>
        </div>
        <h1>${safe(i.title)}<span class="period">.</span></h1>
        <p>${safe(i.description)}</p>
      </div>
      <div class="detail-actions">
        <button class="button secondary" id="detailReport">Export report</button>
      </div>
    </div>

    <div class="detail-strip">
      <span class="severity ${severityClass(i.severity)}"><i></i>${safe(i.severity)} severity</span>
      <span class="status ${statusClass(i.status)}"><i></i>${safe(i.status)}</span>
      <span>◉ ${safe(i.source)}</span>
      <span>▣ ${safe(i.asset)}</span>
      <span>◷ ${timeAgo(i.created_at)}</span>
    </div>

    <div class="detail-layout">
      <div class="detail-main">
        ${evidencePanelHtml(i)}
        ${triagePanelHtml(i)}
        ${fixProposalPanelHtml(i)}
        ${blastRadiusPanelHtml(i)}
        ${timelinePanelHtml(i)}
      </div>
      <aside class="detail-side">
        ${responsePanelHtml(i)}
        ${verificationPanelHtml(i)}
      </aside>
    </div>`;

  bindDetailActions(i);
}

/** Attach click handlers to the buttons inside the detail view. */
function bindDetailActions(i) {
  // Approve simulated response
  $('#approveAction')?.addEventListener('click', async () => {
    try {
      await api(`/api/incidents/${i.id}/approve`, { method: 'POST', body: '{}' });
      toast('Simulated approval recorded');
      await load();
    } catch (error) {
      toast(error.message);
    }
  });

  // Run Blast Radius Analysis
  $('#runBlastRadius')?.addEventListener('click', async () => {
    const button = $('#runBlastRadius');
    const targetService = $('#blastRadiusTarget').value;

    if (!targetService) {
      toast('Please select a target service.');
      return;
    }

    try {
      button.disabled = true;
      button.textContent = 'Calculating blast radius...';

      const data = await api(`/api/incidents/${i.id}/blast-radius`, {
        method: 'POST',
        body: JSON.stringify({ target_service: targetService }),
      });

      if (!data.ok || !data.assessment) {
        throw new Error('Blast Radius assessment was not returned.');
      }

      // Store result for this incident
      blastRadiusResults[i.id] = {
        ...data.assessment,
        target_service: targetService,
      };

      toast('Blast Radius Analysis completed successfully.');
      renderDetail(); // re-render to show result + graph
    } catch (error) {
      toast(error.message);
      button.disabled = false;
      button.textContent = 'Run Blast Radius Analysis →';
    }
  });

  // Run verification
  $('#verifyAction')?.addEventListener('click', async () => {
    try {
      const events = JSON.parse($('#followupEvents').value);
      if (!Array.isArray(events)) throw new Error('Follow-up data must be a JSON array.');

      const result = await api(`/api/incidents/${i.id}/verify`, {
        method: 'POST',
        body: JSON.stringify({ events }),
      });
      toast(`Verification: ${result.verification.result}`);
      await load();
    } catch (error) {
      toast(error instanceof SyntaxError ? 'Follow-up data is not valid JSON.' : error.message);
    }
  });

  // Export report
  $('#detailReport')?.addEventListener('click', () => showReport(i.id));
}

/* ---------- Agent crew view ---------- */

function renderCrew() {
  // [name, description, state, icon]
  const agents = [
    ['Detection', 'Flags suspicious patterns in supplied event data', 'completed', '◇'],
    ['Investigation', 'Correlates event fields and affected assets', 'completed', '⌕'],
    ['Analysis', 'Classifies severity with explicit uncertainty', 'completed', '⌁'],
    ['Response', 'Recommends containment; waits for human approval', 'waiting_approval', '↗'],
    ['Verification', 'Checks only supplied follow-up events', 'idle', '✓'],
    ['Reporting', 'Builds a timeline and exportable incident record', 'ready', '▧'],
  ];

  $('#crewGrid').innerHTML = agents
    .map(
      ([name, description, state, icon]) => `
        <article class="crew-card">
          <div class="crew-top">
            <span class="crew-icon">${icon}</span>
            <span class="agent-state ${state}" data-agent-status="${name}">
              <i></i>${state.replaceAll('_', ' ')}
            </span>
          </div>
          <h3>${name} Agent</h3>
          <p>${description}</p>
          <div class="crew-footer"><span>LOCAL RULE-BASED DEMO</span><span>→</span></div>
        </article>`
    )
    .join('');
}

/** Fetch live agent statuses for an incident and update the crew cards. */
async function refreshAgentStatuses(incidentId) {
  try {
    const response = await fetch(`/api/incidents/${incidentId}/agent-statuses`);
    if (!response.ok) throw new Error('Unable to fetch agent statuses');

    const data = await response.json();

    Object.entries(data.agents).forEach(([agent, status]) => {
      const element = $(`[data-agent-status="${agent}"]`);
      if (!element) return;

      element.className = `agent-state ${status.toLowerCase().replaceAll(' ', '-')}`;
      element.innerHTML = `<i></i>${safe(status)}`;
    });
  } catch (error) {
    console.error('Agent status update failed:', error);
  }
}

/* ---------- Reports view ---------- */

function renderReports() {
  const rowsHtml = incidents
    .map(
      (i) => `
        <article class="report-row">
          <div class="report-icon">▧</div>
          <div class="report-meta">
            <strong>${safe(i.title)}</strong>
            <span>${safe(i.id)} · ${safe(i.severity)} · ${safe(i.status)} · Sample data</span>
          </div>
          <button class="button secondary report-open" data-id="${safe(i.id)}">Open report <span>↗</span></button>
        </article>`
    )
    .join('');

  $('#reportList').innerHTML = rowsHtml || '<div class="empty">No reports available.</div>';

  $$('.report-open').forEach((button) =>
    button.addEventListener('click', () => showReport(button.dataset.id))
  );
}

async function showReport(id) {
  try {
    const report = await api(`/api/incidents/${id}/report`);
    $('#reportTitle').textContent = report.title;
    $('#reportContent').textContent = JSON.stringify(report, null, 2);
    $('#reportDialog').showModal();
  } catch (error) {
    toast(error.message);
  }
}

/* ---------- View switching ---------- */

function showView(name) {
  const views = ['dashboard', 'incident', 'crew', 'reports'];
  views.forEach((view) => $(`#${view}View`).classList.toggle('hidden', view !== name));

  const labels = {
    dashboard: 'Overview',
    incident: selected?.id || 'Incident',
    crew: 'Agent crew',
    reports: 'Reports',
  };
  $('#crumb').textContent = labels[name];

  // The "incident" view highlights the "incidents" nav link
  const activeNav = name === 'incident' ? 'incidents' : name;
  $$('.nav-link').forEach((link) =>
    link.classList.toggle('active', link.dataset.view === activeNav)
  );
}

/* ---------- Event wiring ---------- */

// Sidebar navigation
$('#nav').addEventListener('click', (e) => {
  const link = e.target.closest('[data-view]');
  if (!link) return;

  e.preventDefault();
  selected = null;

  const view = link.dataset.view === 'incidents' ? 'dashboard' : link.dataset.view;
  showView(view);
  window.location.hash = link.dataset.view;

  if (link.dataset.view === 'incidents') $('#searchInput').focus();
});

// Filters, refresh, back, notice
$('#searchInput').addEventListener('input', renderRows);
$('#severityFilter').addEventListener('change', renderRows);
$('#refreshBtn').addEventListener('click', load);
$('#backDashboard').addEventListener('click', () => {
  selected = null;
  showView('dashboard');
  window.location.hash = 'dashboard';
});
$('#dismissNotice').addEventListener('click', () => $('.notice').remove());

// Open an incident when a table row is clicked
$('#incidentRows').addEventListener('click', (e) => {
  const row = e.target.closest('.incident-row');
  if (row) openIncident(row.dataset.id);
});

// New incident dialog
$('#newIncidentBtn').addEventListener('click', () => $('#newIncidentDialog').showModal());

$('#incidentForm').addEventListener('submit', async (e) => {
  if (e.submitter?.value === 'cancel') return;
  e.preventDefault();

  try {
    const form = new FormData(e.currentTarget);
    const events = JSON.parse(form.get('events'));
    if (!Array.isArray(events)) throw new Error('Event data must be a JSON array.');

    const result = await api('/api/incidents', {
      method: 'POST',
      body: JSON.stringify({
        title: form.get('title'),
        source: form.get('source'),
        asset: form.get('asset'),
        description: form.get('description'),
        events,
      }),
    });

    $('#newIncidentDialog').close();
    toast('Sample incident analyzed');
    await load();
    openIncident(result.id);
  } catch (error) {
    toast(error instanceof SyntaxError ? 'Event data is not valid JSON.' : error.message);
  }
});

// Report dialog
$('#closeReport').addEventListener('click', () => $('#reportDialog').close());

$('#copyReport').addEventListener('click', async () => {
  await navigator.clipboard.writeText($('#reportContent').textContent);
  toast('Report JSON copied');
});

$('#downloadReport').addEventListener('click', () => {
  const blob = new Blob([$('#reportContent').textContent], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${selected?.id || 'incident'}-report.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

/* ---------- Start ---------- */

load();