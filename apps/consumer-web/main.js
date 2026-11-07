"use strict";
const form = document.querySelector("#analysis-form");
let currentAnalysisId = null;
let selectedCaseId = null;
let oidcMode = false;
let csrfToken = null;
const securityHeaders = (method = "GET") => {
  if (oidcMode) return ["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())
    ? {"X-Faro-CSRF": csrfToken || ""} : {};
  return {"X-Faro-Api-Key": document.querySelector("#token").value};
};
async function initAuthentication() {
  try {
    const response = await fetch("/v1/auth/config", {cache:"no-store"});
    if (!response.ok) throw new Error("Falha ao verificar modo de autenticação");
    const cfg = await response.json();
    oidcMode = cfg.oidc_enabled === true;
    if (!oidcMode) return;
    document.querySelector("#legacy-auth").classList.add("hidden");
    document.querySelector("#token").required = false;
    document.querySelector("#web-auth").classList.remove("hidden");
    const sessionResponse = await fetch("/v1/auth/session", {cache:"no-store"});
    if (sessionResponse.ok) {
      const session = await sessionResponse.json();
      csrfToken = session.csrf_token;
      text("#web-auth-status", `Conectado: ${session.actor_id} • ${session.tenant_id} (${session.role})`);
      document.querySelector("#web-logout").classList.remove("hidden");
    } else {
      text("#web-auth-status", "Entre com sua identidade corporativa para consultar os dados.");
      document.querySelector("#web-login").classList.remove("hidden");
      document.querySelector("#submit").disabled = true;
    }
  } catch (error) {
    text("#status", `Autenticação indisponível: ${error.message}`);
    document.querySelector("#status").classList.remove("hidden");
    document.querySelector("#submit").disabled = true;
  }
}
document.querySelector("#web-logout").addEventListener("click", async () => {
  try {
    await fetch("/v1/auth/logout", {method:"POST", headers:securityHeaders("POST")});
  } finally {
    csrfToken = null;
    location.reload();
  }
});
initAuthentication();
const status = document.querySelector("#status");
const output = document.querySelector("#output");
const text = (selector, value) => { document.querySelector(selector).textContent = String(value); };
const addItem = (list, value) => {
  const li = document.createElement("li");
  li.textContent = value;
  list.appendChild(li);
};
const levels = { inconclusive:"Inconclusivo", low:"Baixo", moderate:"Moderado", high:"Alto", critical:"Crítico" };
const confidenceLabels = { low:"Baixa", medium:"Média", high:"Alta" };
const coverageLabels = { lexical_only:"Somente URL", lexical_and_submitted_html:"URL + HTML enviado", lexical_and_feed:"URL + feed", lexical_html_and_feed:"URL + HTML + feed" };
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.classList.remove("hidden");
  output.classList.add("hidden");
  text("#status", "Analisando sinais locais...");
  const button = document.querySelector("#submit");
  button.disabled = true;
  const key = document.querySelector("#token").value;
  const url = document.querySelector("#url").value;
  const observed_html = document.querySelector("#observed_html").value || null;
  try {
    const options = {method:"POST",headers:{"Content-Type":"application/json",...securityHeaders("POST")},body:JSON.stringify({url,observed_html})};
    const response = await fetch("/v1/analyses", options);
    const result = await response.json();
    if (!response.ok) throw new Error(Array.isArray(result.detail) ? JSON.stringify(result.detail) : result.detail || "Falha na análise");
    currentAnalysisId = result.analysis_id;
    const graphResponse = await fetch(`/v1/analyses/${result.analysis_id}/graph`, {headers:securityHeaders()});
    const graph = graphResponse.ok ? await graphResponse.json() : {edges:[]};
    text("#risk-level", levels[result.assessment.level] || result.assessment.level);
    text("#score", `${result.assessment.score}/100`);
    text("#confidence", confidenceLabels[result.assessment.confidence] || result.assessment.confidence);
    text("#coverage", coverageLabels[result.assessment.coverage] || result.assessment.coverage);
    text("#recommendation", result.assessment.recommendation);
    text("#analysis-id", `ID: ${result.analysis_id} • ${result.hostname}`);
    for (const id of ["#evidence","#graph","#limitations","#dns","#rdap","#ct","#reputation"]) document.querySelector(id).replaceChildren();
    for (const ev of result.evidence) addItem(document.querySelector("#evidence"), `${ev.title}: ${ev.detail} [${ev.source}]`);
    if (!result.evidence.length) addItem(document.querySelector("#evidence"), "Nenhum sinal detectado nesta cobertura restrita. Isso não comprova segurança.");
    for (const edge of graph.edges) addItem(document.querySelector("#graph"), `${edge.source} → ${edge.target} (${edge.relationship}; ${edge.certainty})`);
    if (result.passive_dns) {
      addItem(document.querySelector("#dns"), `Estado: ${result.passive_dns.status} — ${result.passive_dns.note}`);
      for (const record of result.passive_dns.records) addItem(document.querySelector("#dns"), `${record.type}: ${record.value} (TTL: ${record.ttl}s)`);
      if (result.passive_dns.error_codes.length) addItem(document.querySelector("#dns"), `Consultas indisponíveis ou filtradas: ${result.passive_dns.error_codes.join(", ")}`);
    }
    if (result.rdap) {
      const r = result.rdap;
      addItem(document.querySelector("#rdap"), `Estado: ${r.status} — ${r.note}`);
      if (r.checked_at) addItem(document.querySelector("#rdap"), `Consultado: ${r.checked_at}`);
      if (r.registered_on) addItem(document.querySelector("#rdap"), `Registrado: ${r.registered_on}`);
      if (r.changed_on) addItem(document.querySelector("#rdap"), `Alterado: ${r.changed_on}`);
      if (r.expires_on) addItem(document.querySelector("#rdap"), `Expira: ${r.expires_on}`);
      for (const host of r.nameservers) addItem(document.querySelector("#rdap"), `Nameserver: ${host}`);
      if (r.error_codes.length) addItem(document.querySelector("#rdap"), `Limites/erros: ${r.error_codes.join(", ")}`);
    }
    if (result.certificate_transparency) {
      const c = result.certificate_transparency;
      addItem(document.querySelector("#ct"), `Estado: ${c.status} — ${c.note}`);
      if (c.checked_at) addItem(document.querySelector("#ct"), `Consultado: ${c.checked_at}`);
      addItem(document.querySelector("#ct"), `Certificados históricos encontrados: ${c.certificates_matched}`);
      if (c.latest_not_before) addItem(document.querySelector("#ct"), `Emissão mais recente observada: ${c.latest_not_before}`);
      for (const issuer of c.issuers) addItem(document.querySelector("#ct"), `Emissor: ${issuer}`);
      if (c.error_codes.length) addItem(document.querySelector("#ct"), `Limites/erros: ${c.error_codes.join(", ")}`);
    }
    if (result.threat_intel) {
      const i = result.threat_intel;
      addItem(document.querySelector("#reputation"), `Estado: ${i.status} — ${i.note}`);
      for (const m of i.matches) addItem(document.querySelector("#reputation"), `${m.indicator_type}: ${m.category} [${m.source}] (validade: ${m.expires_at})`);
    }
    result.limitations.forEach(value => addItem(document.querySelector("#limitations"), value));
    output.classList.remove("hidden");
    text("#status", "Triagem concluída.");
  } catch (error) { text("#status", `Não foi possível concluir: ${error.message}`); }
  finally { button.disabled = false; }
});


// v0.6 cases UI: never persist credentials or insert untrusted HTML.
const caseHeaders = (method = "GET") => ({"Content-Type":"application/json",...securityHeaders(method)});
async function caseApi(path, options = {}) {
  const response = await fetch(path, { ...options, headers: caseHeaders(options.method || "GET"), cache: "no-store" });
  const body = await response.json();
  if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Operação recusada pela API");
  return body;
}
function caseMessage(message) { text("#case-status", message); }
async function selectCase(caseId) {
  const item = await caseApi(`/v1/cases/${caseId}`);
  selectedCaseId = item.id;
  document.querySelector("#case-workspace").classList.remove("hidden");
  text("#case-selected", item.title);
  text("#case-info", `Estado: ${item.status} • ${item.analysis_ids.length} análise(s) • ${item.reviews.length} revisão(ões)`);
  const graph = await caseApi(`/v1/cases/${caseId}/graph`);
  const list = document.querySelector("#case-correlations");
  list.replaceChildren();
  for (const finding of graph.shared_indicators) {
    addItem(list, `${finding.node_id} (${finding.analysis_ids.length} análises; ${finding.interpretation})`);
  }
  if (graph.shared_indicators.length === 0) addItem(list, "Sem indicadores técnicos repetidos nas análises vinculadas.");
  caseMessage("Caso carregado. Coincidências não identificam responsáveis.");
}
async function refreshCases() {
  const items = await caseApi("/v1/cases");
  const list = document.querySelector("#case-list");
  list.replaceChildren();
  for (const item of items) {
    const li = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `${item.title} (${item.status})`;
    button.addEventListener("click", () => selectCase(item.id).catch(err => caseMessage(err.message)));
    li.appendChild(button);
    list.appendChild(li);
  }
  if (!items.length) addItem(list, "Nenhum caso nesta organização.");
}
document.querySelector("#case-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!currentAnalysisId) { caseMessage("Faça uma análise antes de criar o caso."); return; }
  try {
    const item = await caseApi("/v1/cases", {method:"POST",body:JSON.stringify({
      title: document.querySelector("#case-title").value, analysis_ids:[currentAnalysisId]})});
    await refreshCases();
    await selectCase(item.id);
    caseMessage("Caso criado e análise associada.");
  } catch (err) { caseMessage(err.message); }
});
document.querySelector("#case-refresh").addEventListener("click", () => refreshCases().catch(err => caseMessage(err.message)));
document.querySelector("#case-link").addEventListener("click", async () => {
  if (!selectedCaseId || !currentAnalysisId) { caseMessage("Selecione um caso e faça uma análise."); return; }
  try {
    await caseApi(`/v1/cases/${selectedCaseId}/analyses`, {method:"POST",body:JSON.stringify({analysis_id:currentAnalysisId})});
    await selectCase(selectedCaseId);
    caseMessage("Análise associada ao caso.");
  } catch (err) { caseMessage(err.message); }
});
document.querySelector("#case-review-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!selectedCaseId) return;
  try {
    await caseApi(`/v1/cases/${selectedCaseId}/reviews`, {method:"POST",body:JSON.stringify({
      decision:document.querySelector("#case-review-decision").value,
      rationale:document.querySelector("#case-review-rationale").value})});
    document.querySelector("#case-review-rationale").value = "";
    await selectCase(selectedCaseId);
    caseMessage("Revisão registrada com data e autoria interna.");
  } catch (err) { caseMessage(err.message); }
});
document.querySelector("#case-export").addEventListener("click", async () => {
  if (!selectedCaseId) return;
  try {
    const documentBody = await caseApi(`/v1/cases/${selectedCaseId}/dossier`);
    const file = new Blob([JSON.stringify(documentBody,null,2)], {type:"application/json"});
    const url = URL.createObjectURL(file);
    const a = document.createElement("a");
    a.href = url;
    a.download = `faro-case-${selectedCaseId}.json`;
    a.click();
    URL.revokeObjectURL(url);
    caseMessage("Dossiê exportado. SHA-256 não é assinatura digital.");
  } catch (err) { caseMessage(err.message); }
});
