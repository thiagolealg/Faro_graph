"use strict";
const form = document.querySelector("#analysis-form");
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
const coverageLabels = { lexical_only:"Somente URL", lexical_and_submitted_html:"URL + HTML enviado" };
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
    const options = {method:"POST",headers:{"Content-Type":"application/json","X-Faro-Api-Key":key},body:JSON.stringify({url,observed_html})};
    const response = await fetch("/v1/analyses", options);
    const result = await response.json();
    if (!response.ok) throw new Error(Array.isArray(result.detail) ? JSON.stringify(result.detail) : result.detail || "Falha na análise");
    const graphResponse = await fetch(`/v1/analyses/${result.analysis_id}/graph`, {headers:{"X-Faro-Api-Key":key}});
    const graph = graphResponse.ok ? await graphResponse.json() : {edges:[]};
    text("#risk-level", levels[result.assessment.level] || result.assessment.level);
    text("#score", `${result.assessment.score}/100`);
    text("#confidence", confidenceLabels[result.assessment.confidence] || result.assessment.confidence);
    text("#coverage", coverageLabels[result.assessment.coverage] || result.assessment.coverage);
    text("#recommendation", result.assessment.recommendation);
    text("#analysis-id", `ID: ${result.analysis_id} • ${result.hostname}`);
    for (const id of ["#evidence","#graph","#limitations","#dns","#rdap","#ct"]) document.querySelector(id).replaceChildren();
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
    result.limitations.forEach(value => addItem(document.querySelector("#limitations"), value));
    output.classList.remove("hidden");
    text("#status", "Triagem concluída.");
  } catch (error) { text("#status", `Não foi possível concluir: ${error.message}`); }
  finally { button.disabled = false; }
});
