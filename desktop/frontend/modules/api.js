// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
// netscope Desktop — API Module
// Handles Tauri IPC invocations and capture control flows.

// Shared application scope. These modules were split out of app.js but never
// received its bindings, so every function here that touched `els`, `state` or
// a helper threw ReferenceError at runtime. The cycle with app.js is safe:
// the imports are only dereferenced inside function bodies, long after both
// modules have finished evaluating.
import { $, STATES, buildCaptureOptions, closeToolModal, els, esc, markCapturing, openToolModal, renderConnections, renderStats, resetSession, saveJSON, setStatus, showNpcapWarning, state } from '../app.js';

export async function invoke(cmd, args = {}) {
  if (window.__TAURI__) return window.__TAURI__.core.invoke(cmd, args);
  console.warn(`[mock] invoke ${cmd}`, args);
  return null;
}
window.invoke = invoke;

export async function listen(event, handler) {
  if (window.__TAURI__) return window.__TAURI__.event.listen(event, handler);
  console.warn(`[mock] listen ${event}`);
}
window.listen = listen;

export async function loadInterfaces() {
  try {
    const ifaces = await invoke('list_interfaces');
    if (ifaces && ifaces.length) {
      const allOpt = `<option value="__all__">${esc(I18N.t('iface.all'))}</option>`;
      const badge = (k) => (k && k !== 'ethernet' && k !== 'loopback') ? `[${k.toUpperCase()}] ` : '';
      els.interfaceSelect.innerHTML = allOpt + ifaces
        .map((d) => `<option value="${d.name}">${esc(badge(d.kind))}${d.description || d.name}</option>`)
        .join('');
      const best = ifaces.findIndex((d) => /wi-?fi|ethernet|wireless|realtek|intel/i.test(d.description || ''));
      els.interfaceSelect.selectedIndex = best >= 0 ? best + 1 : 1;
      showNpcapWarning(false);
    } else {
      els.interfaceSelect.innerHTML = `<option>${esc(I18N.t('iface.none'))}</option>`;
      showNpcapWarning(true);
    }
  } catch (e) {
    els.interfaceSelect.innerHTML = `<option>${esc(I18N.t('iface.error'))}</option>`;
    showNpcapWarning(true, String(e && e.message ? e.message : e));
  }
}
window.loadInterfaces = loadInterfaces;

export async function startCapture() {
  const sel = els.interfaceSelect.value;
  const interfaces = sel === '__all__'
    ? [...els.interfaceSelect.options].map((o) => o.value).filter((v) => v && v !== '__all__')
    : [sel];
  const filter = els.filterInput.value || null;
  try {
    resetSession();
    await invoke('start_capture', {
      interfaces, filter,
      monitor: !!state.settings.monitor,
      options: buildCaptureOptions(),
    });
    markCapturing();
  } catch (e) {
    alert(`Could not start capture:\n${e}`);
  }
}
window.startCapture = startCapture;

export async function stopCapture() {
  try { await invoke('stop_capture'); } catch (e) { console.error(e); }
  setStatus(STATES.IDLE);
  els.startBtn.disabled = false;
  els.stopBtn.disabled = true;
}
window.stopCapture = stopCapture;

export function onCaptureStopped() {
  if (state.status !== STATES.CAPTURING) return;
  setStatus(STATES.IDLE);
  els.startBtn.disabled = false;
  els.stopBtn.disabled = true;
}
window.onCaptureStopped = onCaptureStopped;

export function openCaptureOptions() {
  const o = state.captureOpts;
  const field = (id, label, value, ph) => `
    <label class="capopt-row"><span>${esc(label)}</span>
      <input type="text" id="${id}" value="${esc(String(value || ''))}" placeholder="${esc(ph || '')}" spellcheck="false">
    </label>`;
  const body = `
    <p class="popover-hint">${esc(I18N.t('capopts.hint'))}</p>
    <fieldset class="capopt-group"><legend>${esc(I18N.t('capopts.autostop'))}</legend>
      ${field('co-stop-dur', I18N.t('capopts.stop.duration'), o.stopDurationSecs, '60')}
      ${field('co-stop-pkts', I18N.t('capopts.stop.packets'), o.stopPackets, '10000')}
      ${field('co-stop-size', I18N.t('capopts.stop.filesize'), o.stopFilesizeKb, '10240')}
    </fieldset>
    <fieldset class="capopt-group"><legend>${esc(I18N.t('capopts.file'))}</legend>
      ${field('co-out', I18N.t('capopts.output'), o.outputPath, 'C:\\captures\\session.pcap')}
      ${field('co-ring-size', I18N.t('capopts.ring.filesize'), o.ringFilesizeKb, '2048')}
      ${field('co-ring-dur', I18N.t('capopts.ring.duration'), o.ringDurationSecs, '300')}
      ${field('co-ring-files', I18N.t('capopts.ring.files'), o.ringFiles, '10')}
      <div class="popover-hint">${esc(I18N.t('capopts.ring.hint'))}</div>
    </fieldset>
    <div class="modal-actions">
      <button id="co-clear" class="btn btn-small">${esc(I18N.t('capopts.clear'))}</button>
      <button id="co-apply" class="btn btn-primary">${esc(I18N.t('capopts.apply'))}</button>
    </div>`;
  openToolModal(I18N.t('capopts.title'), body);
  $('#co-apply').addEventListener('click', () => {
    state.captureOpts = {
      stopDurationSecs: $('#co-stop-dur').value.trim(),
      stopPackets: $('#co-stop-pkts').value.trim(),
      stopFilesizeKb: $('#co-stop-size').value.trim(),
      outputPath: $('#co-out').value.trim(),
      ringFilesizeKb: $('#co-ring-size').value.trim(),
      ringDurationSecs: $('#co-ring-dur').value.trim(),
      ringFiles: $('#co-ring-files').value.trim(),
    };
    saveJSON('netscope.captureopts', state.captureOpts);
    closeToolModal();
  });
  $('#co-clear').addEventListener('click', () => {
    state.captureOpts = { stopDurationSecs: '', stopPackets: '', stopFilesizeKb: '', outputPath: '', ringFilesizeKb: '', ringDurationSecs: '', ringFiles: '' };
    saveJSON('netscope.captureopts', state.captureOpts);
    closeToolModal();
  });
}
window.openCaptureOptions = openCaptureOptions;

export function openRemoteCapture() {
  const r = state.remote;
  const field = (id, label, value, ph) => `
    <label class="capopt-row"><span>${esc(label)}</span>
      <input type="text" id="${id}" value="${esc(String(value || ''))}" placeholder="${esc(ph || '')}" spellcheck="false">
    </label>`;
  const body = `
    <p class="popover-hint">${esc(I18N.t('remote.hint'))}</p>
    ${field('rc-host', I18N.t('remote.host'), r.host, '192.168.1.1')}
    ${field('rc-user', I18N.t('remote.user'), r.user, 'root')}
    ${field('rc-port', I18N.t('remote.port'), r.port, '22')}
    ${field('rc-identity', I18N.t('remote.identity'), r.identity, '~/.ssh/id_ed25519')}
    ${field('rc-iface', I18N.t('remote.iface'), r.iface, 'any')}
    ${field('rc-filter', I18N.t('remote.filter'), r.filter, 'not tcp port 22')}
    ${field('rc-command', I18N.t('remote.command'), r.command, I18N.t('remote.command.ph'))}
    <label class="capopt-row capopt-check"><input type="checkbox" id="rc-sudo" ${r.sudo ? 'checked' : ''}> <span>${esc(I18N.t('remote.sudo'))}</span></label>
    <div class="popover-hint">${esc(I18N.t('remote.auth.hint'))}</div>
    <div class="modal-actions">
      <button id="rc-start" class="btn btn-primary">${esc(I18N.t('remote.start'))}</button>
    </div>`;
  openToolModal(I18N.t('remote.title'), body);
  $('#rc-start').addEventListener('click', startRemoteCapture);
}
window.openRemoteCapture = openRemoteCapture;

export async function startRemoteCapture() {
  const r = {
    host: $('#rc-host').value.trim(),
    user: $('#rc-user').value.trim(),
    port: $('#rc-port').value.trim(),
    identity: $('#rc-identity').value.trim(),
    iface: $('#rc-iface').value.trim(),
    filter: $('#rc-filter').value.trim(),
    command: $('#rc-command').value.trim(),
    sudo: $('#rc-sudo').checked,
  };
  if (!r.host) { alert(I18N.t('remote.needhost')); return; }
  state.remote = r;
  saveJSON('netscope.remote', r);
  const startBtn = $('#rc-start');
  startBtn.disabled = true;
  startBtn.textContent = I18N.t('remote.connecting');
  try {
    resetSession();
    const label = await invoke('start_remote_capture', {
      host: r.host,
      user: r.user || null,
      port: r.port ? parseInt(r.port, 10) : null,
      identityFile: r.identity || null,
      remoteInterface: r.iface || null,
      filter: r.filter || null,
      remoteCommand: r.command || null,
      useSudo: !!r.sudo,
      options: buildCaptureOptions(),
    });
    closeToolModal();
    markCapturing();
    els.statusText.textContent = `${I18N.t('status.capturing')} — ${label}`;
  } catch (e) {
    alert(`${I18N.t('remote.failed')}\n${e}`);
    startBtn.disabled = false;
    startBtn.textContent = I18N.t('remote.start');
  }
}
window.startRemoteCapture = startRemoteCapture;

export async function doBlock(ip) {
  try {
    await invoke('block_ip', { ip });
    state.blocked.add(ip);
    renderConnections();
    renderStats();
  } catch (e) {
    alert(`Could not block ${ip}:\n${e}`);
  }
}
window.doBlock = doBlock;

export async function doUnblock(ip) {
  try {
    await invoke('unblock_ip', { ip });
    state.blocked.delete(ip);
    renderConnections();
    renderStats();
  } catch (e) {
    alert(`Could not unblock ${ip}:\n${e}`);
  }
}
window.doUnblock = doUnblock;
