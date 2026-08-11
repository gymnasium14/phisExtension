/**
 * popup.js — логика всплывающего окна PhishShield.
 */

const api = browser ?? chrome;
const VERDICTS = {
    0: 'Находится в белом списке пользователя',
    1: 'Находится в белом списке',
    2:'Домен подозрительно похож на известный сайт',
    3: 'Домен зарегистрирован совсем недавно',
    4: 'В URL страницы найдены фишинговые ключевые слова',
    5: 'Модель машинного обучения оценивает URL как подозрительный'
};
/** id активной вкладки и её состояние проверки */
let tabId = null;
let tabState = null;
let settings = null;
let nonePage = null;

const $ = (sel) => document.querySelector(sel);

/* ------------------------------------------------------------------ */
/* Навигация между экранами                                            */
/* ------------------------------------------------------------------ */

function showView(name) {
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
  $(`#view-${name}`).classList.add('active');
  if (name === 'settings') renderSettingsView();
  if (name === 'journal') renderJournal();
}

document.querySelectorAll('[data-nav]').forEach((btn) =>
  btn.addEventListener('click', () => showView(btn.dataset.nav)));

/* ------------------------------------------------------------------ */
/* Главный экран: вердикт                                              */
/* ------------------------------------------------------------------ */

const VERDICT_UI = {
  scanning: {
    pillClass: 'warn', pill: 'ИДЁТ АНАЛИЗ', verdictClass: 'neutral',
    verdict: 'ПРОВЕРКА…', state: 'state-neutral state-scanning', shield: 'shieldWarn',
    reason: 'Сайт проверяется…'
  },
  safe: {
    pillClass: 'safe', pill: 'ЗАЩИТА АКТИВНА', verdictClass: 'safe',
    verdict: 'БЕЗОПАСНО', state: 'state-safe', shield: 'shieldSafe',
    reason: 'Сайт проверен. Угрозы не обнаружены.'
  },
  suspicious: {
    pillClass: 'warn', pill: 'ВОЗМОЖНА УГРОЗА', verdictClass: 'warn',
    verdict: 'ПОДОЗРИТЕЛЬНО', state: 'state-warn', shield: 'shieldWarn',
    reason: 'Сайт может быть не безопасен. Рекомендуем закрыть страницу.'
  },
  dangerous: {
    pillClass: 'danger', pill: 'УГРОЗА · ВЫ НА ФИШИНГОВОМ САЙТЕ', verdictClass: 'danger',
    verdict: 'ОПАСНО', state: 'state-danger', shield: 'shieldDanger',
    reason: 'Распознан фишинг. Не вводите данные на этом сайте.'
  },
  off: {
    pillClass: 'neutral', pill: 'ЗАЩИТА ОТКЛЮЧЕНА', verdictClass: 'neutral',
    verdict: 'НЕ ПРОВЕРЯЕТСЯ', state: 'state-neutral', shield: 'shieldWarn',
    reason: 'Включите защиту, чтобы проверять сайты.'
  },
  nonpage: {
    pillClass: 'neutral', pill: 'НЕ НА САЙТЕ', verdictClass: 'neutral',
    verdict: 'НЕ ПРОВЕРЯЕТСЯ', state: 'state-neutral', shield: 'shieldWarn',
    reason: 'Проверка начнётся как только вы передёте на сайт.'
  }
};

const RISK_COLORS = { safe: 'var(--safe)', suspicious: 'var(--warn)', dangerous: 'var(--danger)' };

async function renderMain() {
  let verdict = "scanning";
  
  if (settings && settings.protectionEnabled === false) {
    verdict = "off";
  } else if (tabState && tabState.risk !== undefined) {
    if (tabState.risk <= 25) {
      verdict = "safe";
    } else if (tabState.risk > 25 && tabState.risk < 75) {
      verdict = "suspicious";
    } else {
      verdict = "dangerous";
    }
  }
  if (nonePage)
    verdict = "nonpage";

  const ui = VERDICT_UI[verdict];
  $('#statusPill').className = `status-pill ${ui.pillClass}`;
  $('#statusPill').textContent = ui.pill;

  $('#view-main').className = `view active ${ui.state}`;console.log('verdict:', verdict);
  ['shieldSafe', 'shieldWarn', 'shieldDanger'].forEach((id) => {
    document.getElementById(id).style.visibility = id !== ui.shield ? 'hidden' : 'visible';
  });

  $('#verdictPill').className = `verdict-pill ${ui.verdictClass}`;
  $('#verdictPill').textContent = ui.verdict;

  const risk = tabState.risk ?? 0;
  $('#riskRow').style.visibility = (verdict === 'off' || verdict == "nonpage") ? 'hidden' : 'visible';
  $('#riskFill').style.width = `${risk}%`;
  $('#riskFill').style.background = RISK_COLORS[verdict] ?? 'var(--text-3)';
  $('#riskPct').textContent = `${risk}%`;

  if (tabState.text)
    $('#reason').innerHTML = ui.reason+"<br><br>"+VERDICTS[tabState.text];
  else
    $('#reason').innerHTML = ui.reason;
  $('#siteUrl').textContent = tabState.url ? await shortUrl(tabState.url) : '—';
}

async function shortUrl(url) {
  let u;
  try {
    u = new URL(url);
    const httpProtocol = (await api.runtime.sendMessage({type: "GET_HTTP", hostname: u.hostname})).result;
    return `${(httpProtocol ? "" : u.protocol) || httpProtocol}//${u.hostname}`;
  } catch {
    const httpProtocol = (await api.runtime.sendMessage({type: "GET_HTTP", hostname: url})).result;
    return `${httpProtocol}//${url}`;
  }
}

/* Копирование адреса */
$('#btnCopyUrl').addEventListener('click', async () => {
  if (tabState?.url) {
    await navigator.clipboard.writeText(tabState.url).catch(() => {});
    $('#btnCopyUrl').style.color = 'var(--safe-strong)';
    setTimeout(() => ($('#btnCopyUrl').style.color = ''), 900);
  }
});

/* ------------------------------------------------------------------ */
/* Настройки                                                           */
/* ------------------------------------------------------------------ */

async function renderSettingsView() {
  const res = await send({ type: 'GET_SETTINGS' });
  settings = res.settings;
  $('#setDontWait').checked = settings.dontWait;
  applyThemeSeg(settings.theme);
  await renderWhitelist();
}

$('#setDontWait').addEventListener('change', async (e) => {
  const res = await send({ type: 'SET_SETTINGS', patch: { dontWait: e.target.checked } });
  settings = res.settings;
});

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
}

function applyThemeSeg(theme) {
  document.querySelectorAll('#themeSeg button').forEach((b) =>
    b.classList.toggle('active', b.dataset.theme === theme));
}

document.querySelectorAll('#themeSeg button').forEach((b) =>
  b.addEventListener('click', async () => {
    applyTheme(b.dataset.theme);
    applyThemeSeg(b.dataset.theme);
    const res = await send({ type: 'SET_SETTINGS', patch: { theme: b.dataset.theme } });
    settings = res.settings;
  }));

$('#protectionToggle').addEventListener('change', async (e) => {
  const res = await send({ type: 'SET_SETTINGS', patch: { protectionEnabled: e.target.checked } });
  settings = res.settings;
  renderMain();
});

$('#btnSettings').addEventListener('click', () => showView('settings'));
$('#btnJournal').addEventListener('click', () => showView('journal'));


async function renderJournal() {
  const journal = await send({ type: 'GET_HISTORY' });
  const ul = $('#journalList');
  ul.innerHTML = '';
  $('#journalEmpty').hidden = Object.keys(journal).length > 0;
  let count = 0;
 Object.keys(journal).forEach(i => {
    if (count > 20)
      return;
    const e = journal[i];
    const li = document.createElement('li');
    const host = document.createElement('div');
    host.className = 'j-host';
    host.textContent = i;
    const risk = document.createElement('span');
    risk.className = 'j-risk';
    risk.textContent = `${e.chance}%`;
    li.append(host, risk);
    ul.appendChild(li);
    count += 1;
  });
}

/* ------------------------------------------------------------------ */
/* Белый список                                                        */
/* ------------------------------------------------------------------ */

const AVATAR_COLORS = ['#16a34a', '#5346e4', '#dc2626', '#0891b2', '#d97706', '#9333ea'];

async function renderWhitelist(domains) {
  if (!domains) {
    const res = await send({ type: 'GET_WHITELIST' });
    domains = res.domains;
  }
  const ul = $('#wlList');
  ul.innerHTML = '';
  $('#wlEmpty').hidden = domains.length > 0;

  domains.forEach((domain, i) => {
    console.log(domain);
    const li = document.createElement('li');
    const av = document.createElement('span');
    const name = document.createElement('span');
    const rm = document.createElement('button');
    
    name.className = 'wl-domain';
    name.textContent = domain;
    
    const host = domain.replace(/^.*?\/\//, '')

    av.className = 'wl-avatar';
    av.style.background = AVATAR_COLORS[i % AVATAR_COLORS.length];
    av.textContent = host[0] ? host[0].toUpperCase() : '?';

    rm.className = 'wl-remove';
    rm.textContent = '✕';
    rm.title = 'Удалить из белого списка';
    rm.addEventListener('click', async () => {
      const res = await send({ type: 'REMOVE_WHITELIST', domain });
      renderWhitelist(res.domains);
    });
    
    li.append(av, name, rm);
    ul.appendChild(li);
  });
}

$('#wlAddBtn').addEventListener('click', addWhitelistDomain);
$('#wlInput').addEventListener('keydown', (e) => e.key === 'Enter' && addWhitelistDomain());

async function addWhitelistDomain() {
  const input = $('#wlInput');
  const val = input.value.trim();
  console.log(await shortUrl(val));
  if (!val) return;
  const res = await send({ type: 'ADD_WHITELIST', domain: await shortUrl(val) });
  const bad = !res.ok;
  $('#wlInputWrap')?.classList.toggle('error', bad);
  const errBlock = $('#wlError');
  if (errBlock) errBlock.hidden = !bad;
  
  if (res.ok) {
    input.value = '';
    renderWhitelist(res.domains);
  }
}

/* ------------------------------------------------------------------ */
/* Формы обратной связи                                                */
/* ------------------------------------------------------------------ */

$('#btnReportSite')?.addEventListener('click', async () => {
  $('#reportSiteUrl').textContent = tabState?.url ? await shortUrl(tabState.url) : '—';
  showView('report-site');
});

$('#btnSendSiteReport')?.addEventListener('click', async () => {
  await send({
    type: 'REPORT',
    payload: {
      url: tabState?.url ?? '',
      kind: $('#reportCategory').value,
      comment: $('#reportSiteComment').value.trim()
    }
  });
  $('#reportSiteComment').value = '';
  $('#thanksText').textContent = 'Мы изучим сайт и обновим базу, если он опасен.';
  showView('thanks');
});

/* ------------------------------------------------------------------ */
/* Обмен с background и инициализация                                  */
/* ------------------------------------------------------------------ */

async function send(arg) {
  return await api.runtime.sendMessage(arg);
}

async function refreshState() {
  try {
    const res = await api.runtime.sendMessage({ type: 'GET_STATE', tabId: tabId });
    if (res && res.state) {
      tabState = res.state;
    } else {
      tabState = null;
    }
  } catch (err) {
    console.error('Ошибка получения состояния:', err);
    tabState = null;
  }
  console.log("Получили state", tabState)
  if (tabState.url.startsWith('chrome://') || tabState.url.startsWith('about:') || tabState.url.startsWith('edge://'))
    nonePage = true;
  if (!nonePage && !("risk" in tabState))
  {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    await api.tabs.sendMessage(tab.id, { type: 'ANALYZE_REQUEST' });
  }
  renderMain();
}

api.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'STATE_UPDATED' && msg.tabId === tabId) {
    refreshState();
  }
});

(async function init() {
  try {
    const settingsRes = await send({ type: 'GET_SETTINGS' });
    settings = settingsRes.settings;
    $('#protectionToggle').checked = settings.protectionEnabled;
    applyTheme(settings?.theme ?? 'auto');
    
    const versionLabel = $('#versionLabel');
    if (versionLabel) {
      versionLabel.textContent = 'v' + api.runtime.getManifest().version;
    }
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    tabId = tab?.id ?? null;
    refreshState();
  } catch (e) {
    console.error('Ошибка инициализации popup:', e);
  }
})();