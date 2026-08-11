const url = "http://46.36.220.219:5001";
let history = {};
let httpCache = {};
const tabStates = new Map();
const proceededHosts = new Set();

const api = globalThis.browser ?? globalThis.chrome;
const actionApi = api.action ?? api.browserAction;

const DEFAULT_SETTINGS = {
  protectionEnabled: true,  
  skipPopular: true,        
  dontWait: false,          
  highAccuracy: true,       
  theme: 'auto'             
};

const VERDICT_COLORS = {
  safe: '#2ecc71',
  suspicious: '#f1c40f',
  dangerous: '#e74c3c',
  scanning: '#8b93a7',
  off: '#b6bcc9'
};

function drawIcon(color, size) {
  const canvas = new OffscreenCanvas(size, size);
  const ctx = canvas.getContext('2d');
  const s = size / 32;

  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(16 * s, 16 * s, 15 * s, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = '#ffffff';
  ctx.beginPath();
  ctx.moveTo(16 * s, 7 * s);
  ctx.lineTo(24 * s, 10 * s);
  ctx.lineTo(24 * s, 16 * s);
  ctx.bezierCurveTo(24 * s, 21 * s, 20.5 * s, 24.5 * s, 16 * s, 26 * s);
  ctx.bezierCurveTo(11.5 * s, 24.5 * s, 8 * s, 21 * s, 8 * s, 16 * s);
  ctx.lineTo(8 * s, 10 * s);
  ctx.closePath();
  ctx.fill();

  return ctx.getImageData(0, 0, size, size);
}

async function updateIcon(tabId) {
  let verdict = 'scanning';
  const tabState = tabStates.get(tabId);
  if ('risk' in tabState)
  {
    if (tabState.risk <= 25) {
      verdict = "safe";
    } else if (tabState.risk > 25 && tabState.risk < 75) {
      verdict = "suspicious";
    } else {
      verdict = "dangerous";
    }
  }
  const color = VERDICT_COLORS[verdict] ?? VERDICT_COLORS.scanning;
  try {
    const imageData = {};
    for (const size of [16, 32]) imageData[size] = drawIcon(color, size);
    await actionApi.setIcon({ tabId, imageData });
  } catch {
    try {
      await actionApi.setBadgeBackgroundColor({ tabId, color });
      await actionApi.setBadgeText({
        tabId,
        text: verdict === 'dangerous' ? '!' : verdict === 'suspicious' ? '?' : ''
      });
    } catch { /* вкладка закрыта */ }
  }
}

function blankState(tabId, url = '') {
  return {
    tabId,
    url
  };
}

function getOrCreateState(tabId, url) {
  let state = tabStates.get(tabId);
  if (!state) {
    state = blankState(tabId, url);
    state.tabId = tabId;
    tabStates.set(tabId, state);
  }
  return state;
}

async function broadcastState(tabId) {
  let state = null;
  if (typeof(tabId) == 'number')
  {
    state = tabStates.get(tabId);
  }
  else{
    state = tabId;
  }
  if (!state) return;
  if (state.risk >= 75 && !proceededHosts.has(new URL(state.url).hostname)){
    api.tabs.sendMessage(state.tabId, { type: 'SHOW_WARN' }); 
  }
  try { 
    await api.runtime.sendMessage({ type: 'STATE_UPDATED', tabId: state.tabId }); 
  } catch { /* popup закрыт */ }
  await updateIcon(state.tabId);
}

async function storageGet(key, fallback) {
  const obj = await api.storage.sync.get(key); // Используем sync для синхронизации настроек между сессиями
  return obj[key] ?? fallback;
}

async function storageSet(key, value) {
  await api.storage.sync.set({ [key]: value });
}

async function getSettings() {
  const saved = await storageGet('settings', {});
  return { ...DEFAULT_SETTINGS, ...saved };
}

async function sendReport(kind, payload) {
  try {
    await fetch(url+"/report", {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, ...payload })
    });
  } catch (e) {
    console.warn('[PhishShield] Сервер отчётов недоступен:', e.message);
  }
}

async function getTabUrl() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab?.url || '';
}

async function fetchHttp(url) {
    if (httpCache[url])
      return httpCache[url];

    try {
        await fetch(`https://${url}`);
        httpCache[url] = "https:";
        await api.storage.sync.set({ httpCache });
        return "https:";
    } catch {
      try {
          await fetch(`http://${url}`);
          httpCache[url] = "http:";
          await api.storage.sync.set({ httpCache });
          return "http:";
      }
      catch {return null}
    }
}

/* Централизованный диспетчер сообщений с жесткими break для предотвращения проваливания кейсов */
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      switch (message.type) {
        case 'ANALYZE_RESULT': {
          let currentUrl = await getTabUrl();
          const state = getOrCreateState(sender.tab.id, currentUrl);
          state.risk = message.probability;
          state.text = message.text;
          broadcastState(state);
          break;
        }
        case "GET_HTTP": {
          sendResponse({result: (await fetchHttp(message.hostname)) || ""});
          break;
        }
        case "captureAndOCR": {
          try {
            const text = await runOCR(sender.tab.windowId);
            sendResponse({ success: true, text: text });
          } catch (err) {
            sendResponse({ success: false, error: err.message });
          }
          break;
        }
        case "REDEEM_URL": {
          const tomorrow = new Date();
          tomorrow.setDate(tomorrow.getDate() + 1);
          history[message.url] = { chance: message.chance, expires: tomorrow, text: message.text };
          await api.storage.sync.set({ history });
          sendResponse({ ok: true });
          break;
        }
        case "GET_URL": {
          const tabState = history[message.url];
          if (tabState) {
            sendResponse({ result: true, chance: tabState.chance, text: tabState.text});
          } else {
            sendResponse({ result: false });
          }
          break;
        }
        case 'GET_STATE': {
          let currentUrl = await getTabUrl();
          const state = getOrCreateState(message.tabId, currentUrl);
          sendResponse({ state });
          break;
        }
        case 'GET_WHITELIST': {
          const domains = await storageGet('userWhitelist', []);
          sendResponse({ domains });
          break;
        }
        case 'ADD_WHITELIST': {
          const domain = message.domain;
          if (!/^[a-zа-яё0-9-]+(\.[a-zа-яё0-9-]+)+$/i.test(domain.replace(/^.*?\/\//, ''))) {
            sendResponse({ ok: false, error: 'Введите корректный домен' });
            break;
          }
          const list = await storageGet('userWhitelist', []);
          if (!list.includes(domain)) {
            list.unshift(domain);
            await storageSet('userWhitelist', list);
          }
          sendResponse({ ok: true, domains: list });
          break;
        }
        case 'REMOVE_WHITELIST': {
          const currentList = await storageGet('userWhitelist', []);
          const list = currentList.filter((d) => d !== message.domain);
          await storageSet('userWhitelist', list);
          sendResponse({ ok: true, domains: list });
          break;
        }
        case 'GET_SETTINGS': {
          const settings = await getSettings();
          sendResponse({ settings });
          break;
        }
        case 'SET_SETTINGS': {
          const currentSettings = await getSettings();
          const settings = { ...currentSettings, ...message.patch };
          await storageSet('settings', settings);
          sendResponse({ ok: true, settings });
          break;
        }
        case 'REPORT': {
          await sendReport(message.payload.kind, message.payload);
          sendResponse({ ok: true });
          break;
        }
        case 'GET_HISTORY': {
          sendResponse(history);
          break;
        }
        case 'CLOSE_TAB': {
          try { await api.tabs.remove(sender.tab.id); } catch { /* уже закрыта */ }
          sendResponse({ ok: true });
          break;
        }
        case 'PROCEED_ANYWAY': {
          if (message.host) proceededHosts.add(message.host);
          const state = tabStates.get(sender.tab.id);
          if (state) {
            state.text = "Вы решили продолжить самостоятельно."
            await broadcastState(sender.tab.id);
          }
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: 'Unknown message type' });
      }
    } catch (err) {
      console.error('Ошибка в onMessage listener:', err);
      sendResponse({ ok: false, error: err.message });
    }
  })();
  return true; // Держит канал связи открытым для асинхронного ответа
});

function checkExpires() {
  const today = new Date();
  Object.keys(history).forEach(key => {
    if (history[key].expires <= today) delete history[key];
  });
}

api.storage.sync.get(['history'], (result) => {
  if (result && result.history) {
    history = result.history;
    checkExpires();
  }
});

api.storage.sync.get(['httpCache'], (result) => {
  if (result && result.httpCache) {
    httpCache = result.httpCache;
  }
});

async function runOCR(windowId) {
  const screenshotUrl = await api.tabs.captureVisibleTab(windowId, { format: 'png' });
  const formData = new FormData();
  formData.append('base64Image', screenshotUrl);
  formData.append('language', 'rus');
  formData.append('apikey', 'helloworld');

  const response = await fetch('https://api.ocr.space/parse/image', {
    method: 'POST',
    body: formData
  });

  const result = await response.json();
  if (result.OCRExitCode === 1 && result.ParsedResults) {
    return result.ParsedResults.map(item => item.ParsedText).join('\n');
  } else {
    throw new Error(result.ErrorMessage || "Ошибка OCR API");
  }
}

api.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const targetUrl = details.url;
  const tabId = details.tabId;
  
  if (targetUrl.startsWith('chrome://') || targetUrl.startsWith('about:') || targetUrl.startsWith('edge://')) return;

  let host = '';
  try {
    host = new URL(targetUrl).hostname;
  } catch { return; }

  const settings = await getSettings();
  if (!settings.protectionEnabled) return;

  const state = blankState(tabId, targetUrl, host);
  tabStates.set(tabId, state);
  await broadcastState(tabId);
});

api.tabs.onRemoved.addListener((tabId) => tabStates.delete(tabId));

setInterval(() => {
  checkExpires();
}, 60 * 10 * 1000);