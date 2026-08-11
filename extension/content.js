import { shorteningServices, brands, MLP_MINIMUM_CHANCE, MINIMUM_SITE_AGE, FEATURE_NAMES, PHISH_HINTS } from './constants.js';
import whiteList from './whitelist.json';
import * as ort from 'onnxruntime-web';
const api = globalThis.browser ?? globalThis.chrome;
const MODEL_PATH = api.runtime.getURL('mlp_model.onnx');
let session = null;
ort.env.wasm.simd = false;
ort.env.wasm.wasmPaths = api.runtime.getURL('/');
ort.env.wasm.numThreads = 1;
ort.env.wasm.proxy = false;

const PHISHSHIELD_HOST_ID = 'phishshield-warning-host';

async function showPhishingWarning()
{
  // Не показываем второе окно поверх первого.
  const existing = document.getElementById(PHISHSHIELD_HOST_ID);
  if (existing) return () => existing.remove();

  // Подгружаем разметку + стили из отдельного html-файла.
  const templateUrl = api.runtime.getURL('warning-banner.html');
  const html = await fetch(templateUrl).then((r) => r.text());
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const styleText = doc.querySelector('style')?.textContent ?? '';
  const card = doc.getElementById('phishshield-warning');
  if (!card) throw new Error('warning-banner.html: не найден #phishshield-warning');

  // Изолируем окно от стилей самой страницы через Shadow DOM.
  const host = document.createElement('div');
  host.id = PHISHSHIELD_HOST_ID;
  const shadow = host.attachShadow({ mode: 'open' });

  const styleEl = document.createElement('style');
  styleEl.textContent = styleText;
  shadow.append(styleEl, card);
  document.documentElement.appendChild(host);

  // Заполняем данными.
  const host_ = getHostname();

  const hide = () => host.remove();

  shadow.getElementById('ps-btn-close')?.addEventListener('click', () => {
    api.runtime.sendMessage({ type: 'CLOSE_TAB' }).catch(() => {});
  });
  shadow.getElementById('ps-btn-proceed')?.addEventListener('click', () => {
    api.runtime.sendMessage({ type: 'PROCEED_ANYWAY', host: host_ }).catch(() => {});
    hide();
  });

  return hide;
}
async function loadModel() {
  if (!session) {
    session = await ort.InferenceSession.create(MODEL_PATH, {
    executionProviders: ['cpu']       // Принудительно используем CPU
    });
  }
  return session;
}

// Загрузка JSON-файла с параметрами скейлера
async function loadScalerParams() {
    const response = await fetch(api.runtime.getURL('scaler_params.json'));
    return await response.json();
}

function extractFeatureVector(featuresDict) {
    const vector = [];
    for (const name of FEATURE_NAMES) {
        const value = featuresDict[name];
        if (value === undefined) {
            throw new Error(`Отсутствует признак: ${name}`);
        }
        if (typeof value !== 'number' || isNaN(value)) {
            throw new Error(`Признак ${name} не является числом: ${value}`);
        }
        vector.push(value);
    }
    return vector;
}

function scaleFeatures(featuresArray, params) {
    // featuresArray - массив чисел (признаки)
    if (params.type === 'standard') {
        return featuresArray.map((val, idx) => 
            (val - params.mean[idx]) / params.scale[idx]
        );
    } else if (params.type === 'minmax') {
        return featuresArray.map((val, idx) => 
            (val - params.min[idx]) / (params.max[idx])   // max - это data_range
        );
    } else {
        throw new Error('Неизвестный тип скейлера');
    }
}

/**
 * Вычисляет расстояние Левенштейна между двумя строками.
 * @param {string} a - первая строка
 * @param {string} b - вторая строка
 * @returns {number} минимальное количество операций (вставка, удаление, замена)
 */
function levenshteinDistance(a, b) {
    const m = a.length;
    const n = b.length;

    // Создаём матрицу размером (m+1) x (n+1)
    const dp = Array(m + 1);
    for (let i = 0; i <= m; i++) {
        dp[i] = Array(n + 1);
        dp[i][0] = i; // удаление всех символов из a
    }
    for (let j = 0; j <= n; j++) {
        dp[0][j] = j; // вставка всех символов в a
    }

    // Заполняем матрицу
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            if (a[i - 1] === b[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = Math.min(
                    dp[i - 1][j] + 1,     // удаление
                    dp[i][j - 1] + 1,     // вставка
                    dp[i - 1][j - 1] + 1  // замена
                );
            }
        }
    }

    return dp[m][n];
}
// Функция для извлечения признаков из текущей страницы
let featuresCache
function extractFeatures(url) {
    if (featuresCache)
        return featuresCache;
    url = url || window.location.href;

    const features = {};
    try {
        const urlObj = new URL(url);

        features.url = url;
        features.length_url = url.length;
        features.length_hostname = urlObj.hostname.length;
        features.ip = /^[0-9.]+$/.test(urlObj.hostname) ? 1 : 0;
        features.nb_dots = (url.match(/\./g) || []).length;
        features.nb_hyphens = (url.match(/-/g) || []).length;
        features.nb_at = (url.match(/@/g) || []).length;
        features.nb_qm = (url.match(/\?/g) || []).length;
        features.nb_and = (url.match(/&/g) || []).length;
        features.nb_or = (url.match(/or/g) || []).length;
        features.nb_eq = (url.match(/=/g) || []).length;
        features.nb_underscore = (url.match(/_/g) || []).length;
        features.nb_tilde = (url.match(/~/g) || []).length;
        features.nb_percent = (url.match(/%/g) || []).length;
        features.nb_slash = (url.match(/\//g) || []).length;
        features.nb_star = (url.match(/\*/g) || []).length;
        features.nb_colon = (url.match(/:/g) || []).length;
        features.nb_comma = (url.match(/,/g) || []).length;
        features.nb_semicolumn = (url.match(/;/g) || []).length;
        features.nb_dollar = (url.match(/\$/g) || []).length;
        features.nb_space = (url.match(/\s/g) || []).length;
        features.nb_www = (url.match(/www/g) || []).length;
        features.nb_com = (url.match(/\.com/g) || []).length;
        features.nb_dslash = (url.match(/\/\//g) || []).length;

        features.http_in_path = urlObj.pathname.includes("http") ? 1 : 0;
        features.https_token = url.includes("https") ? 1 : 0;
        features.ratio_digits_url =
            (url.match(/\d/g) || []).length / url.length || 0;
        features.ratio_digits_host =
            (urlObj.hostname.match(/\d/g) || []).length /
                urlObj.hostname.length || 0;
        features.punycode = url.includes("xn--") ? 1 : 0;
        features.port = urlObj.port ? 1 : 0;
        features.tld_in_path = /\.(com|net|org|info|co|io|biz|xyz|top|club|me|online|site|live|tv|name|us|cc|mobi|store|asia|press|club|pro|click|download|red|party|win|cloud|party|tech|app|work|space|fun|website|org|re|group|sh|in|cn|tv|site|website|ai)/.test(urlObj.pathname) ? 1 : 0;
        features.tld_in_subdomain =
            /\.(com|net|org|info|co|io|biz|xyz|top|club|me|online|site|live|tv|name|us|cc|mobi|store|asia|press|club|pro|click|download|red|party|win|cloud|party|tech|app|work|space|fun|website|org|re|group|sh|in|cn|tv|site|website|ai)/.test(urlObj.hostname.split(".")[0]) ? 1 : 0;

        const subdomains = urlObj.hostname.split(".").slice(0, -2);
        features.abnormal_subdomain = subdomains.length > 2 ? 1 : 0;
        features.nb_subdomains = subdomains.length;
        features.prefix_suffix = urlObj.hostname.includes("-") ? 1 : 0;
        features.shortening_service = shorteningServices.some((service) =>
            url.includes(service)
        )
            ? 1
            : 0;

        features.path_extension =
            /\.(php|html|aspx|jsp|cgi)/.test(urlObj.pathname) ? 1 : 0;

        features.length_words_raw = url.split(/[/.?=&-_]/).join("").length;
        features.char_repeat =
            /([a-zA-Z0-9])\1{2,}/.test(url) ? 1 : 0;

        const words = url.split(/[/.?=&-_]/).filter((word) => word.length > 0);
        features.shortest_words_raw = Math.min(...words.map((w) => w.length)) || 0;
        features.shortest_word_host =
            Math.min(...urlObj.hostname.split(".").map((w) => w.length)) || 0;
        features.shortest_word_path =
            Math.min(...urlObj.pathname.split("/").map((w) => w.length)) || 0;
        features.longest_words_raw = Math.max(...words.map((w) => w.length)) || 0;
        features.longest_word_host =
            Math.max(...urlObj.hostname.split(".").map((w) => w.length)) || 0;
        features.longest_word_path =
            Math.max(...urlObj.pathname.split("/").map((w) => w.length)) || 0;
        features.avg_words_raw =
            words.reduce((sum, w) => sum + w.length, 0) / words.length || 0;
        features.avg_word_host =
            urlObj.hostname.split(".").reduce((sum, w) => sum + w.length, 0) /
                urlObj.hostname.split(".").length || 0;
        features.avg_word_path =
            urlObj.pathname.split("/").reduce((sum, w) => sum + w.length, 0) /
                urlObj.pathname.split("/").length || 0;

        features.phish_hints =
            PHISH_HINTS.test(url) ? 1 : 0;
        features.domain_in_brand = brands.test(
            urlObj.hostname
        )
            ? 1
            : 0;
        features.brand_in_subdomain = brands.test(
            subdomains.join(".")
        )
            ? 1
            : 0;
        features.brand_in_path =
           brands.test(urlObj.pathname) ? 1 : 0;

        features.suspecious_tld =
            /\.(tk|ml|ga|cf|gq|xyz|top|club|work|space|win|date|party|online|site|download|bid|info|name|co|shop|icu|city|cc|pro|press|host|win|mobi|cf|pw|asia|io|link|cloud|tk|live|party|buzz|vip|rocks|church|info|click|website|run|fit|)$/.test(urlObj.hostname) ? 1 : 0;

    } catch (err) {
        console.error("Error extracting features:", err);
    }
    featuresCache = features
    return features;
}

let totalAnswer
function analyzeResult(chance, wannaRedeem, text)
{
    if (totalAnswer[0] > chance)
        text = totalAnswer[2];
    if (wannaRedeem === null)
        wannaRedeem = totalAnswer[1];
    totalAnswer = [Math.max(totalAnswer[0], chance), wannaRedeem, text]
}

function getHostname(url){
    const features = extractFeatures(url);
    const urlObj = new URL(features.url);
    return urlObj.hostname;
}
async function getDomainAgeDays(host) {
  const domain = host.split('.').slice(-2).join('.');
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(`https://rdap.org/domain/${domain}`, { signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`RDAP ${res.status}`);
    const data = await res.json();
    const reg = (data.events || []).find((e) => e.eventAction === 'registration');
    const age = reg ? Math.floor((Date.now() - Date.parse(reg.eventDate)) / 864e5) : null;
    return age;
  } catch (e) {
    console.warn('[PhishShield] WHOIS недоступен для', domain, e.message);
    return null;
  }
}

const analyzeMethods = [
    // History check
    async function (url){
        const hostname = getHostname(url);
        const response = await api.runtime.sendMessage({ type: "GET_URL", url: hostname });
        if (response.result){
            console.log("by history");
            analyzeResult(response.chance, false, response.text);
            return true
        }
    },
    // Whitelist processing
    async function (url){
        const hostname = getHostname(url).replace(/^www\./, '');
        let foundedLevenshtein = false;
        let userWL = (await api.runtime.sendMessage({type: "GET_WHITELIST"}))?.domains;
        if (typeof(userWL) == "object")
        {
            for (const domain of userWL){
                if (domain == hostname){
                    console.log("exact domain " + hostname + " by user WL")
                    analyzeResult(0, true, 0);
                    return true;
                }
            }
        }
        for (const domain of whiteList) {
            if (domain == hostname)
            {
                console.log("exact domain with "+hostname);
                analyzeResult(0, true, 1);
                return true;
            }
            else if (levenshteinDistance(domain,hostname) < 4)
            {
                console.log("levenshtein dist "+hostname+" with "+domain);
                foundedLevenshtein = true
            }
        }
        if (foundedLevenshtein)
            analyzeResult(70, true, 2);
    },
    // WHOIS scheme
    async function(url)
    {
        const hostname = getHostname(url).replace(/^www\./, '');
        const ageDays = getDomainAgeDays(hostname);

        if (ageDays < MINIMUM_SITE_AGE)
        {
            console.log("by WHOIS got "+ageDays+" days")
            analyzeResult(70, true, 3);
        }
    },
    // Trigger words
    async function(url){
        if (PHISH_HINTS.test(url))
            analyzeResult(40, true, 4);
    },
    // MLP processing
    async function(url){
        await loadModel();
        const features = extractFeatures(url);

        // 2. Преобразуем в упорядоченный массив
        const rawVector = extractFeatureVector(features);

        const scalerParams = await loadScalerParams();
        // 3. Масштабируем
        const scaledVector = scaleFeatures(rawVector, scalerParams);
        
        const tensor = new ort.Tensor('float32', new Float32Array(scaledVector), [1, scaledVector.length]);
        const inputName = session.inputNames[0];
        const inputFeed = { [inputName]: tensor };

        const results = await session.run(inputFeed);
        const outputTensor = results[session.outputNames[0]]; 
        const outputData = outputTensor.data[0];

        console.log("mpl chance " + outputData);

        analyzeResult(Math.round(outputData), true, 5);
        if (outputData >= MLP_MINIMUM_CHANCE) {
            console.log("by mlp");
            return true;
        }
    }
]
// Инициализация
async function analyze(url){
    totalAnswer = [0, true, "Всё хорошо"]
    for (let i = 0; i < analyzeMethods.length; i++){
        if (await analyzeMethods[i](url))
            break;
    }
    const hostname = getHostname(url);
    if (totalAnswer[1])
        api.runtime.sendMessage({type: "REDEEM_URL", url: hostname, chance: totalAnswer[0], text: totalAnswer[2]});

    return totalAnswer;
}

async function analyzeHandle(url){
    url = url || window.location.href;
    const result = await analyze(url);
    api.runtime.sendMessage({type: "ANALYZE_RESULT", probability: result[0], text: result[2]});
}

let settings = null;

async function init(){
    ({ settings } = await api.runtime.sendMessage({ type: 'GET_SETTINGS' }));
    if (settings.protectionEnabled == null || settings.protectionEnabled)
        analyzeHandle();
}
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type){
        case ("ANALYZE_REQUEST"):{
            analyzeHandle();
            sendResponse({ok: true});
            break;
        }
        case ("SHOW_WARN"):{
            showPhishingWarning();
            break;
        }
    }
});
init();