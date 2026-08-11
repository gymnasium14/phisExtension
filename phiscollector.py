from urllib.parse import urlparse
import requests
import pandas as pd
import os
import ipaddress
import re
from tranco import Tranco
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings()

fast_session = requests.Session()
retry = Retry(total=0, connect=0, read=0, redirect=0, other=0)
adapter = HTTPAdapter(max_retries=retry)
fast_session.mount("https://", adapter)
fast_session.mount("http://", adapter)

def levenshtein(s1, s2):
    return SequenceMatcher(None, s1, s2).ratio()

PHISH_HINTS = {
    "login", "signin", "verify", "account",
    "secure", "update", "banking", "confirm",
    "password", "paypal", "wallet"
}

BRANDS = {
    "paypal", "google", "apple",
    "amazon", "microsoft", "facebook"
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq"
}

SHORTENERS = [
    "bit.ly", "goo.gl", "tinyurl", "ow.ly", "is.gd", "t.co", "adf.ly",
    "buff.ly", "lnkd.in", "v.gd", "shorte.st", "short.ly", "chng.it",
    "zmurl.com", "cli.re", "u.to", "srnk.net", "qr.net", "linktr.ee",
    "rebrand.ly", "cut.ly", "lil.ly", "link.tl", "fastly.me", "qrurl.com",
    "shortlink.co", "short.io", "bc.vc", "go2l.ink", "linkzip.net",
    "fave.co", "plink.in", "clicky.me", "linkbuck.com", "shrtfly.com",
    "2t.do", "qrphi.com", "tiny.cc", "x.co", "lnk.to", "s.id", "lnk.run",
    "cutt.ly", "ltt.ly", "shot.ly", "j.mp", "bit.do", "cuturl.in",
    "link.sh", "qrcu.be", "b1z.co"
]

def clean_text(text: str):
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'[^А-яёA-z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def split_words(text):
    return [w for w in re.split(r'[^a-zA-Z0-9]+', text) if w]

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return 1
    except:
        return 0

def has_repeated_chars(url):
    return int(bool(re.search(r'(.)\1{2,}', url)))

def shortest(words):
    return min(map(len, words)) if words else 0
def longest(words):
    return max(map(len, words)) if words else 0
def avg(words):
    return sum(map(len, words)) / len(words) if words else 0

def getURLFeatures(url: str, isFish: int):
    features = {}
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    words_raw = split_words(url)
    words_host = split_words(hostname)
    words_path = split_words(path)

    features['is_fraud'] = isFish
    features["url"] = url
    features["length_url"] = len(url)
    features["length_hostname"] = len(hostname)
    features["ip"] = is_ip(hostname)
    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_or"] = url.lower().count("or")
    features["nb_eq"] = url.count("=")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_percent"] = url.count("%")
    features["nb_slash"] = url.count("/")
    features["nb_star"] = url.count("*")
    features["nb_colon"] = url.count(":")
    features["nb_comma"] = url.count(",")
    features["nb_semicolumn"] = url.count(";")
    features["nb_dollar"] = url.count("$")
    features["nb_space"] = url.count(" ")
    features["nb_dslash"] = url.count("//")
    features["https_token"] = int("https" in url.lower())

    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)
    features["ratio_digits_url"] = digits_url / len(url) if len(url) else 0
    features["ratio_digits_host"] = digits_host / len(hostname) if len(hostname) else 0
    features["punycode"] = int("xn--" in hostname.lower())
    features["port"] = int(parsed.port is not None)
    features["nb_subdomains"] = max(len(hostname.split(".")) - 2, 0)
    features["prefix_suffix"] = int("-" in hostname)
    features["path_extension"] = int(bool(re.search(r'\.(php|html|htm|asp|aspx|jsp)$', path.lower())))
    features["length_words_raw"] = sum(len(w) for w in words_raw)
    features["char_repeat"] = has_repeated_chars(url)

    features["shortest_words_raw"] = shortest(words_raw)
    features["shortest_word_host"] = shortest(words_host)
    features["shortest_word_path"] = shortest(words_path)
    features["longest_words_raw"] = longest(words_raw)
    features["longest_word_host"] = longest(words_host)
    features["longest_word_path"] = longest(words_path)
    features["avg_words_raw"] = avg(words_raw)
    features["avg_word_host"] = avg(words_host)
    features["avg_word_path"] = avg(words_path)
    features["phish_hints"] = int(any(kw in url.lower() for kw in PHISH_HINTS))

    tld = hostname.split(".")[-1] if "." in hostname else ""
    features["suspicious_tld"] = int(tld in SUSPICIOUS_TLDS)

    return features
# ------------------ Многопоточная обработка ------------------
def process_single_url(url, is_fishing, timeout=5):
    full_url = url if url.startswith('https') or url.startswith('http') else f'https://{url}'
    # 1. Признаки URL (всегда)
    df_features = getURLFeatures(full_url, 1 if is_fishing else 0)
    return df_features

def scrape_content_parallel(url_list, is_fishing=False, max_workers=50):
    features_list = []
    total = len(url_list)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(process_single_url, url, is_fishing): url for url in url_list}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            completed += 1
            try:
                df_feat = future.result()
                features_list.append(df_feat)
                print(f"Обработан {completed}/{total}: {url}")
            except Exception as e:
                print(f"Ошибка при обработке {url}: {e}")

    df = pd.DataFrame(features_list)
    if not df.empty:
        df = df.set_index("url")
    return df

# ------------------ Загрузка данных ------------------
def loadCSV(filename: str):
    if os.path.exists(filename):
        return pd.DataFrame(pd.read_csv(filename,index_col="url"))
    else:
        return pd.DataFrame()

phishing_url_source = "https://openphish.com/feed.txt"

def fetch_openphish_data_parallel(max_workers=50):
    try:
        response = requests.get(phishing_url_source, timeout=10)
        if response.status_code == 200:
            urls = response.text.splitlines()
            print(f"Получено {len(urls)} фишинговых ссылок")

            df_feat = scrape_content_parallel(urls, is_fishing=True)
            return df_feat
        else:
            print(f"Ошибка при загрузке фишинговых ссылок: {response.status_code}")
            return pd.DataFrame(), pd.DataFrame()
    except Exception as e:
        print(f"Ошибка: {e}")
        return pd.DataFrame(), pd.DataFrame()

threads = 100
filename_text = "text_dataset.csv"
filename_url = "dataset.csv"
df_url_existing = loadCSV(filename_url)

features_list = []
legit, phis = 0,0
for i, r in df_url_existing.iterrows():
    status = r['is_fraud']
    features_list.append(getURLFeatures(i,status))
    if status == 1:
        phis += 1
    else:
        legit += 1

print(legit, phis)
exit()
df_url_existing = pd.DataFrame(features_list).set_index("url")
urls = ["https://btsu.tj/", "https://www.bsuir.by/ru/memorandumy", "https://iit.bsuir.by/en/courses", "https://dostavka.kufar.by/", "https://re.kufar.by/", "https://auto.kufar.by/", "https://business.kufar.by/", "https://analytics.wildberries.ru","https://dev.wildberries.ru", "https://seller.wildberries.ru"]

def makeURLs():
    features_list = []
    for item in urls:
        features_list.append(getURLFeatures(item,0))
    
    return pd.DataFrame(features_list).set_index("url")


df_url_phish = makeURLs()
df_url_existing = pd.concat([df_url_existing, df_url_phish])

trancoList = Tranco(cache=True, cache_dir='/tmp').list().top()

latest_list = [d for d in trancoList if d.endswith('.by')]

for i in range(100000):
    latest_list.append(trancoList[i])

# ------------------ Основной блок ------------------
if __name__ == "__main__":
    print("Загрузка списка Tranco...")
    print(f"Обработка {len(latest_list)} легитимных сайтов параллельно (до {threads} потоков)...")
    df_url_legit = scrape_content_parallel(latest_list, is_fishing=False, max_workers=threads)

    print("Обработка фишинговых ссылок...")
    df_url_phish = fetch_openphish_data_parallel(max_workers=threads)
    #df_url_phish, df_text_phish = pd.DataFrame(), pd.DataFrame()
    df_url_final = pd.concat([df_url_existing, df_url_legit, df_url_phish])

    df_url_final = df_url_final[~df_url_final.index.duplicated(keep='last')]

    df_url_final.to_csv(filename_url)
    print(df_url_final.info())

    print(f"Готово. Сохранено {len(df_url_final)} записей признаков URL.")
