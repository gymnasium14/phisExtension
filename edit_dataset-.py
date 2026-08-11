import pandas as pd
import re
import ipaddress
from urllib.parse import urlparse, urlunparse, urlsplit
import codecs
import os

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
    "bond", "cc", "cf", "cfd", "fo", "ga", "gd", "ly", "online", "onion", "ph", "shop", "wf", "xin", "yt", "mu", "mp", "pro", "za", "in"
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

def decode_punycode_url(url: str) -> str:
    parsed = urlparse(url)
    hostname = urlsplit(url).hostname   # уже без порта и без квадратных скобок
    port = parsed.port

    # Если хоста нет (относительная ссылка) — возвращаем исходник
    if hostname is None:
        return url

    # Проверяем, нужно ли декодировать: только если это ASCII и начинается с "xn--"
    if hostname.isascii() and hostname.startswith('xn--'):
        try:
            decoded_host = codecs.decode(hostname.encode('ascii'), 'idna')
        except Exception:
            # Если декодирование не удалось — оставляем как есть
            decoded_host = hostname
    else:
        # Хост уже в нормальном виде или не содержит Punycode
        decoded_host = hostname

    # Собираем новый netloc
    netloc_parts = []

    # 2. Хост (для IPv6 добавляем квадратные скобки)
    if ':' in decoded_host:  # это IPv6
        decoded_host = f'[{decoded_host}]'
    netloc_parts.append(decoded_host)

    # 3. Порт (если есть)
    if port is not None:
        netloc_parts.append(f':{port}')

    new_netloc = ''.join(netloc_parts)

    # Собираем URL обратно
    return urlunparse((
        parsed.scheme,
        new_netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

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

import re
import ipaddress

def extract_ipv6(text: str):
    """
    Извлекает все IPv6-адреса из текстовой строки.

    Аргументы:
        text (str): строка для анализа (может содержать URL, логи, любой текст)

    Возвращает:
        list: список найденных IPv6-адресов (в канонической форме).
              Если адресов нет, возвращает пустой список.
    """
    # Регулярное выражение для поиска IPv6-адресов в различных форматах:
    # - с квадратными скобками (как в URL: http://[::1]:8080)
    # - без скобок (просто адрес)
    # Обрабатывает сокращённые, полные, с портом, с зоной (через %)
    ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|' \
                   r'(?:[0-9a-fA-F]{1,4}:){1,7}:|' \
                   r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' \
                   r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|' \
                   r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|' \
                   r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|' \
                   r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|' \
                   r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|' \
                   r':(?::[0-9a-fA-F]{1,4}){1,7}|' \
                   r'::|' \
                   r'[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}'

    # Ищем все совпадения (включая адреса в квадратных скобках)
    # Для URL вида http://[2001:db8::1] нужно сначала извлечь содержимое скобок
    # Но проще найти все потенциальные IPv6-подстроки, а затем проверить их модулем ipaddress

    # Попробуем найти адреса в квадратных скобках
    bracket_pattern = r'\[([0-9a-fA-F:%.]+)\]'
    brackets = re.findall(bracket_pattern, text)
    found = []

    for addr in brackets:
        # Убираем возможный порт после закрывающей скобки? Нет, порт отдельно.
        # Но внутри скобок только адрес, возможно с зоной.
        try:
            # Удаляем зону (если есть %interface)
            if '%' in addr:
                addr = addr.split('%')[0]
            ip = ipaddress.IPv6Address(addr)
            found.append(str(ip))
        except ValueError:
            continue

    # Теперь ищем адреса без скобок (просто IPv6 в тексте)
    # Используем то же регулярное выражение, но исключим уже найденные в скобках
    raw_matches = re.findall(ipv6_pattern, text, re.IGNORECASE)
    for candidate in raw_matches:
        # Если адрес уже есть в found – пропускаем
        # Проверяем валидность
        try:
            # Удаляем порт, если он приписан через двоеточие (но осторожно, т.к. в IPv6 много двоеточий)
            # Поэтому проверяем через ipaddress, он отбракует невалидные
            ip = ipaddress.IPv6Address(candidate)
            if str(ip) not in found:
                found.append(str(ip))
        except ValueError:
            continue

    return found


def has_ipv6_in_string(text: str) -> bool:
    """
    Проверяет, содержится ли в строке хотя бы один IPv6-адрес.
    """
    return bool(extract_ipv6(text))

def getURLFeatures(url: str, isFish: int):
    features = {}
    parsed = urlparse(url)
    if not url.startswith(('http://', 'https://')):
        urlEdited = 'http://' + url
    else:
        urlEdited = url
    hostname = urlsplit(urlEdited).hostname or "bruh"
    path = parsed.path or ""

    features["punycode"] = int("xn--" in hostname.lower())
    if (features["punycode"]):
        url = decode_punycode_url(url)
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

def loadCSV(filename: str):
    if os.path.exists(filename):
        return pd.DataFrame(pd.read_csv(filename, index_col="url"))
    else:
        return pd.DataFrame()

df_url_existing = loadCSV("dataset.csv")
df_url_existing1 = loadCSV("phishing_sites.csv")

df_url_final = pd.concat([df_url_existing, df_url_existing1])

df_url_existing = df_url_final[~df_url_final.index.duplicated(keep='last')]

features_list = []
for i, r in df_url_existing.iterrows():
    status = r['is_fraud']
    try:
        result = getURLFeatures(i,status)
        if result:
            features_list.append(result)
    except Exception as e:
        print(f"Ошибка {e} с {i}")

df_url_existing = pd.DataFrame(features_list).set_index("url")

df_url_existing.to_csv("dataset_new.csv")