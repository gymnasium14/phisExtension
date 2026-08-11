from tranco import Tranco
import json

custom = [
    "mvd.gov.by",
    "ndtp.by",
    "bsuir.by",
    "buissnes.kufar.by",
    "auto.kufar.by",
    "travel.kufar.by",
    "helpcenter.kufar.by",
    "karta.kuffar.by",
    "media.kufar.by"
]

trancoList = Tranco(cache=True, cache_dir='/tmp').list().top()

total = [d for d in trancoList if d.endswith('.by')]

for i in range(len(custom)):
    total.append(custom[i])
    pass

for i in range(3999):
    total.append(trancoList[i])
    pass

with open('whitelist.json', 'w', encoding='utf-8') as f:
    json.dump(total, f, ensure_ascii=False, indent=1)
    pass