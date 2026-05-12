"""
IMMUNIS ACIN — Synthetic Training Data Generator
==================================================

Generates structured training data for 3 fine-tuned models:
  1. IMMUNIS-Sentinel (Qwen2.5-7B): fingerprinting + antibody synthesis (50K)
  2. IMMUNIS-Adversary (Llama-3.1-8B): evasion variant generation (10K)
  3. IMMUNIS-Vision (Qwen2-VL-7B): visual threat classification (20K)

15 languages, 11 attack families, stratified sampling.
Output: JSONL in HuggingFace chat-template format for QLoRA.

Usage:
    python -m training.generate_data --output data/training --sentinel 50000
    python -m training.generate_data --all
"""

import json, random, hashlib, argparse, logging, os
from typing import Dict, Any, List
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
random.seed(42)

# ═════════════════════════════════════════════════════════════════════════════
# REFERENCE DATA
# ═════════════════════════════════════════════════════════════════════════════

LANG_WEIGHTS = {"en":.20,"zu":.08,"st":.08,"af":.06,"xh":.06,"tn":.05,
                "ar":.08,"zh":.08,"ru":.06,"pt":.05,"sw":.05,"fr":.04,
                "de":.04,"hi":.04,"es":.03}

FAMILIES = {
    "phishing":         {"m":["T1566.001","T1566.002","T1598"],"v":["email","web","visual"],       "s":{"critical":.05,"high":.30,"medium":.45,"low":.20}},
    "bec":              {"m":["T1534","T1566.001","T1078"],    "v":["email"],                       "s":{"critical":.25,"high":.45,"medium":.25,"low":.05}},
    "ransomware":       {"m":["T1486","T1490","T1027"],        "v":["email","endpoint","network"],  "s":{"critical":.50,"high":.35,"medium":.10,"low":.05}},
    "apt":              {"m":["T1071","T1059","T1053","T1547"],"v":["network","endpoint"],          "s":{"critical":.40,"high":.40,"medium":.15,"low":.05}},
    "supply_chain":     {"m":["T1195.001","T1195.002","T1199"],"v":["supply_chain","network"],     "s":{"critical":.35,"high":.40,"medium":.20,"low":.05}},
    "insider_threat":   {"m":["T1078","T1530","T1567"],        "v":["insider","endpoint"],          "s":{"critical":.20,"high":.35,"medium":.35,"low":.10}},
    "credential_theft": {"m":["T1110","T1003","T1555"],        "v":["web","email","network"],       "s":{"critical":.15,"high":.40,"medium":.35,"low":.10}},
    "data_exfiltration":{"m":["T1041","T1048","T1567"],        "v":["network","endpoint"],          "s":{"critical":.30,"high":.40,"medium":.25,"low":.05}},
    "malware":          {"m":["T1204","T1059","T1027","T1055"],"v":["email","endpoint","web"],      "s":{"critical":.25,"high":.40,"medium":.30,"low":.05}},
    "social_engineering":{"m":["T1566","T1598","T1534"],       "v":["email","voice","web"],          "s":{"critical":.10,"high":.30,"medium":.40,"low":.20}},
    "zero_day":         {"m":["T1190","T1203","T1211"],        "v":["network","endpoint","web"],     "s":{"critical":.60,"high":.30,"medium":.10,"low":.00}},
}

SE = ["urgency","authority","scarcity","social_proof","reciprocity","fear","greed","curiosity","impersonation","pretexting"]
DOMAINS = ["secure-login-verify.com","account-update-now.net","invoice-payment-hub.net","bank-verification-za.net","tax-refund-sars.co.za","fnb-security-alert.com","absa-verify.net","capitec-update.co.za","sars-efiling-login.com","vodacom-rewards.co.za","eskom-payment.co.za","municipality-billing.co.za"]
ENTITIES = ["Standard Bank","FNB","ABSA","Nedbank","Capitec","SARS","Eskom","Vodacom","MTN","Telkom","City of Tshwane","City of Johannesburg","SASSA","Discovery"]
AUTH = ["CEO","CFO","CTO","Managing Director","Head of Finance","IT Director","Legal Counsel","External Auditor","HR Director"]
SVC = ["Microsoft 365","Google Workspace","Standard Bank Online","FNB Online Banking","SARS eFiling","SharePoint","Salesforce","SAP","AWS Console","Azure Portal"]
FNAMES = ["Thabo","Sipho","Nomsa","Lerato","Ahmed","Chen","Fatima","James","Sarah","Pieter","Ayanda","Mpho","Bongani","Naledi"]
LNAMES = ["Mokoena","Nkosi","van der Merwe","Dlamini","Wang","Patel","Botha","Ndlovu","Joubert","Sithole","Molefe","Ibrahim"]
EVASION = ["language_switch","paraphrase","homoglyph_substitution","unicode_encoding","structural_reorder","authority_pivot","urgency_modulation","domain_typosquat","payload_fragmentation","social_engineering_pivot"]
VIS_TYPES = ["qr_phishing","deepfake","document_forgery","steganography","screenshot_phishing","clean"]

# ═════════════════════════════════════════════════════════════════════════════
# PLACEHOLDER FILL
# ═════════════════════════════════════════════════════════════════════════════

def _rc(L): return random.choice(L)
def _rn(): return f"{_rc(FNAMES)} {_rc(LNAMES)}"
def _ramt(): return f"{_rc(['R','$','€','£'])}{_rc(['2,500','5,000','12,450','25,000','75,000','250,000','500,000'])}"
def _rurl(): return f"https://{_rc(DOMAINS)}/{_rc(['verify','login','confirm','update','secure'])}?t={hashlib.md5(str(random.random()).encode()).hexdigest()[:10]}"
def _rip(): return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
def _rh(): return hashlib.sha256(str(random.random()).encode()).hexdigest()
def _rbtc(): return f"{random.uniform(0.5,15):.4f}"
def _rba(): return "bc1q"+hashlib.sha256(str(random.random()).encode()).hexdigest()[:38]

def _fill(t):
    M = {"{recipient}":_rn(),"{sender}":_rn(),"{authority}":_rc(AUTH),"{amount}":_ramt(),
         "{account}":str(random.randint(10**9,10**10-1)),"{url}":_rurl(),"{service}":_rc(SVC),
         "{entity}":_rc(ENTITIES),"{invoice_num}":f"INV-{random.randint(1000,9999)}",
         "{project}":_rc(["Q4 Migration","Cloud Upgrade","ERP Rollout","IT Audit"]),
         "{vendor}":_rc(["Acme Corp","TechPro Solutions","DataVault SA"]),
         "{quantity}":str(random.randint(5,20)),
         "{location}":_rc(["Lagos, Nigeria","Moscow, Russia","Beijing, China","Unknown VPN","Johannesburg, SA"]),
         "{btc_amount}":_rbtc(),"{btc_address}":_rba(),
         "{data_size}":_rc(["2.3 GB","15 GB","47 GB","500 MB"]),
         "{file_count}":str(random.randint(100,50000)),
         "{ip_address}":_rip(),"{internal_ip}":f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
         "{external_ip}":_rip(),"{c2_server}":_rip(),
         "{target_host}":f"app{random.randint(1,9)}.internal.corp",
         "{session_token}":hashlib.md5(str(random.random()).encode()).hexdigest(),
         "{encoded_payload}":"SQBFAFgA"+hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
         "{reg_key}":_rc(["WindowsUpdate","SystemHealth","SecurityMonitor"]),
         "{task_name}":_rc(["HealthCheck","SysUpdate","Maintenance"]),
         "{malware_path}":f"C:\\Windows\\Temp\\svc{random.randint(100,999)}.dll",
         "{package_name}":_rc(["crypt0-utils","node-fetch-v2","auth-helper-lib"]),
         "{version}":f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,99)}",
         "{version_range}":f"{random.randint(1,3)}.0-{random.randint(3,5)}.{random.randint(0,9)}",
         "{affected_count}":str(random.randint(50,50000)),"{hash}":_rh()[:32],
         "{product}":_rc(["SolarWinds Orion","Kaseya VSA","3CX Desktop"]),
         "{employee_id}":f"EMP-{random.randint(1000,9999)}","{employee_name}":_rn(),
         "{system}":_rc(["SharePoint","SAP","Oracle HCM","File Server"]),
         "{timestamp}":"2025-05-09T02:34:17Z","{record_count}":str(random.randint(1000,500000)),
         "{days_ago}":str(random.randint(3,30)),"{access_count}":str(random.randint(50,500)),
         "{sensitive_type}":_rc(["salary data","customer PII","trade secrets","source code"]),
         "{usb_serial}":f"USB-{_rh()[:8].upper()}","{port}":str(random.randint(1024,65535)),
         "{dns_domain}":f"{''.join(random.choices('abcdefghij',k=8))}.xyz",
         "{query_count}":str(random.randint(500,5000)),
         "{duration}":_rc(["15 minutes","2 hours","45 minutes"]),
         "{dwell_days}":str(random.randint(7,180)),
         "{software}":_rc(["Apache Log4j","Microsoft Exchange","Fortinet FortiOS","MOVEit Transfer"]),
         "{component}":_rc(["JNDI lookup","OWA module","VPN gateway"]),
         "{function}":_rc(["parse_request","handle_auth","process_upload"]),
         "{threat_actor}":_rc(["APT28","APT29","Lazarus Group","Sandworm","Cl0p","LockBit"]),
         "{exploit_technique}":_rc(["buffer overflow","SQL injection","deserialization","SSRF"]),
         "{payload_type}":_rc(["reverse shell","webshell","RAT","cryptominer"]),
         "{target_sector}":_rc(["financial","government","healthcare","energy"]),
         "{quarter}":str(random.randint(1,4)),"{file_size}":_rc(["245 KB","1.2 MB","3.7 MB"]),
         "{filename}":_rc(["Report_2025","Invoice_Final","Salary_Schedule"]),
         "{software_tool}":_rc(["AnyDesk","TeamViewer","UltraVNC"])}
    r = t
    for k,v in M.items(): r = r.replace(k,v)
    return r

# ═════════════════════════════════════════════════════════════════════════════
# CONTENT TEMPLATES
# ═════════════════════════════════════════════════════════════════════════════

_BEC = {
 "en":["Dear {recipient},\n\nUrgently transfer {amount} to account {account}. Approved by {authority}. Complete today.\n\nRegards,\n{authority}",
       "{recipient}, in a meeting. Buy {quantity} gift cards worth {amount} each. Send codes by email. Don't tell anyone.\n\n{authority}",
       "URGENT: Vendor {vendor} flagged overdue. Wire {amount} to {account} now. Approved by {authority}.\n\n{sender}",
       "Hi {recipient},\n\nAttached updated invoice #{invoice_num} for {amount}. Banking details changed — use account {account}.\n\nAccounts"],
 "zu":["Sawubona {recipient},\n\nThumela {amount} ku-{account} ngokushesha. Kugunyazwe ngu-{authority}.\n\n{authority}",
       "{recipient}, ngisemhlanganweni. Thenga ama-gift card angu-{quantity} angu-{amount}. Thumela amakhodi nge-email.\n\n{authority}"],
 "st":["Motswalle {recipient},\n\nRomela {amount} ho account {account} kapele. E lumelletsoe ke {authority}.\n\n{authority}",
       "{recipient}, ke kopanong. Reka li-gift card tse {quantity} tsa {amount}. Romela likhouthu ka email.\n\n{authority}"],
 "af":["Beste {recipient},\n\nStuur dringend {amount} na rekening {account}. Goedgekeur deur {authority}.\n\n{authority}"],
 "xh":["Mhlobo {recipient},\n\nThumela {amount} kwi-akhawunti {account} ngokukhawuleza. Kugunyaziswe ngu-{authority}.\n\n{authority}"],
 "tn":["Tsala {recipient},\n\nRomele {amount} mo go account {account} ka bonako. Letleletswe ke {authority}.\n\n{authority}"],
 "ar":["عزيزي {recipient}،\n\nتحويل {amount} إلى حساب {account} عاجلاً. موافقة {authority}.\n\n{authority}",
       "{recipient}، مرفق فاتورة #{invoice_num} بمبلغ {amount}. بيانات بنكية جديدة: {account}.\n\nالمحاسبة"],
 "zh":["{recipient}，请立即将{amount}转至{account}。{authority}已批准。\n\n{authority}",
       "{recipient}،附更新发票#{invoice_num}，金额{amount}。银行已更改，用{account}。\n\n财务部"],
 "ru":["Уважаемый {recipient},\n\nСрочно переведите {amount} на {account}. Одобрено {authority}.\n\n{authority}"],
 "pt":["Prezado {recipient},\n\nTransfira {amount} para conta {account}. Aprovado por {authority}.\n\n{authority}"],
 "sw":["Ndugu {recipient},\n\nTuma {amount} kwa akaunti {account} haraka. Imeidhinishwa na {authority}.\n\n{authority}"],
 "fr":["Cher {recipient},\n\nVirez {amount} sur compte {account}. Approuvé par {authority}.\n\n{authority}"],
 "de":["Sehr geehrte/r {recipient},\n\nÜberweisen Sie {amount} auf Konto {account}. Genehmigt: {authority}.\n\n{authority}"],
 "hi":["प्रिय {recipient},\n\n{amount} खाता {account} में ट्रांसफर करें। {authority} अनुमोदित।\n\n{authority}"],
 "es":["Estimado {recipient},\n\nTransfiera {amount} a cuenta {account}. Aprobado por {authority}.\n\n{authority}"],
}

_PHISH = {
 "en":["URGENT: {service} account compromised. Verify: {url}\n24h or suspended.",
       "Unusual activity on {service} from {location}. Review: {url}\nSecurity Team",
       "{service} password expires in 2h. Update: {url}\nIT Support",
       "ACTION REQUIRED: {service} payment {amount} failed. Update: {url}"],
 "zu":["ISEXWAYISO: I-akhawunti ye-{service} ivinjelwe. Qinisekisa: {url}",
       "Ukungena okungajwayelekile ku-{service} evela e-{location}. Shesha: {url}"],
 "st":["TEMOSO: Account ea {service} e thibetsoe. Netefatsa: {url}"],
 "af":["DRINGEND: {service} rekening gekompromitteer. Verifieer: {url}"],
 "xh":["ISILUMKISO: I-akhawunti ye-{service} imisiwe. Qinisekisa: {url}"],
 "tn":["TEMOSO: Akhaonto ya {service} e thibetswe. Netefatsa: {url}"],
 "ar":["تنبيه: حساب {service} مخترق. تحقق: {url}"],
 "zh":["紧急：{service}账户异常（{location}）。验证：{url}"],
 "ru":["ВНИМАНИЕ: {service} заблокирован. Подтвердите: {url}"],
 "pt":["URGENTE: Conta {service} comprometida. Verifique: {url}"],
 "sw":["TAHADHARI: Akaunti {service} imezuiwa. Thibitisha: {url}"],
 "fr":["URGENT: Compte {service} compromis. Vérifiez: {url}"],
 "de":["DRINGEND: {service}-Konto kompromittiert. Bestätigen: {url}"],
 "hi":["चेतावनी: {service} खाता ब्लॉक। सत्यापित: {url}"],
 "es":["URGENTE: Cuenta {service} comprometida. Verifique: {url}"],
}

_RANSOM = {
 "en":["FILES ENCRYPTED\nAES-256. Send {btc_amount} BTC to {btc_address}. 72 hours.",
       "NETWORK COMPROMISED\n{data_size} exfiltrated. Pay {btc_amount} BTC to {btc_address} in 48h or data published."],
 "zu":["AMAFAYELA AVALIWE\n{btc_amount} BTC ku: {btc_address}. Amahora 72."],
 "st":["LIFAELE LI KENNGOE KHOUTU\n{btc_amount} BTC ho: {btc_address}. Lihora 72."],
 "ar":["ملفاتك مشفرة\n{btc_amount} BTC إلى {btc_address}. 72 ساعة."],
 "zh":["文件已加密\n{btc_amount} BTC至{btc_address}。72小时。"],
 "ru":["ФАЙЛЫ ЗАШИФРОВАНЫ\n{btc_amount} BTC: {btc_address}. 72 часа."],
}

_TECH = {
 "apt":[
   "[SIEM] PowerShell: -enc {encoded_payload}\n{internal_ip}→{c2_server}\nexplorer>cmd>powershell>rundll32",
   "[EDR] Persistence: Run\\{reg_key}, Task {task_name} q30m\nC2: {c2_server} DNS tunnel. Beacon 300s",
   "GET /api/internal/config HTTP/1.1\nHost:{target_host}\nX-Forwarded-For:127.0.0.1\n[C2 beacon DNS-over-HTTPS dwell {dwell_days}d]"],
 "supply_chain":[
   "[ALERT] Compromised: {package_name} v{version}\nMalicious post-install. {affected_count} systems. Hash:{hash}",
   "Advisory: {product} build compromised. Versions {version_range}. Trojanised→{affected_count} customers"],
 "insider_threat":[
   "[DLP] {employee_name}({employee_id}): {file_count} files({data_size}) from {system}→personal cloud. Off-hours. PII:{record_count}",
   "[HR+SEC] {employee_name} resigned {days_ago}d ago. {system} {access_count}x/48h. USB:{usb_serial}. Data:{sensitive_type}"],
 "data_exfiltration":[
   "[NETFLOW] {internal_ip}:{port}→{external_ip}:443. {data_size}/{duration}. DNS:{dns_domain} {query_count}q/h. C2 exfil",
   "[SIEM] Staged exfil dwell {dwell_days}d. LDAP→{file_count} files→7z+AES→HTTPS {url}"],
 "zero_day":[
   "[VULN] 0-day {software} CVSS 9.8. RCE {component} {function}(). No patch. Disable {component}",
   "[INTEL] Active 0-day {software}. {threat_actor}. {exploit_technique}→{payload_type}. Sector:{target_sector}"],
 "malware":[
   "Attachment: Q{quarter}_Report.xlsx.exe({file_size}). Drops {malware_path}. C2:{c2_server}:443. Task+registry",
   "[AV] {filename}.docm macro→stage2 {url}. Keylogger+screencap. Exfil:{c2_server}"],
 "credential_theft":[
   "{service} session expired. Re-enter credentials. Login:{url}",
   "[Phishing Kit] Cloned {service} at {url}. LE cert 2h old. Creds→{c2_server}"],
 "social_engineering":[
   "Hi {recipient}, {entity} IT support. Virus detected—install {software_tool} from {url}.\n{sender}",
   "NOTICE: {entity} security audit. Reset password {url} within 4h.\nIT Security"],
}

def _get_content(lang, family):
    if family in _TECH: return _fill(_rc(_TECH[family]))
    for tpl_map, fam in [(_BEC,"bec"),(_PHISH,"phishing"),(_RANSOM,"ransomware")]:
        if family == fam:
            if lang in tpl_map: return _fill(_rc(tpl_map[lang]))
            return _fill(_rc(tpl_map["en"]))
    return _fill(_rc(_BEC.get(lang, _BEC["en"])))

# ═════════════════════════════════════════════════════════════════════════════
# EXAMPLE GENERATORS
# ═════════════════════════════════════════════════════════════════════════════

def _sev(fam):
    d = FAMILIES[fam]["s"]
    return random.choices(list(d.keys()), list(d.values()))[0]

def _se_scores(fam):
    presets = {"bec":(.8,.9,.9),"phishing":(.8,.6,.3),"ransomware":(.9,.3,.8),
               "apt":(.4,.2,.2),"zero_day":(.5,.2,.2),"social_engineering":(.7,.8,.4)}
    u,a,f = presets.get(fam, (.5,.5,.3))
    jitter = lambda v: round(max(0,min(1,v+random.uniform(-.15,.15))),2)
    return jitter(u), jitter(a), jitter(f)

SENTINEL_SYS = ("You are IMMUNIS-Sentinel, a multilingual cybersecurity threat analyst.\n"
    "Analyse raw threat data and produce a JSON fingerprint with: attack_family, "
    "attack_vector, severity, language, confidence, summary, iocs, techniques, "
    "code_switching, languages_detected, mitre_techniques, urgency_score, "
    "authority_score, financial_score.")

SYNTHESIS_SYS = ("You are IMMUNIS-Sentinel, a cybersecurity antibody synthesiser.\n"
    "Given a threat fingerprint, create a detection antibody in JSON with: name, "
    "description, detection_logic (patterns, semantic_indicators, thresholds, "
    "attack_families, language_agnostic, required_indicators), severity, "
    "mitre_techniques, false_positive_notes, recommended_action.")

ADVERSARY_SYS = ("You are IMMUNIS-Adversary, an adversarial AI for defensive testing.\n"
    "Given a threat and its antibody, generate an evasion variant in JSON with: "
    "variant_content, evasion_techniques, target_rules_evaded, preserved_intent, "
    "language, difficulty, explanation.")

VISION_SYS = ("You are IMMUNIS-Vision, a visual threat analyst.\n"
    "Analyse the image description for threats. Respond with JSON: threat_detected, "
    "threat_type, severity, confidence, description, indicators, urls_found, "
    "brands_impersonated, recommended_action.")


def gen_sentinel_fingerprint(lang, family):
    """One Sentinel fingerprinting training example (chat format)."""
    content = _get_content(lang, family)
    sev = _sev(family)
    u,a,f = _se_scores(family)
    meta = FAMILIES[family]
    vec = _rc(meta["v"])
    mitre = random.sample(meta["m"], min(random.randint(1,3), len(meta["m"])))
    techs = random.sample(SE, random.randint(1,4))
    cs = lang in ("zu","st","xh","tn","af","sw") and random.random()<.25
    langs = [lang,"en"] if cs else [lang]
    conf = round(random.uniform(.65,.98),2)

    fp = json.dumps({
        "attack_family":family, "attack_vector":vec, "severity":sev,
        "language":lang, "confidence":conf,
        "summary":f"{family.replace('_',' ').title()} threat in {lang.upper()}",
        "iocs":[_rurl() if random.random()<.5 else _rip() for _ in range(random.randint(1,3))],
        "techniques":techs, "code_switching":cs, "languages_detected":langs,
        "mitre_techniques":mitre, "urgency_score":u, "authority_score":a, "financial_score":f
    }, indent=2)

    return {"messages":[
        {"role":"system","content":SENTINEL_SYS},
        {"role":"user","content":f"Analyse this threat:\n---\n{content}\n---"},
        {"role":"assistant","content":fp}
    ]}


def gen_sentinel_synthesis(lang, family):
    """One Sentinel antibody synthesis training example."""
    sev = _sev(family)
    u,a,f = _se_scores(family)
    meta = FAMILIES[family]
    vec = _rc(meta["v"])
    mitre = random.sample(meta["m"], min(random.randint(1,2), len(meta["m"])))
    techs = random.sample(SE, random.randint(1,3))

    fp_input = json.dumps({
        "attack_family":family,"attack_vector":vec,"severity":sev,"language":lang,
        "confidence":round(random.uniform(.7,.95),2),
        "summary":f"{family.replace('_',' ').title()} threat in {lang.upper()}",
        "techniques":techs,"mitre_techniques":mitre,
        "urgency_score":u,"authority_score":a,"financial_score":f,
        "iocs":[_rurl() for _ in range(random.randint(1,2))]
    }, indent=2)

    name = f"{''.join(w.title() for w in family.split('_'))}_{sev.title()}_{lang.upper()}"
    antibody = json.dumps({
        "name":name,
        "description":f"Detects {family.replace('_',' ')} threats targeting {lang.upper()} speakers with {sev} severity",
        "detection_logic":{
            "patterns":[f".*{family}.*",f".*{_rc(techs)}.*"] if random.random()<.7 else [],
            "semantic_indicators":techs[:2],
            "thresholds":{"urgency_min":round(max(0,u-.2),2),"authority_min":round(max(0,a-.2),2),
                          "financial_min":round(max(0,f-.2),2),"confidence_min":.5},
            "attack_families":[family],
            "language_agnostic":lang=="en" or random.random()<.6,
            "required_indicators":random.randint(2,3)
        },
        "severity":sev,"mitre_techniques":mitre,
        "false_positive_notes":f"May trigger on legitimate {family.replace('_',' ')} communications",
        "recommended_action":_rc(["Block","Alert","Quarantine","Investigate"])
    }, indent=2)

    return {"messages":[
        {"role":"system","content":SYNTHESIS_SYS},
        {"role":"user","content":f"Create antibody for this fingerprint:\n{fp_input}"},
        {"role":"assistant","content":antibody}
    ]}


def gen_adversary(lang, family):
    """One Adversary evasion training example."""
    content = _get_content(lang, family)
    sev = _sev(family)
    meta = FAMILIES[family]
    mitre = random.sample(meta["m"], min(random.randint(1,2), len(meta["m"])))
    difficulty = _rc(["low","medium","high","extreme"])
    num_tech = {"low":1,"medium":2,"high":3,"extreme":4}[difficulty]
    evade_techs = random.sample(EVASION, min(num_tech, len(EVASION)))
    target_lang = lang
    if "language_switch" in evade_techs:
        target_lang = _rc([l for l in LANG_WEIGHTS if l != lang])

    variant_content = _get_content(target_lang, family)
    # Simulate evasion modifications
    if "homoglyph_substitution" in evade_techs:
        variant_content = variant_content.replace("a","а",1).replace("e","е",1)  # Cyrillic
    if "structural_reorder" in evade_techs:
        parts = variant_content.split("\n")
        if len(parts) > 2: random.shuffle(parts); variant_content = "\n".join(parts)

    ab_name = f"{''.join(w.title() for w in family.split('_'))}_Detection"
    fp_and_ab = json.dumps({
        "threat":{"attack_family":family,"severity":sev,"language":lang,"summary":content[:100]},
        "antibody":{"name":ab_name,"detection_logic":{
            "patterns":[f".*{family}.*"],"semantic_indicators":random.sample(SE,2),
            "thresholds":{"urgency_min":.5,"authority_min":.5,"confidence_min":.5},
            "attack_families":[family]}}
    }, indent=2)

    evasion = json.dumps({
        "variant_content":variant_content[:500],
        "evasion_techniques":evade_techs,
        "target_rules_evaded":[f"pattern_{family}","threshold_urgency"],
        "preserved_intent":family.replace("_"," "),
        "language":target_lang,
        "difficulty":difficulty,
        "explanation":f"Evades {ab_name} via {', '.join(evade_techs)}"
    }, indent=2)

    return {"messages":[
        {"role":"system","content":ADVERSARY_SYS},
        {"role":"user","content":f"Generate {difficulty} evasion variant:\n{fp_and_ab}"},
        {"role":"assistant","content":evasion}
    ]}


def gen_vision(threat_type):
    """One Vision classification training example."""
    is_threat = threat_type != "clean"
    conf = round(random.uniform(.75,.98),2) if is_threat else round(random.uniform(.01,.15),2)
    sev = _rc(["critical","high","medium"]) if is_threat else "info"

    # Simulated image description (vision models receive image + text prompt)
    descs = {
        "qr_phishing": f"Image contains a QR code. Decoded URL: {_rurl()}. "
            f"Domain resembles {_rc(ENTITIES)} but uses typosquatting. "
            f"Surrounding text: 'Scan to verify your account'",
        "deepfake": f"Video frame of person resembling {_rc(AUTH)} of {_rc(ENTITIES)}. "
            f"FFT analysis shows periodic artifacts at mid-frequencies. "
            f"No EXIF camera metadata. Facial boundary inconsistencies visible.",
        "document_forgery": f"Scanned document claiming to be from {_rc(ENTITIES)}. "
            f"ELA reveals inconsistent compression in signature region. "
            f"Font changes between paragraphs. Logo resolution differs from body.",
        "steganography": f"PNG image {_rc(['1920x1080','3840x2160','1280x720'])}. "
            f"Chi-squared LSB test: normalised value 0.{random.randint(10,45)}. "
            f"LSB distribution anomaly in blue channel. Estimated payload: {random.randint(1,50)}KB.",
        "screenshot_phishing": f"Screenshot of {_rc(SVC)} login page. "
            f"URL bar shows {_rurl()}. Brand logo present: {_rc(ENTITIES)}. "
            f"Keywords: 'verify', 'password', 'suspended'. Certificate: Let's Encrypt.",
        "clean": f"Corporate document: {_rc(['quarterly report','meeting minutes','org chart'])}. "
            f"No QR codes, no anomalous compression, standard EXIF data. "
            f"Font consistent throughout. No suspicious URLs.",
    }

    indicators = []
    urls = []
    brands = []
    if threat_type == "qr_phishing":
        indicators = ["QR code decoded","Typosquatting domain","Suspicious URL"]
        urls = [_rurl()]
        brands = [_rc(ENTITIES)]
    elif threat_type == "deepfake":
        indicators = ["FFT frequency artifacts","Missing EXIF","Facial boundary issues"]
    elif threat_type == "document_forgery":
        indicators = ["ELA variance > 15","Font inconsistency","Logo resolution mismatch"]
        brands = [_rc(ENTITIES)]
    elif threat_type == "steganography":
        indicators = ["Chi-squared < 0.5","LSB distribution anomaly","Estimated hidden payload"]
    elif threat_type == "screenshot_phishing":
        indicators = ["Login form detected","Brand impersonation","Suspicious URL","Recent certificate"]
        urls = [_rurl()]
        brands = [_rc(ENTITIES)]

    result = json.dumps({
        "threat_detected":is_threat,
        "threat_type":threat_type,
        "severity":sev,
        "confidence":conf,
        "description":descs[threat_type][:200],
        "indicators":indicators,
        "urls_found":urls,
        "brands_impersonated":brands,
        "recommended_action":_rc(["Block","Alert","Quarantine","Investigate"]) if is_threat else "Allow"
    }, indent=2)

    return {"messages":[
        {"role":"system","content":VISION_SYS},
        {"role":"user","content":f"Analyse this image:\n---\n{descs[threat_type]}\n---"},
        {"role":"assistant","content":result}
    ]}


# ═════════════════════════════════════════════════════════════════════════════
# STRATIFIED SAMPLING
# ═════════════════════════════════════════════════════════════════════════════

def _sample_lang():
    return random.choices(list(LANG_WEIGHTS.keys()), list(LANG_WEIGHTS.values()))[0]

def _sample_family():
    fams = list(FAMILIES.keys())
    return random.choice(fams)  # uniform across families for balanced training


# ═════════════════════════════════════════════════════════════════════════════
# DATASET GENERATION
# ═════════════════════════════════════════════════════════════════════════════

def generate_sentinel_dataset(n: int, output_dir: Path):
    """Generate n Sentinel training examples (70% fingerprint, 30% synthesis)."""
    path = output_dir / "sentinel_train.jsonl"
    n_fp = int(n * 0.7)
    n_syn = n - n_fp
    lang_counts = Counter()
    family_counts = Counter()

    logger.info(f"Generating {n} Sentinel examples ({n_fp} fingerprint + {n_syn} synthesis)...")

    with open(path, "w", encoding="utf-8") as f:
        for i in range(n_fp):
            lang = _sample_lang()
            fam = _sample_family()
            example = gen_sentinel_fingerprint(lang, fam)
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            lang_counts[lang] += 1
            family_counts[fam] += 1
            if (i+1) % 10000 == 0:
                logger.info(f"  Fingerprint: {i+1}/{n_fp}")

        for i in range(n_syn):
            lang = _sample_lang()
            fam = _sample_family()
            example = gen_sentinel_synthesis(lang, fam)
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            lang_counts[lang] += 1
            family_counts[fam] += 1
            if (i+1) % 10000 == 0:
                logger.info(f"  Synthesis: {i+1}/{n_syn}")

    logger.info(f"Sentinel dataset: {path} ({n} examples)")
    logger.info(f"  Languages: {dict(lang_counts.most_common())}")
    logger.info(f"  Families:  {dict(family_counts.most_common())}")
    return path


def generate_adversary_dataset(n: int, output_dir: Path):
    """Generate n Adversary evasion training examples."""
    path = output_dir / "adversary_train.jsonl"
    logger.info(f"Generating {n} Adversary examples...")

    with open(path, "w", encoding="utf-8") as f:
        for i in range(n):
            lang = _sample_lang()
            fam = _sample_family()
            example = gen_adversary(lang, fam)
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            if (i+1) % 5000 == 0:
                logger.info(f"  Adversary: {i+1}/{n}")

    logger.info(f"Adversary dataset: {path} ({n} examples)")
    return path


def generate_vision_dataset(n: int, output_dir: Path):
    """Generate n Vision classification training examples.

    Distribution: 70% threats (balanced across 5 types), 30% clean.
    """
    path = output_dir / "vision_train.jsonl"
    n_clean = int(n * 0.3)
    n_threat = n - n_clean
    threat_types = [t for t in VIS_TYPES if t != "clean"]
    logger.info(f"Generating {n} Vision examples ({n_threat} threats + {n_clean} clean)...")

    type_counts = Counter()
    with open(path, "w", encoding="utf-8") as f:
        for i in range(n_threat):
            vtype = _rc(threat_types)
            example = gen_vision(vtype)
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            type_counts[vtype] += 1
            if (i+1) % 5000 == 0:
                logger.info(f"  Vision threats: {i+1}/{n_threat}")

        for i in range(n_clean):
            example = gen_vision("clean")
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            type_counts["clean"] += 1

    logger.info(f"Vision dataset: {path} ({n} examples)")
    logger.info(f"  Types: {dict(type_counts.most_common())}")
    return path


def generate_eval_splits(output_dir: Path, eval_frac: float = 0.1):
    """Split each JSONL into train/eval sets."""
    for name in ["sentinel_train.jsonl", "adversary_train.jsonl", "vision_train.jsonl"]:
        path = output_dir / name
        if not path.exists():
            continue

        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        random.shuffle(lines)
        split = int(len(lines) * (1 - eval_frac))
        train_lines = lines[:split]
        eval_lines = lines[split:]

        train_path = output_dir / name.replace("_train", "_train_split")
        eval_path = output_dir / name.replace("_train", "_eval")

        with open(train_path, "w", encoding="utf-8") as f:
            f.writelines(train_lines)
        with open(eval_path, "w", encoding="utf-8") as f:
            f.writelines(eval_lines)

        logger.info(f"Split {name}: {len(train_lines)} train + {len(eval_lines)} eval")


def generate_all(output_dir: Path, sentinel_n=50000, adversary_n=10000, vision_n=20000):
    """Generate all training datasets."""
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Targets: Sentinel={sentinel_n}, Adversary={adversary_n}, Vision={vision_n}")
    logger.info("="*60)

    generate_sentinel_dataset(sentinel_n, output_dir)
    generate_adversary_dataset(adversary_n, output_dir)
    generate_vision_dataset(vision_n, output_dir)
    generate_eval_splits(output_dir)

    # Write manifest
    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "seed": 42,
        "datasets": {
            "sentinel": {"total": sentinel_n, "fingerprint": int(sentinel_n*.7),
                         "synthesis": sentinel_n - int(sentinel_n*.7)},
            "adversary": {"total": adversary_n},
            "vision": {"total": vision_n, "threats": int(vision_n*.7),
                       "clean": vision_n - int(vision_n*.7)},
        },
        "languages": list(LANG_WEIGHTS.keys()),
        "attack_families": list(FAMILIES.keys()),
        "visual_threat_types": VIS_TYPES,
    }
    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Manifest: {manifest_path}")
    logger.info("="*60)
    logger.info("DONE — All datasets generated.")


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="IMMUNIS ACIN Training Data Generator")
    parser.add_argument("--output", type=str, default="data/training",
                        help="Output directory for JSONL files")
    parser.add_argument("--sentinel", type=int, default=50000,
                        help="Number of Sentinel examples")
    parser.add_argument("--adversary", type=int, default=10000,
                        help="Number of Adversary examples")
    parser.add_argument("--vision", type=int, default=20000,
                        help="Number of Vision examples")
    parser.add_argument("--all", action="store_true",
                        help="Generate all datasets with default sizes")
    parser.add_argument("--sentinel-only", action="store_true",
                        help="Generate only Sentinel dataset")
    parser.add_argument("--adversary-only", action="store_true",
                        help="Generate only Adversary dataset")
    parser.add_argument("--vision-only", action="store_true",
                        help="Generate only Vision dataset")

    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    if args.sentinel_only:
        generate_sentinel_dataset(args.sentinel, out)
        generate_eval_splits(out)
    elif args.adversary_only:
        generate_adversary_dataset(args.adversary, out)
        generate_eval_splits(out)
    elif args.vision_only:
        generate_vision_dataset(args.vision, out)
        generate_eval_splits(out)
    else:
        generate_all(out, args.sentinel, args.adversary, args.vision)


if __name__ == "__main__":
    main()
