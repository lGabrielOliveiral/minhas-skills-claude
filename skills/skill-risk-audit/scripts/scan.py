#!/usr/bin/env python3
"""
skill-risk-audit -- Etapa 1 (deterministica) do auditor de skills.

Le skills e plugins instalados SEM executa-los e gera, em JSON:
  - nota de 0 a 4 por categoria, com evidencias;
  - combinacoes perigosas;
  - piso que a etapa 2 (o Claude) nao pode rebaixar;
  - cobertura: o que nao foi lido e por que.

Uso:
  python scan.py --list [--cwd PASTA_DO_PROJETO]
  python scan.py --scope all [--cwd PASTA_DO_PROJETO]
  python scan.py --target NOME_OU_CAMINHO [--cwd PASTA_DO_PROJETO]

Somente biblioteca padrao. Nao acessa a rede. Nao executa nada da skill analisada.
Nao ha marcador de supressao: nada dentro da skill analisada silencia uma regra.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import bisect
import hashlib
import json
import os
import re
import sys
import zlib
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

SELF_DIR = Path(__file__).resolve().parent.parent

CATEGORIES = {
    1: "Instruções ao agente",
    2: "Execução de código",
    3: "Credenciais e arquivos sensíveis",
    4: "Rede e envio de dados",
    5: "Persistência e memória",
    6: "Permissões, hooks e MCP",
    7: "Cadeia de suprimentos",
    8: "Ocultação",
    9: "Coerência (etapa 2)",
    10: "Cobertura",
}

FULL_READ_LIMIT = 2_000_000      # acima disso, le inicio + fim e marca cobertura parcial
HEAD_TAIL_BYTES = 256_000
MAX_FILES = 3000                 # por alvo; acima disso, cobertura parcial
PADDING_MIN_SIZE = 200_000
PADDING_RATIO = 0.03             # compressao abaixo disso = enchimento repetitivo
MAX_FINDINGS_PER_CATEGORY = 15
MAX_HITS_PER_RULE_PER_FILE = 5
EVIDENCE_WIDTH = 160

MEDIA_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".woff", ".woff2",
              ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov"}
ARCHIVE_EXTS = {".pdf", ".zip", ".gz", ".tgz", ".tar", ".7z", ".rar", ".bz2", ".xz", ".docx",
                ".xlsx", ".pptx", ".jar", ".whl", ".egg", ".skill"}
BINARY_EXEC_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".com", ".scr", ".elf",
                    ".pyc", ".pyo", ".node", ".deb", ".rpm", ".apk", ".dmg", ".sys", ".o"}
CODE_KINDS = {".py": "python", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
              ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
              ".bat": "batch", ".cmd": "batch", ".js": "javascript", ".mjs": "javascript",
              ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript", ".jsx": "javascript",
              ".rb": "ruby", ".pl": "perl", ".php": "php", ".vbs": "vbscript", ".lua": "lua",
              ".go": "go", ".rs": "rust", ".java": "java", ".cs": "csharp"}
CODE_KIND_SET = set(CODE_KINDS.values())
TEXT_KIND_SET = {"manifest", "markdown", "text"}
RULE_LANGS = {"en", "pt", "es"}
CONF_ORDER = {"alta": 3, "media": 2, "baixa": 1}


@dataclass
class Finding:
    cat: int
    grade: int
    conf: str
    rule: str
    title: str
    file: str
    line: int
    evidence: str
    floor: bool = False
    end_line: int = 0


# --------------------------------------------------------------------------- #
# Regras (en / pt / es). Escopo: any | text | code | nonpy
# --------------------------------------------------------------------------- #
RULES: list[tuple] = []

# Em documentação (markdown/texto), algumas regras valem menos: guias legítimos citam
# esses termos com frequência. Em código, a nota original se mantém.
TEXT_GRADE = {"K1": 2, "K1b": 1, "N2": 2, "C1": 2}


def rule(rid, cat, grade, conf, scope, title, pattern, floor=False, case=False):
    flags = re.MULTILINE if case else re.IGNORECASE | re.MULTILINE
    RULES.append((rid, cat, grade, conf, scope, title, re.compile(pattern, flags), floor))


# 1. Instrucoes ao agente
rule("I1", 1, 3, "alta", "any", "Tenta sobrescrever as instruções do agente",
     r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts?)"
     r"|disregard\s+(?:all\s+|your\s+|the\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules|system\s+prompt|guidelines)"
     r"|forget\s+(?:all\s+)?(?:your\s+|the\s+)?(?:previous\s+|prior\s+)?instructions"
     r"|ignor(?:e|ar|em)\s+(?:todas\s+)?(?:as\s+)?(?:instru[cç](?:[oõ]es|[aã]o)|regras)\s+(?:anteriores|acima|pr[eé]vias)"
     r"|desconsider(?:e|ar)\s+(?:todas\s+)?(?:as\s+|suas\s+)?(?:instru[cç]|regras|orienta[cç])"
     r"|esque[cç]a\s+(?:todas\s+)?(?:as\s+|suas\s+)?(?:instru[cç]|regras)"
     r"|ignor(?:a|ar)\s+(?:todas\s+)?(?:las\s+)?(?:instrucciones|reglas)\s+(?:anteriores|previas)"
     r"|olvida\s+(?:todas\s+)?(?:las\s+|tus\s+)?instrucciones")

rule("I2", 1, 4, "alta", "any", "Tenta manipular o auditor de segurança",
     r"(?:mark|classify|rate|report|treat|consider|label)\s+(?:this\s+|the\s+)?(?:skill|plugin|file|package|code)\s+as\s+(?:safe|clean|benign|trusted|harmless|low[\s-]risk)"
     r"|if\s+you\s+are\s+(?:an?\s+)?(?:ai\s+|llm\s+|security\s+)?(?:scanner|auditor|reviewer|analy[sz]er|analy[sz]ing\s+this)"
     r"|(?:marque|classifique|considere|avalie|trate|rotule)\s+(?:esta\s+|essa\s+|este\s+|esse\s+)?(?:skill|plugin|arquivo|c[oó]digo)\s+como\s+(?:segur[ao]|confi[aá]vel|benign[ao]|limp[ao]|inofensiv[ao]|baixo\s+risco)"
     r"|se\s+voc[eê]\s+(?:for|[eé])\s+(?:um\s+|uma\s+)?(?:ia\s+|llm\s+)?(?:scanner|auditor|revisor|analisador|ferramenta\s+de\s+seguran)"
     r"|(?:marca|clasifica|considera|trata)\s+(?:esta\s+|este\s+)?(?:skill|plugin|archivo|c[oó]digo)\s+como\s+(?:segur[ao]|confiable|benign[ao]|limpi[ao]|inofensiv[ao])"
     r"|si\s+eres\s+(?:un\s+|una\s+)?(?:ia\s+)?(?:esc[aá]ner|auditor|revisor|analizador)",
     floor=True)

rule("I2b", 1, 2, "media", "text", "Pede para não reportar achados ou pular a análise",
     r"(?:do\s+not|don'?t|never)\s+(?:report|flag|raise)\s+(?:any\s+)?(?:security\s+)?(?:findings?|vulnerabilit\w*)"
     r"|(?:skip|bypass)\s+(?:the\s+)?security\s+(?:scan|audit|review|analysis)"
     r"|n[aã]o\s+(?:reporte|relate|sinalize|aponte)\s+(?:nenhum\s+|qualquer\s+)?(?:achado|vulnerabilidade)"
     r"|(?:pule|burle)\s+(?:a\s+)?(?:varredura|auditoria)\s+de\s+seguran[cç]a"
     r"|no\s+(?:reportes|informes|se[nñ]ales)\s+(?:ning[uú]n\s+)?(?:hallazgo|vulnerabilidad)")

rule("I3", 1, 3, "alta", "any", "Manda esconder ações do usuário",
     r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|warn)\s+(?:this\s+|it\s+|anything\s+)?(?:to\s+)?(?:the\s+)?user"
     r"|(?:do\s+not|don'?t|never)\s+mention\s+(?:this\s+|it\s+)?to\s+(?:the\s+)?user"
     r"|without\s+(?:telling|informing|notifying|asking|alerting)\s+(?:the\s+user|anyone|anybody)"
     r"(?!\s+to\s+(?:restate|repeat|re-?enter|re-?type|re-?explain|provide\s+(?:it|this|them)\s+again))"
     r"|sem\s+(?:avisar|informar|contar\s+a|alertar|notificar)\s+ningu[eé]m"
     r"|sin\s+(?:avisar|informar|decir)(?:le)?\s+a\s+nadie"
     r"|(?:hide|conceal)\s+(?:this|it|these|the)\s+(?:\w+\s+)?from\s+(?:the\s+)?user"
     r"|n[aã]o\s+(?:conte|diga|mencione|informe|avise|revele|alerte)\s+(?:isso\s+|isto\s+|nada\s+|sobre\s+isso\s+)?(?:ao|para\s+o)\s+usu[aá]rio"
     r"|sem\s+(?:avisar|informar|contar|perguntar|alertar|notificar)\s+(?:ao\s+|o\s+)?usu[aá]rio"
     r"|(?:esconda|oculte)\s+(?:isso|isto|ess[ae]s?\s+\w+)\s+do\s+usu[aá]rio"
     r"|no\s+(?:le\s+)?(?:digas|menciones|informes|muestres|avises)\s+(?:nada\s+|esto\s+)?al\s+usuario"
     r"|sin\s+(?:avisar|informar|decir|preguntar)(?:le)?\s+al\s+usuario")

rule("I3b", 1, 1, "baixa", "text", "Palavra de ação encoberta",
     r"\b(?:silently|secretly|covertly|stealthily|secretamente|silenciosamente|sigilosamente|en\s+secreto|às\s+escondidas)\b")

rule("I4", 1, 3, "media", "text", "Instrução para enviar dados para fora",
     r"(?:send|upload|post|forward|transmit|exfiltrate|leak)\s+(?:the\s+|all\s+|any\s+|full\s+|its\s+|your\s+)*(?:contents?|conversation|chat\s+history|context|data|files?|credentials?|keys?|tokens?|secrets?|passwords?|environment)\b[^\n]{0,60}(?<!\bup\s)\b(?:to|into)\b(?!\s+\d)"
     r"|(?:envie|mande|encaminhe|transmita|publique|suba)\s+(?:o\s+|a\s+|os\s+|as\s+|todo\s+o\s+|todos\s+os\s+)?(?:conte[uú]do|conversa|hist[oó]rico|contexto|dados|arquivos?|credenciais|chaves?|tokens?|segredos?|senhas?)\b[^\n]{0,60}\b(?:para|ao|no|na)\b"
     r"|(?:env[ií]a|manda|reenv[ií]a|sube|transmite)\s+(?:el\s+|la\s+|los\s+|las\s+|todo\s+el\s+)?(?:contenido|conversaci[oó]n|historial|contexto|datos|archivos?|credenciales|claves|tokens?|secretos|contrase[nñ]as)\b[^\n]{0,60}\b(?:a|al|para)\b")

rule("I5", 1, 2, "media", "text", "Instrução para ler ou colar segredos",
     r"(?:\bread|\bcat|\bopen|\bcopy|\bpaste|\binclude|\bprint|\bleia|\babra|\bcopie|\bcole|\binclua|\bimprima|\blea|\bcopia|\bpega|\bincluye)\b[^\n]{0,50}"
     r"(?:[/\\]\.ssh\b|\bid_rsa\b|\bid_ed25519\b|\.aws[/\\]credentials|\.env\b|\.npmrc\b|\.git-credentials|\.credentials\.json|\bapi[_\s-]?keys?\b|\baccess\s+tokens?\b|\bcredenciais\b|\bcredenciales\b|\bsenhas?\b|\bcontrase[nñ]as\b)")

rule("I7", 1, 2, "media", "any", "Desvia a comunicação com o usuário para fora da sessão",
     r"(?:is\s+not|isn'?t|not)\s+(?:watching|reading|monitoring|following)\s+(?:this|the)\s+(?:session|chat|conversation|terminal)"
     r"|(?:user|they)\s+(?:is|are)\s+only\s+(?:watching|reading|monitoring|following)\s+(?:the\s+)?\w+"
     r"|all\s+(?:feedback|communication|messages|updates)\s+(?:to\s+the\s+user\s+)?(?:must|should)\s+(?:be\s+)?(?:sent|go|happen)\s+(?:through|via|in|on|to)\b"
     r"|(?:do\s+not|don'?t|never)\s+(?:reply|respond|answer|report)\s+(?:to\s+the\s+user\s+)?(?:in|on)\s+(?:the\s+|this\s+)?(?:chat|session|terminal|conversation)"
     r"|(?:n[aã]o\s+est[aá]|n[aã]o\s+fica)\s+(?:acompanhando|olhando|lendo|monitorando)\s+(?:esta|a|essa)\s+(?:sess[aã]o|conversa|terminal)"
     r"|o\s+usu[aá]rio\s+(?:s[oó]|apenas)\s+(?:acompanha|olha|l[eê]|monitora)\s+(?:o|a)\s+\w+"
     r"|o\s+usu[aá]rio\s+(?:acompanha|olha|l[eê]|monitora)\s+(?:s[oó]|apenas)\s+(?:o|a)\s+\w+"
     r"|toda\s+(?:a\s+)?comunica[cç][aã]o\s+(?:com\s+o\s+usu[aá]rio\s+)?deve\s+(?:ser\s+)?(?:enviada|feita)\s+(?:por|pel[oa]|via|no|na)\b"
     r"|n[aã]o\s+(?:responda|reporte|escreva)\s+(?:ao\s+usu[aá]rio\s+)?(?:no|na|nesta)\s+(?:chat|sess[aã]o|terminal|conversa)"
     r"|(?:no\s+est[aá]|no\s+sigue)\s+(?:viendo|mirando|leyendo)\s+(?:esta|la)\s+(?:sesi[oó]n|conversaci[oó]n|terminal)"
     r"|toda\s+(?:la\s+)?comunicaci[oó]n\s+(?:con\s+el\s+usuario\s+)?debe\s+(?:ser\s+)?(?:enviada|hecha)\s+(?:por|a\s+trav[eé]s\s+de|en)\b")

rule("I6", 1, 2, "media", "text", "Pede para revelar o prompt de sistema",
     r"(?:reveal|print|show|output|repeat|dump|leak)\s+(?:your|the)\s+(?:full\s+)?(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)"
     r"|(?:revele|mostre|imprima|repita)\s+(?:o\s+|seu\s+)?(?:prompt\s+de\s+sistema|system\s+prompt|instru[cç][oõ]es\s+(?:ocultas|iniciais))"
     r"|(?:revela|muestra|imprime|repite)\s+(?:el\s+|tu\s+)?(?:prompt\s+del\s+sistema|system\s+prompt)")

# 2. Execucao de codigo
rule("C1", 2, 3, "alta", "any", "Baixa um script e executa direto (curl | sh)",
     r"(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
     r"|(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b"
     r"|(?:ba|z)?sh\s+<\(\s*(?:curl|wget)"
     r"|(?:ba|z)?sh\s+-c\s+[\"']?\$\((?:curl|wget)")

rule("C2", 2, 3, "alta", "any", "PowerShell baixa e executa código (download cradle)",
     r"(?:\biex\b|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+(?:System\.)?Net\.WebClient|\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod|\[System\.Net\.WebClient\])"
     r"|(?:\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]{0,200}\|\s*(?:\biex\b|Invoke-Expression)")

rule("C3", 8, 3, "alta", "any", "Comando PowerShell codificado ou decodificado e executado",
     r"(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{16,}"
     r"|FromBase64String\s*\([^)\n]{0,300}\)[^\n]{0,80}(?:\biex\b|Invoke-Expression|Invoke-Command|\.Invoke\(|Start-Process)")

rule("C4", 2, 4, "alta", "any", "Decodifica conteúdo escondido e executa",
     r"(?:\bexec|\beval)\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|codecs\.decode|zlib\.decompress|gzip\.decompress|marshal\.loads|atob|Buffer\.from\s*\([^)\n]{0,300}['\"]base64['\"]\))"
     r"|base64\s+(?:-d|--decode)\b[^\n]{0,60}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
     floor=True)

rule("C5", 2, 1, "baixa", "code", "Executa código inline (python -c, node -e)",
     r"\b(?:python3?|node|perl|ruby)\s+-(?:c|e)\s+['\"]")

rule("C6", 2, 2, "alta", "text", "Comando `!` que roda antes do Claude ler a skill",
     r"(?<![\w`])!`[^`\n]+`")

rule("C7", 2, 2, "media", "any", "Torna executável e roda de pasta temporária",
     r"chmod\s+\+x\s+[^\n]{0,80}(?:/tmp/|\$TMPDIR|%TEMP%|\$env:TEMP)")

rule("C8", 2, 3, "alta", "any", "Usa binário do Windows comum em ataques (LOLBin)",
     r"\bmshta(?:\.exe)?\s|\brundll32(?:\.exe)?\s|\bregsvr32(?:\.exe)?\s|\bcertutil(?:\.exe)?\s+-(?:urlcache|decode)|\bbitsadmin(?:\.exe)?\s+/transfer")

rule("C9", 2, 1, "baixa", "any", "Inicia processo externo",
     r"\bStart-Process\b|\bInvoke-Command\b|\bcmd(?:\.exe)?\s+/c\b")

rule("C10", 2, 2, "media", "nonpy", "Execução dinâmica em script",
     r"child_process|\bexecSync\s*\(|\bspawnSync\s*\(|\bnew\s+Function\s*\(|(?<![\w.])eval\s*\(|\bInvoke-Expression\b|(?<![\w-])iex\s")

# 3. Credenciais
rule("K1", 3, 3, "alta", "any", "Referência a chave SSH privada",
     r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)")
rule("K1b", 3, 2, "media", "any", "Referência à pasta .ssh",
     r"[~$\w%]?[/\\]\.ssh[/\\]")
rule("K2", 3, 3, "alta", "any", "Referência a arquivo de credenciais",
     r"\.aws[/\\]+credentials|\.config[/\\]+gcloud|\.azure[/\\]+|\.kube[/\\]+config|\.docker[/\\]+config\.json"
     r"|\.git-credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.claude[/\\]+\.credentials\.json|\.config[/\\]+gh[/\\]+hosts\.yml")
rule("K3", 3, 3, "alta", "any", "Acesso a cofre de senhas, cookies ou dados do navegador",
     r"Login\s+Data\b|cookies\.sqlite|\bLocal\s+State\b|wallet\.dat|\bkeychain\b|security\s+find-(?:generic|internet)-password"
     r"|Get-StoredCredential|\bcmdkey\b|CredentialManager|ProtectedData\]?::Unprotect|CryptUnprotectData"
     r"|\\Microsoft\\Credentials|Chrome[/\\]+User\s+Data|Mozilla[/\\]+Firefox[/\\]+Profiles")
rule("K4", 3, 3, "alta", "any", "Coleta todas as variáveis de ambiente",
     r"dict\s*\(\s*os\.environ\s*\)|os\.environ\.(?:items|copy)\s*\(|json\.dumps\s*\(\s*(?:dict\s*\()?\s*os\.environ"
     r"|\bprintenv\b|\benv\s*\|\s*(?:curl|nc|base64)|Get-ChildItem\s+env:|\bgci\s+env:|\bdir\s+env:"
     r"|JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\s*\(\s*process\.env\s*\)")
rule("K5", 3, 1, "baixa", "any", "Lê variável de ambiente com segredo",
     r"(?:os\.environ(?:\.get)?|getenv|process\.env|\$env:|\$\{?)[\[\(\.\s'\"]*[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY)",
     case=True)
rule("K6", 3, 2, "media", "any", "Lê arquivo .env",
     r"(?:\bopen\s*\(|read_text|readFileSync|readFile\s*\(|Get-Content|\bcat\s|\btype\s)[^\n]{0,40}\.env\b")

# 4. Rede
rule("N1", 4, 2, "media", "any", "Envia dados pela rede",
     r"requests\.(?:post|put|patch)\s*\(|httpx\.(?:post|put|patch)\s*\(|urlopen\s*\([^)\n]{0,300}data\s*=|aiohttp[^\n]{0,60}\.post\s*\("
     r"|fetch\s*\([^)\n]{0,300}method\s*:\s*['\"](?:POST|PUT|PATCH)|axios\.(?:post|put|patch)\s*\("
     r"|\bcurl\b[^\n]{0,200}\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|-X\s*(?:POST|PUT))\b"
     r"|\bwget\b[^\n]{0,200}--post-(?:data|file)|Invoke-(?:WebRequest|RestMethod)\b[^\n]{0,200}-Method\s+['\"]?(?:Post|Put|Patch)"
     r"|\.Upload(?:String|File|Data)\s*\(|\bscp\s+[^\n]{0,100}@|\brsync\s+[^\n]{0,100}@[^\n]{0,60}:")
rule("N2", 4, 3, "alta", "any", "Endpoint usado para coletar dados (webhook, túnel, paste)",
     r"discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|webhook\.site|requestbin|pipedream\.net"
     r"|ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|interact\.sh|\boast\.(?:fun|me|pro|live|site|online)"
     r"|burpcollaborator|pastebin\.com|transfer\.sh|\bfile\.io\b|api\.telegram\.org/bot|\b0x0\.st\b|\btemp\.sh\b")
rule("N3", 4, 2, "media", "any", "URL com IP direto",
     r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}")
rule("N4", 4, 4, "alta", "any", "Shell reverso",
     r"/dev/tcp/|bash\s+-i\s+>&|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s|\bsocat\b[^\n]{0,80}exec:"
     r"|Net\.Sockets\.TCPClient|os\.dup2\s*\(\s*\w+\.fileno\(\)",
     floor=True)
rule("N5", 4, 1, "baixa", "any", "Baixa conteúdo da internet",
     r"requests\.get\s*\(|urlopen\s*\(|urllib\.request|httpx\.get\s*\(|\bcurl\s|\bwget\s|Invoke-WebRequest|Invoke-RestMethod"
     r"|(?<![\w-])iwr\s|(?<![\w-])irm\s|\.DownloadString\s*\(|\.DownloadFile\s*\(")

# 5. Persistencia e memoria
rule("P1", 5, 4, "alta", "code", "Escreve na memória ou nas regras do agente",
     r"(?:>>?|Add-Content|Set-Content|Out-File|tee\s+-a|open\s*\([^)\n]{0,300}['\"][aw+]{1,2}['\"]|write_text|appendFile(?:Sync)?|writeFile(?:Sync)?)"
     r"[^\n]{0,100}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|MEMORY\.md|\.claude[/\\]+(?:memory|projects)[/\\])",
     floor=True)
rule("P1b", 5, 4, "alta", "any", "Comando que escreve na memória ou nas regras do agente",
     r"(?:echo|printf|cat)\b[^\n]{0,200}>>\s*[\"']?[^\n]{0,60}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|\.cursorrules)"
     r"|(?:Add-Content|Out-File\s+-Append)[^\n]{0,100}(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md)",
     floor=True)
rule("P2", 5, 3, "media", "text", "Instrução para gravar algo na memória ou nas regras do agente",
     r"(?:add|append|write|insert|save)\s+[^\n]{0,50}\b(?:to|into|in)\s+(?:your\s+|the\s+)?(?:file\s+)?(?:CLAUDE\.md|AGENTS\.md|MEMORY\.md|GEMINI\.md)"
     r"|(?:add|append|write|insert|save)\s+[^\n]{0,50}\b(?:to|into|in)\s+(?:your|the\s+agent'?s|persistent|long[-\s]term)\s+memor(?:y|ies)\b(?!-)"
     r"|(?:adicione|acrescente|escreva|insira|salve|grave|inclua)\s+[^\n]{0,50}\b(?:no|na|em|ao|à|nos|nas)\s+(?:seu\s+|o\s+|a\s+)?(?:arquivo\s+)?(?:CLAUDE\.md|AGENTS\.md|MEMORY\.md|GEMINI\.md)"
     r"|(?:adicione|acrescente|escreva|insira|salve|grave|inclua)\s+[^\n]{0,50}\b(?:na|em)\s+(?:sua\s+mem[oó]ria|mem[oó]ria\s+(?:persistente|do\s+agente|de\s+longo\s+prazo))"
     r"|(?:agrega|a[nñ]ade|escribe|guarda)\s+[^\n]{0,50}\b(?:en|al)\s+(?:tu\s+|la\s+|el\s+)?(?:archivo\s+)?(?:CLAUDE\.md|AGENTS\.md|MEMORY\.md|tu\s+memoria|memoria\s+persistente)")
rule("P3", 5, 3, "media", "any", "Mecanismo de persistência no sistema",
     r"\bcrontab\s+(?:-[el]|[^\n]{0,40}\|)|\bschtasks(?:\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTask"
     r"|LaunchAgents|LaunchDaemons|systemctl\s+(?:--user\s+)?enable|CurrentVersion\\+Run(?:Once)?\b"
     r"|Start\s+Menu\\+Programs\\+Startup|(?:>>|Add-Content|Out-File\s+-Append)[^\n]{0,60}(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\$PROFILE|_profile\.ps1)"
     r"|authorized_keys")
rule("P4", 5, 3, "media", "code", "Altera os próprios arquivos da skill",
     r"open\s*\([^)\n]{0,200}(?:SKILL\.md|__file__)[^)\n]{0,200}['\"][aw+]{1,2}['\"]|(?:SKILL\.md|__file__)[^\n]{0,30}\.write_text\s*\("
     r"|(?:Set-Content|Out-File|Add-Content)[^\n]{0,60}SKILL\.md")

# 6. Permissoes, hooks e MCP
rule("H3", 6, 3, "alta", "any", "Desliga confirmações ou permissões do agente",
     r"dangerously[-_]?skip[-_]?permissions|bypassPermissions|--yolo\b|\byolo\s+mode"
     r"|auto[-_\s]?approve\s+(?:all|every|any)|(?:approve|accept|allow)\s+(?:all|every|any)\s+(?:tool|command|permission)s?\s+automatically"
     r"|without\s+asking\s+(?:for\s+)?(?:permission|confirmation|approval)|sem\s+pedir\s+(?:permiss[aã]o|confirma[cç][aã]o|aprova[cç][aã]o)"
     r"|aprove\s+automaticamente|sin\s+pedir\s+(?:permiso|confirmaci[oó]n)|apru[eé]ba(?:lo)?\s+autom[aá]ticamente")
rule("H4", 6, 3, "alta", "any", "Escreve nas configurações do Claude Code",
     r"(?:>>?|Set-Content|Add-Content|Out-File|write_text|writeFile|open\s*\([^)\n]{0,300}['\"][aw+])[^\n]{0,100}\.claude[/\\]+settings(?:\.local)?\.json")

# 7. Cadeia de suprimentos
rule("S1", 7, 1, "baixa", "any", "Instala pacotes",
     r"\bpip3?\s+install\b|\bnpm\s+(?:i|install)\b|\bnpx\s+(?:-y|--yes)\b|\byarn\s+add\b|\bpnpm\s+(?:add|dlx)\b|\buvx\s"
     r"|\bgo\s+install\b|\bgem\s+install\b|Install-Module\b|\bchoco\s+install\b|\bwinget\s+install\b|\bbrew\s+install\b")
rule("S2", 7, 2, "media", "any", "Instala pacote de URL, git ou índice alternativo",
     r"pip3?\s+install\s+[^\n]{0,40}(?:https?://|git\+)|npm\s+(?:i|install)\s+[^\n]{0,40}(?:https?://|github:|git\+)"
     r"|--extra-index-url|--index-url\s+(?!https://pypi\.org)|--trusted-host")
rule("S3", 7, 1, "baixa", "any", "Executa pacote sempre na versão mais recente (@latest)",
     r"(?:npx|uvx|pnpm\s+dlx|bunx)\s+(?:-y\s+)?[@\w/.-]+@latest")
rule("S4", 7, 2, "media", "code", "setup.py com comando customizado de instalação",
     r"cmdclass\s*=")

# 8. Ocultacao (regras; o resto e analise propria)
rule("O2", 8, 2, "media", "any", "Sequência longa de bytes em hexadecimal",
     r"(?:\\x[0-9a-fA-F]{2}){16,}")
rule("O3", 8, 2, "media", "any", "Texto montado caractere por caractere",
     r"(?:chr\s*\(\s*\d+\s*\)\s*\+\s*){4,}|String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){8,}|(?:\[char\]\s*\d+\s*[+,]\s*){4,}")

STOPWORDS = {
    "en": set("the and of to is you that with for this are be it your when use if or from will should can not "
              "any all must do does into only".split()),
    "pt": set("o os do da dos das não você seu sua no na ao pelo pela mais isso uma também são quando deve "
              "então está esse essa nas nos aos às".split()),
    "es": set("el los las del usted tu más esto también cuando debe pero está ese esa al sus muy nos".split()),
}
LANG_NAMES = {"en": "inglês", "pt": "português", "es": "espanhol"}

OVERBROAD = re.compile(
    r"\b(?:always|every\s+(?:task|request|message|prompt)|any\s+(?:task|request)|all\s+(?:tasks|requests)"
    r"|sempre|qualquer\s+(?:tarefa|pedido|pergunta|mensagem)|todas?\s+as\s+(?:tarefas|mensagens)"
    r"|siempre|cualquier\s+(?:tarea|petici[oó]n))\b", re.IGNORECASE)

TOP_PACKAGES = {"requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3", "pyyaml", "click",
                "pytest", "scipy", "pillow", "cryptography", "httpx", "aiohttp", "beautifulsoup4",
                "selenium", "openai", "anthropic", "lodash", "express", "react", "axios", "chalk",
                "commander", "dotenv", "typescript", "webpack", "eslint", "moment", "colors", "jquery"}

ZW_RE = re.compile("[​‌‍⁠͏᠎⁡-⁤]")
BIDI_RE = re.compile("[‪-‮⁦-⁩]")
TAG_RE = re.compile("[\U000E0000-\U000E007F]+")
# Letras cirílicas que imitam latinas (а е о р с у х і ѕ ј ԁ һ) dentro de palavra latina.
CYR_LOOKALIKE = "аеорсухіѕјԁһАЕОРСХІ"
MIXED_WORD_RE = re.compile(r"\b\w*(?:[A-Za-z][" + CYR_LOOKALIKE + r"]|[" + CYR_LOOKALIKE + r"][A-Za-z])\w*\b")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{48,}={0,2})(?![A-Za-z0-9+/=_-])")
HEXBLOB_RE = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){60,})(?![0-9a-fA-F])")
URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})")
MAX_DECODE_DEPTH = 2


# --------------------------------------------------------------------------- #
# utilitarios
# --------------------------------------------------------------------------- #
class Lines:
    def __init__(self, text: str):
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(self, idx: int) -> int:
        return bisect.bisect_right(self.starts, idx)

    def line_text(self, n: int) -> str:
        if n < 1 or n > len(self.starts):
            return ""
        s = self.starts[n - 1]
        e = self.text.find("\n", s)
        return self.text[s: e if e != -1 else len(self.text)]


def clip(s: str, width: int = EVIDENCE_WIDTH) -> str:
    s = " ".join(s.split())
    return s if len(s) <= width else s[: width - 1] + "…"


def kind_of(path: Path) -> str:
    name, ext = path.name.lower(), path.suffix.lower()
    if name == "skill.md":
        return "manifest"
    if ext in CODE_KINDS:
        return CODE_KINDS[ext]
    if ext in MEDIA_EXTS:
        return "media"
    if ext in ARCHIVE_EXTS:
        return "archive"
    if ext in BINARY_EXEC_EXTS:
        return "binexec"
    if ext in (".md", ".markdown", ".mdx", ".txt", ".rst"):
        return "markdown"
    return "text"


def scope_ok(scope: str, kind: str) -> bool:
    if kind == "decoded" or scope == "any":
        return True
    if scope == "text":
        return kind in TEXT_KIND_SET
    if scope == "code":
        return kind in CODE_KIND_SET
    if scope == "nonpy":
        return kind in CODE_KIND_SET and kind != "python"
    return False


def fence_lines(text: str) -> set[int]:
    """Linhas dentro de blocos de código FECHADOS. Bloco sem fechamento não conta."""
    out: set[int] = set()
    start = None
    for i, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith(("```", "~~~")):
            if start is None:
                start = i
            else:
                out.update(range(start, i + 1))
                start = None
    return out


def looks_quoted(line: str, col: int) -> bool:
    before = line[:col]
    if before.count('"') % 2 == 1 or before.count("`") % 2 == 1:
        return True
    if before.count("“") > before.count("”"):
        return True
    return line.lstrip().startswith("|")


def parse_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    fm: dict[str, str] = {}
    key = None
    for raw in text[3:end].splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", raw)
        if m:
            key = m.group(1)
            val = m.group(2).strip()
            fm[key] = "" if val in (">", "|", ">-", "|-") else val.strip("'\"")
        elif key and raw.strip():
            fm[key] = (fm.get(key, "") + " " + raw.strip()).strip()
    return fm


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# --------------------------------------------------------------------------- #
# analisadores
# --------------------------------------------------------------------------- #
def run_rules(text, kind, label, lines, fences, findings):
    for rid, cat, grade, conf, scope, title, rx, floor in RULES:
        if not scope_ok(scope, kind):
            continue
        hits = 0
        seen_lines: set[int] = set()
        for m in rx.finditer(text):
            ln = lines.line_of(m.start())
            if ln in seen_lines:
                continue
            seen_lines.add(ln)
            lt = lines.line_text(ln)
            g, fl, t = grade, floor, title
            if kind in TEXT_KIND_SET and rid in TEXT_GRADE:
                g = TEXT_GRADE[rid]
            if floor and kind in TEXT_KIND_SET:
                col = m.start() - lines.starts[ln - 1]
                if ln in fences or looks_quoted(lt, col):
                    g, fl, t = 3, False, title + " (aparece como exemplo ou citação)"
            findings.append(Finding(cat, g, conf, rid, t, label, ln, clip(lt)))
            hits += 1
            if hits >= MAX_HITS_PER_RULE_PER_FILE:
                break


def call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


DYNAMIC_SOURCES = ("requests.", "urllib", "urlopen", "httpx", "socket", "b64decode", "fromhex",
                   "decompress", "codecs.decode", "marshal.loads")


def scan_python(text, label, lines, findings, coverage, partial=False):
    if partial:
        coverage.append({"grade": 2, "file": label,
                         "detail": "Análise estrutural do Python não feita (arquivo lido só em parte)"})
        return
    try:
        tree = ast.parse(text)
    except Exception as e:  # noqa: BLE001 - qualquer falha vira item de cobertura
        coverage.append({"grade": 2, "file": label,
                         "detail": f"Análise estrutural do Python falhou ({type(e).__name__}); só as regras de texto rodaram"})
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node)
        ln = getattr(node, "lineno", 1)
        ev = clip(lines.line_text(ln))

        def add(rid, grade, conf, title, floor=False):
            findings.append(Finding(2, grade, conf, rid, title, label, ln, ev, floor))

        if name in ("exec", "eval", "builtins.exec", "builtins.eval"):
            inner = [call_name(c) for c in ast.walk(node) if isinstance(c, ast.Call) and c is not node]
            src = next((n for n in inner if any(h in n for h in DYNAMIC_SOURCES)), None)
            if src:
                add("A1", 4, "alta", f"{name}() executa conteúdo vindo de {src}()", floor=True)
            else:
                add("A2", 2, "media", f"Chamada {name}()")
        elif name == "compile":
            add("A3", 1, "baixa", "Chamada compile()")
        elif name in ("__import__", "importlib.import_module") and node.args and not isinstance(node.args[0], ast.Constant):
            add("A4", 2, "media", "Importa módulo com nome dinâmico")
        elif name.startswith("subprocess."):
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                        for k in node.keywords)
            if shell:
                add("A5", 2, "media", "subprocess com shell=True")
            else:
                add("A5", 1, "baixa", "Executa processo externo (subprocess)")
        elif name in ("os.system", "os.popen") or (name.startswith("os.") and name.split(".")[-1].startswith(("exec", "spawn"))):
            add("A6", 2, "media", f"{name}() executa comando")
        elif name == "getattr" and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            add("A7", 1, "baixa", "getattr() com nome dinâmico (pode esconder uma chamada)")
        elif name in ("pickle.loads", "pickle.load", "marshal.loads", "dill.loads"):
            add("A8", 2, "media", f"{name}() pode executar código ao desserializar")


def scan_unicode(text, kind, label, lines, findings, decode_cb):
    count, first = 0, None
    for m in ZW_RE.finditer(text):
        prev = text[m.start() - 1] if m.start() > 0 else ""
        nxt = text[m.end()] if m.end() < len(text) else ""
        if prev.isalpha() or nxt.isalpha():
            count += 1
            first = first if first is not None else m.start()
    if count:
        ln = lines.line_of(first)
        findings.append(Finding(8, 3, "alta", "U1", f"{count} caractere(s) invisível(is) entre letras", label, ln,
                                clip(lines.line_text(ln).encode("unicode_escape").decode("ascii"))))
    m = BIDI_RE.search(text)
    if m:
        ln = lines.line_of(m.start())
        findings.append(Finding(8, 3, "alta", "U2", "Caractere que inverte a direção do texto (texto disfarçado)",
                                label, ln, f"U+{ord(m.group(0)):04X}"))
    for m in TAG_RE.finditer(text):
        hidden = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0xE0020 <= ord(c) <= 0xE007E)
        ln = lines.line_of(m.start())
        findings.append(Finding(8, 4, "alta", "U3", "Texto invisível escondido com caracteres Unicode TAG",
                                label, ln, clip(hidden) or "(vazio)", floor=True))
        if hidden.strip():
            decode_cb(hidden, f"{label} [texto invisível decodificado]", ln)
    seen = 0
    for m in MIXED_WORD_RE.finditer(text):
        ln = lines.line_of(m.start())
        findings.append(Finding(8, 3, "alta", "U4", "Palavra com letras de alfabetos misturados (homóglifo)",
                                label, ln, clip(m.group(0))))
        seen += 1
        if seen >= 3:
            break


def scan_encoded(text, label, lines, findings, decode_cb):
    found = 0
    for m in B64_RE.finditer(text):
        if found >= 40:
            break
        ctx = text[max(0, m.start() - 40): m.start()].lower()
        if any(k in ctx for k in ("data:image", "data:font", "data:application/font", "integrity", "sha256-", "sha512-")):
            continue
        blob = m.group(1)
        try:
            if "-" in blob or "_" in blob:
                raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
            else:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in dec) / max(1, len(dec))
        if printable < 0.9 or len(dec.strip()) < 20:
            continue
        ln = lines.line_of(m.start())
        findings.append(Finding(8, 2, "media", "O1", "Texto escondido em base64", label, ln, clip(dec)))
        decode_cb(dec, f"{label} [base64 decodificado]", ln)
        found += 1
    for i, m in enumerate(HEXBLOB_RE.finditer(text)):
        if i >= 40:
            break
        try:
            dec = bytes.fromhex(m.group(1)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in dec) / max(1, len(dec))
        if printable < 0.9:
            continue
        ln = lines.line_of(m.start())
        findings.append(Finding(8, 2, "media", "O4", "Texto escondido em hexadecimal", label, ln, clip(dec)))
        decode_cb(dec, f"{label} [hex decodificado]", ln)


def detect_lang(para: str) -> tuple[str | None, int]:
    letters = [ch for ch in para if ch.isalpha()]
    if not letters:
        return None, 0
    nonlatin = [ch for ch in letters if ord(ch) > 0x24F and not 0x1E00 <= ord(ch) <= 0x1EFF]
    words = re.findall(r"[^\W\d_]+", para.lower())
    if len(nonlatin) >= 10 and len(nonlatin) / len(letters) > 0.3:
        return "outro alfabeto", len(words)
    counts = {lang: sum(1 for w in words if w in sw) for lang, sw in STOPWORDS.items()}
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    best, second = ranked[0], ranked[1]
    if best[1] >= 3 and best[1] >= 2 * max(1, second[1]):
        return best[0], len(words)
    return None, len(words)


def html_comment_spans(text: str, limit: int = 2000) -> list[tuple[int, int]]:
    """Busca linear de comentários HTML fechados (evita regex quadrática em arquivos hostis)."""
    spans, i = [], 0
    while len(spans) < limit:
        a = text.find("<!--", i)
        if a == -1:
            break
        b = text.find("-->", a + 4)
        if b == -1:
            break
        spans.append((a, b + 3))
        i = b + 3
    return spans


def scan_language(text, label, lines, fences, findings, coverage):
    comments = html_comment_spans(text)
    paras, cur, start = [], [], None
    for i, line in enumerate(text.split("\n"), 1):
        if line.strip():
            if start is None:
                start = i
            cur.append(line)
        elif cur:
            paras.append((start, i - 1, "\n".join(cur)))
            cur, start = [], None
    if cur:
        paras.append((start, start + len(cur) - 1, "\n".join(cur)))

    detected = []
    weight: dict[str, int] = {}
    for s, e, p in paras:
        lang, nwords = detect_lang(p)
        detected.append((s, e, p, lang, nwords))
        if lang:
            weight[lang] = weight.get(lang, 0) + nwords
    if not weight:
        return
    majority = max(weight, key=weight.get)
    if majority not in RULE_LANGS:
        coverage.append({"grade": 2, "file": label,
                         "detail": "Documento escrito em idioma sem regras automáticas (outro alfabeto): depende da leitura do Claude"})
    for s, e, p, lang, nwords in detected:
        if not lang or lang == majority or nwords < 8:
            continue
        offset = lines.starts[s - 1]
        in_comment = any(a <= offset < b for a, b in comments)
        in_fence = s in fences
        where = " dentro de comentário HTML" if in_comment else (" dentro de bloco de código" if in_fence else "")
        name_from = LANG_NAMES.get(lang, lang)
        name_major = LANG_NAMES.get(majority, majority)
        grade = 3 if in_comment else 1
        findings.append(Finding(8, grade, "media", "L1",
                                f"Trecho em {name_from} num documento em {name_major}{where}",
                                label, s, clip(p), False, e))
        if lang not in RULE_LANGS:
            coverage.append({"grade": 2, "file": label,
                             "detail": f"Trecho em idioma sem regras automáticas (linhas {s}-{e})"})


def upgrade_language_findings(findings):
    """Troca de idioma no mesmo trecho de uma instrucao sensivel vira nota 3."""
    sensitive = [f for f in findings if f.cat in (1, 2, 3, 4, 5, 6) and f.grade >= 2]
    for f in findings:
        if f.rule != "L1" or f.grade >= 3:
            continue
        end = f.end_line or f.line
        for s in sensitive:
            if s.file == f.file and f.line <= s.line <= end:
                f.grade = 3
                f.title += " com instrução sensível"
                break


def scan_frontmatter(text, label, lines, findings) -> dict:
    fm = parse_frontmatter(text)
    desc = fm.get("description", "")
    if not desc:
        findings.append(Finding(1, 1, "baixa", "F1", "SKILL.md sem descrição", label, 1, ""))
    elif OVERBROAD.search(desc):
        findings.append(Finding(1, 1, "baixa", "F2", "Descrição ampla demais (tenta ser ativada sempre)", label, 1,
                                clip(OVERBROAD.search(desc).group(0))))
    tools = fm.get("allowed-tools", "") or fm.get("allowed_tools", "")
    if tools:
        if re.search(r"(?:^|[\s,\[\"'])(?:\*|Bash)(?:$|[\s,\]\"'])|Bash\(\s*\*?\s*\)", tools):
            findings.append(Finding(6, 2, "alta", "F3", "allowed-tools libera Bash sem restrição", label, 1, clip(tools)))
        else:
            findings.append(Finding(6, 1, "baixa", "F4", "allowed-tools libera ferramentas sem pedir permissão",
                                    label, 1, clip(tools)))
    if "hooks" in fm:
        findings.append(Finding(6, 2, "media", "F5", "SKILL.md declara hooks", label, 1, clip(fm.get("hooks", ""))))
    return fm


def _line_for(text: str, needle: str, lines: Lines) -> int:
    idx = text.find(needle)
    return lines.line_of(idx) if idx >= 0 else 1


def scan_json_config(path: Path, text, label, lines, findings):
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return
    if not isinstance(obj, dict):
        return
    servers = obj.get("mcpServers")
    if servers is None and path.name == ".mcp.json":
        servers = {k: v for k, v in obj.items() if isinstance(v, dict)}
    for name, cfg in (servers or {}).items():
        if not isinstance(cfg, dict):
            continue
        ln = _line_for(text, f'"{name}"', lines)
        cmd, args, url = cfg.get("command"), cfg.get("args") or [], cfg.get("url")
        if cmd:
            full = " ".join([str(cmd)] + [str(a) for a in args])
            findings.append(Finding(6, 2, "media", "M1", f"Servidor MCP '{name}' executa um comando local ao iniciar",
                                    label, ln, clip(full)))
            if re.search(r"\b(?:npx|uvx|bunx|pnpm|pipx)\b", str(cmd)) and (
                    any("@latest" in str(a) for a in args)
                    or not any(re.search(r"@\d|==\d", str(a)) for a in args)):
                findings.append(Finding(7, 2, "media", "M2", f"Servidor MCP '{name}' baixa pacote sem versão fixada",
                                        label, ln, clip(full)))
        elif url:
            host = re.sub(r"^https?://", "", str(url)).split("/")[0]
            findings.append(Finding(6, 1, "baixa", "M3", f"Servidor MCP '{name}' remoto ({host})", label, ln, clip(str(url))))

    cmds: list[str] = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "command" and isinstance(v, str):
                    cmds.append(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for i in o:
                walk(i)

    if "hooks" in obj:
        walk(obj["hooks"])
        for c in cmds[:10]:
            findings.append(Finding(6, 2, "media", "H1", "Hook executa comando automaticamente",
                                    label, _line_for(text, c[:30], lines), clip(c)))
    perms = obj.get("permissions")
    if isinstance(perms, dict):
        allow = perms.get("allow") or []
        broad = [a for a in allow if isinstance(a, str) and (a.strip() in ("*", "Bash", "Bash(*)", "Bash(*:*)"))]
        if broad:
            findings.append(Finding(6, 3, "alta", "H2", "Configuração libera permissões amplas sem perguntar",
                                    label, _line_for(text, '"allow"', lines), clip(", ".join(broad))))

    if path.name == "package.json":
        scripts = obj.get("scripts") or {}
        if isinstance(scripts, dict):
            for k in ("preinstall", "install", "postinstall", "prepare", "preuninstall"):
                if k in scripts:
                    findings.append(Finding(7, 3, "alta", "D1", f"package.json roda o script '{k}' na instalação",
                                            label, _line_for(text, f'"{k}"', lines), clip(str(scripts[k]))))
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(obj.get(key), dict):
                deps.update(obj[key])
        check_packages(list(deps.items()), label, text, lines, findings)


def check_packages(pkgs, label, text, lines, findings):
    for pkg, ver in pkgs:
        low = str(pkg).lower()
        ln = _line_for(text, str(pkg), lines)
        if low not in TOP_PACKAGES and len(low) >= 4:
            for top in TOP_PACKAGES:
                if levenshtein(low, top) == 1:
                    findings.append(Finding(7, 3, "media", "D2", f"Nome parecido com o pacote popular '{top}': '{pkg}'",
                                            label, ln, clip(f"{pkg} {ver}")))
                    break
        v = str(ver)
        if v.startswith(("http", "git", "github:", "file:")):
            findings.append(Finding(7, 2, "media", "D3", f"Dependência vinda de URL ou git: {pkg}", label, ln, clip(v)))


def scan_requirements(text, label, lines, findings):
    pkgs, unpinned = [], 0
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith(("#", "-r", "-c")):
            continue
        if s.startswith(("http", "git+")):
            findings.append(Finding(7, 2, "media", "D3", "Dependência vinda de URL ou git", label, i, clip(s)))
            continue
        name = re.split(r"[<>=!~\[ ;@]", s, 1)[0].strip()
        pkgs.append((name, s))
        if "==" not in s:
            unpinned += 1
    check_packages(pkgs, label, text, lines, findings)
    if unpinned:
        findings.append(Finding(7, 1, "baixa", "D4", f"{unpinned} dependência(s) sem versão fixa", label, 1, ""))


# --------------------------------------------------------------------------- #
# leitura de arquivos e alvo
# --------------------------------------------------------------------------- #
def read_file(p: Path, size: int) -> tuple[bytes, bool, bytes]:
    """Retorna (dados para analisar, leitura_parcial, amostra para enchimento)."""
    with open(p, "rb") as f:
        if size <= FULL_READ_LIMIT:
            data = f.read()
            return data, False, data
        head = f.read(HEAD_TAIL_BYTES)
        f.seek(max(size // 2 - HEAD_TAIL_BYTES // 2, 0))
        middle = f.read(HEAD_TAIL_BYTES)
        f.seek(max(size - HEAD_TAIL_BYTES, 0))
        tail = f.read()
        return head + b"\n" + tail, True, head + middle + tail


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_decode_cb(findings, coverage, depth: int = 1):
    """Analisa texto decodificado (base64, hex, Unicode TAG) com todas as regras, recursivamente."""

    def decode_cb(decoded: str, label: str, ln: int):
        dl = Lines(decoded)
        sub: list[Finding] = []
        run_rules(decoded, "decoded", label, dl, set(), sub)
        if depth < MAX_DECODE_DEPTH:
            scan_encoded(decoded, label, dl, sub, make_decode_cb(sub, coverage, depth + 1))
        else:
            if B64_RE.search(decoded) or HEXBLOB_RE.search(decoded):
                coverage.append({"grade": 2, "file": label,
                                 "detail": f"Conteúdo codificado em mais de {MAX_DECODE_DEPTH} camadas não foi aberto"})
        for f in sub:
            f.line = ln
            if "escondido em conteúdo codificado" not in f.title:
                f.title += " (escondido em conteúdo codificado)"
                if f.grade >= 2:
                    f.grade = min(4, f.grade + 1)
        findings.extend(sub)

    return decode_cb


def analyze_text(path: Path, rel: str, kind: str, text: str, findings, coverage, domains, is_root_manifest,
                 partial=False):
    lines = Lines(text)
    fences = fence_lines(text) if kind in ("manifest", "markdown") else set()
    decode_cb = make_decode_cb(findings, coverage)

    run_rules(text, kind, rel, lines, fences, findings)
    if kind == "python":
        scan_python(text, rel, lines, findings, coverage, partial)
    scan_unicode(text, kind, rel, lines, findings, decode_cb)
    scan_encoded(text, rel, lines, findings, decode_cb)
    for host in URL_HOST_RE.findall(text):
        domains.add(host.lower())
    if kind in ("manifest", "markdown"):
        scan_language(text, rel, lines, fences, findings, coverage)
    fm = {}
    if kind == "manifest":
        fm = scan_frontmatter(text, rel, lines, findings)
    name = path.name.lower()
    if name.endswith(".json"):
        scan_json_config(path, text, rel, lines, findings)
    if re.match(r"requirements.*\.(?:txt|in)$", name):
        scan_requirements(text, rel, lines, findings)
    return fm if is_root_manifest else {}


def scan_target(target: dict) -> dict:
    root = Path(target["path"])
    findings: list[Finding] = []
    coverage: list[dict] = []
    domains: set[str] = set()
    tree_hash = hashlib.sha256()
    files_total = files_read = bytes_total = 0
    fm: dict = {}
    root_res = root.resolve()
    limit_hit = False

    def on_walk_error(err):
        coverage.append({"grade": 2, "file": str(getattr(err, "filename", "?")),
                         "detail": f"Pasta não pôde ser lida ({type(err).__name__})"})

    is_junction = getattr(os.path, "isjunction", lambda _p: False)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_walk_error):
        dpath = Path(dirpath)
        if dpath.resolve() == SELF_DIR:
            coverage.append({"grade": 1, "file": str(dpath),
                             "detail": "Pasta do próprio auditor ignorada"})
            dirnames[:] = []
            continue
        dirnames.sort()
        for d in list(dirnames):
            dp = dpath / d
            if dp.is_symlink() or is_junction(dp):
                dirnames.remove(d)
                handle_symlink(dp, root, root_res, findings, coverage)
            elif d == ".git":
                dirnames.remove(d)
                coverage.append({"grade": 1, "file": (dp.relative_to(root)).as_posix(),
                                 "detail": "Pasta .git não analisada (histórico do repositório)"})
        for fn in sorted(filenames):
            p = dpath / fn
            rel = p.relative_to(root).as_posix()
            files_total += 1
            if files_total > MAX_FILES:
                if not limit_hit:
                    coverage.append({"grade": 2, "file": "(vários)",
                                     "detail": f"Mais de {MAX_FILES} arquivos: o restante não foi lido"})
                    limit_hit = True
                continue
            if p.is_symlink():
                handle_symlink(p, root, root_res, findings, coverage)
                continue
            kind = kind_of(p)
            try:
                size = p.stat().st_size
            except OSError:
                coverage.append({"grade": 2, "file": rel, "detail": "Não foi possível ler o arquivo"})
                continue
            bytes_total += size
            try:
                tree_hash.update(rel.encode() + b"\0" + file_sha256(p).encode())
            except OSError:
                pass
            if kind == "media":
                coverage.append({"grade": 1, "file": rel, "detail": "Imagem ou mídia não analisada"})
                continue
            if kind == "archive":
                coverage.append({"grade": 2, "file": rel, "detail": "Documento ou arquivo compactado não analisado"})
                continue
            if kind == "binexec":
                findings.append(Finding(8, 3, "alta", "B1", "Executável binário dentro da skill", rel, 0, fn))
                coverage.append({"grade": 2, "file": rel, "detail": "Binário não analisado"})
                continue
            try:
                data, partial, sample = read_file(p, size)
            except OSError:
                coverage.append({"grade": 2, "file": rel, "detail": "Não foi possível ler o arquivo"})
                continue
            encoding = "utf-8-sig"
            if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
                encoding = "utf-16"
            elif b"\x00" in data[:8192]:
                coverage.append({"grade": 2, "file": rel, "detail": "Arquivo binário sem tipo conhecido, não analisado"})
                continue
            if partial:
                coverage.append({"grade": 2, "file": rel,
                                 "detail": f"Arquivo grande ({size / 1_000_000:.1f} MB): lidos só o início e o fim; "
                                           "números de linha do fim são aproximados"})
            if size >= PADDING_MIN_SIZE and sample:
                ratio = len(zlib.compress(sample, 6)) / len(sample)
                if ratio < PADDING_RATIO:
                    findings.append(Finding(8, 3, "alta", "O5",
                                            f"Arquivo de {size / 1_000_000:.1f} MB cheio de conteúdo repetitivo (enchimento)",
                                            rel, 0, f"taxa de compressão {ratio:.3f}"))
            text = data.decode(encoding, errors="replace")
            is_root_manifest = kind == "manifest" and p.parent.resolve() == root_res
            got = analyze_text(p, rel, kind, text, findings, coverage, domains, is_root_manifest, partial)
            if got:
                fm = got
            files_read += 1

    upgrade_language_findings(findings)
    return build_result(target, findings, coverage, domains, fm, files_total, files_read, bytes_total,
                        tree_hash.hexdigest())


def handle_symlink(p: Path, root: Path, root_res: Path, findings, coverage):
    rel = p.relative_to(root).as_posix()
    try:
        dest = p.resolve()
    except OSError:
        coverage.append({"grade": 2, "file": rel, "detail": "Link simbólico que não pôde ser resolvido"})
        return
    try:
        dest.relative_to(root_res)
        inside = True
    except ValueError:
        inside = False
    if not inside:
        findings.append(Finding(8, 3, "alta", "B2", "Link simbólico aponta para fora da skill", rel, 0, str(dest)))
        coverage.append({"grade": 2, "file": rel, "detail": "Destino do link simbólico não analisado"})


# --------------------------------------------------------------------------- #
# notas
# --------------------------------------------------------------------------- #
def has(findings, *rules, min_grade=1):
    return any(f.rule in rules and f.grade >= min_grade for f in findings)


def build_combos(findings) -> list[dict]:
    combos = []
    cat_max = {c: max([f.grade for f in findings if f.cat == c] or [0]) for c in CATEGORIES}
    cred_strong = any(f.cat == 3 and f.grade >= 3 for f in findings)
    secret_env = has(findings, "K5", "K6")
    net_out = has(findings, "N1", "N4")          # envio de fato, não só citar um endpoint
    download = has(findings, "N5", "C1", "C2")
    exec_ = cat_max[2] >= 2
    hidden = has(findings, "U1", "U2", "U3", "U4", "O5", min_grade=3)
    obfusc = has(findings, "O1", "O2", "O3", "O4", "C3")
    sensitive_fs = [f for f in findings if f.cat in (2, 3, 4, 5, 6) and f.grade >= 2]
    sensitive = bool(sensitive_fs)
    conceal_files = {f.file for f in findings if f.rule == "I3"}

    if cred_strong and net_out:
        combos.append({"id": "X1", "grade": 4, "floor": True,
                       "title": "Lê credenciais e envia dados pela rede"})
    elif secret_env and net_out:
        combos.append({"id": "X2", "grade": 3, "floor": False,
                       "title": "Usa segredo e envia dados para fora: confirmar se o destino é o serviço esperado"})
    if conceal_files and sensitive:
        same_file = any(f.file in conceal_files for f in sensitive_fs)
        combos.append({"id": "X3", "grade": 4 if same_file else 3, "floor": same_file,
                       "title": "Manda esconder do usuário e faz ação sensível"
                                + ("" if same_file else " (em arquivos diferentes)")})
    if hidden and sensitive:
        combos.append({"id": "X4", "grade": 4, "floor": True,
                       "title": "Conteúdo invisível ou disfarçado junto com ação sensível"})
    if has(findings, "I7") and exec_:
        combos.append({"id": "X7", "grade": 3, "floor": False,
                       "title": "Tira a comunicação da sessão e executa código: o usuário pode não ver o que acontece"})
    if download and exec_:
        combos.append({"id": "X5", "grade": 3, "floor": False,
                       "title": "Baixa conteúdo da internet e executa código"})
    if obfusc and (exec_ or net_out):
        combos.append({"id": "X6", "grade": 3, "floor": False,
                       "title": "Conteúdo codificado junto com execução ou envio pela rede"})
    return combos


def build_result(target, findings, coverage, domains, fm, files_total, files_read, bytes_total, tree_hash):
    combos = build_combos(findings)
    cov_grade = max([c["grade"] for c in coverage] or [0])
    partial = cov_grade >= 2

    categories = {}
    for c, cname in CATEGORIES.items():
        if c == 9:
            categories[str(c)] = {"name": cname, "grade": None, "findings": [], "omitted": 0,
                                  "note": "Preenchida pelo Claude na etapa 2"}
            continue
        if c == 10:
            categories[str(c)] = {"name": cname, "grade": 2 if partial else (1 if coverage else 0),
                                  "findings": [], "omitted": 0, "items": coverage[:30],
                                  "omitted_items": max(0, len(coverage) - 30)}
            continue
        fs = sorted((f for f in findings if f.cat == c),
                    key=lambda f: (-f.grade, -CONF_ORDER.get(f.conf, 0), f.file, f.line))
        categories[str(c)] = {"name": cname, "grade": max([f.grade for f in fs] or [0]),
                              "findings": [asdict(f) for f in fs[:MAX_FINDINGS_PER_CATEGORY]],
                              "omitted": max(0, len(fs) - MAX_FINDINGS_PER_CATEGORY)}

    grades = [v["grade"] for k, v in categories.items() if v["grade"] is not None]
    scanner_grade = max(grades + [c["grade"] for c in combos] + [0])
    floor_grade = max([f.grade for f in findings if f.floor] + [c["grade"] for c in combos if c["floor"]]
                      + ([2] if partial else []) + [0])
    return {
        "name": target["name"],
        "kind": target["kind"],
        "location": target["location"],
        "path": target["path"],
        "description": fm.get("description", ""),
        "declared_name": fm.get("name", ""),
        "files_total": files_total,
        "files_read": files_read,
        "bytes_total": bytes_total,
        "tree_sha256": tree_hash,
        "scanner_grade": scanner_grade,
        "floor_grade": floor_grade,
        "coverage": {"status": "Parcial" if partial else "Completa"},
        "combos": combos,
        "categories": categories,
        "domains": sorted(domains)[:40],
    }


# --------------------------------------------------------------------------- #
# descoberta
# --------------------------------------------------------------------------- #
def skill_name_of(d: Path) -> str:
    try:
        text = (d / "SKILL.md").read_text(encoding="utf-8", errors="replace")[:4000]
        return parse_frontmatter(text).get("name") or d.name
    except OSError:
        return d.name


def discover(cwd: Path) -> tuple[list[dict], list[dict]]:
    home = Path.home()
    targets, skipped, seen = [], [], set()

    def add(path: Path, name: str, kind: str, location: str):
        try:
            res = path.resolve()
        except OSError:
            res = path
        if res == SELF_DIR:
            skipped.append({"name": name, "path": str(path), "reason": "o próprio auditor"})
            return
        if res in seen:
            return
        seen.add(res)
        targets.append({"name": name, "kind": kind, "location": location, "path": str(path)})

    def safe_iter(d: Path) -> list[Path]:
        try:
            return sorted(d.iterdir())
        except OSError as e:
            skipped.append({"name": d.name, "path": str(d), "reason": f"pasta ilegível ({type(e).__name__})"})
            return []

    def add_skills(base: Path, location: str):
        if not base.is_dir():
            return
        for child in safe_iter(base):
            if not child.is_dir():
                continue
            if (child / "SKILL.md").exists():
                add(child, skill_name_of(child), "skill", location)
                continue
            found = False
            for g in safe_iter(child):
                if g.is_dir() and (g / "SKILL.md").exists():
                    add(g, skill_name_of(g), "skill", location)
                    found = True
            if not found:
                skipped.append({"name": child.name, "path": str(child),
                                "reason": "pasta sem SKILL.md (não é uma skill)"})

    for base in (home / ".claude" / "skills", home / ".agents" / "skills", home / ".config" / "agents" / "skills"):
        add_skills(base, "global")
    if cwd.resolve() != home.resolve():
        for base in (cwd / ".claude" / "skills", cwd / ".agents" / "skills"):
            add_skills(base, "projeto")

    manifest = home / ".claude" / "plugins" / "installed_plugins.json"
    if not manifest.exists():
        skipped.append({"name": "plugins", "path": str(manifest),
                        "reason": "nenhum plugin instalado em disco (plugins do claude.ai podem não ficar no computador)"})
    else:
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
            skipped.append({"name": "installed_plugins.json", "path": str(manifest), "reason": "arquivo ilegível"})
        plugins = data.get("plugins", data) if isinstance(data, dict) else {}
        for pid, recs in (plugins or {}).items():
            if isinstance(recs, dict):
                recs = [recs]
            if not isinstance(recs, list):
                continue
            for rec in recs:
                ip = rec.get("installPath") if isinstance(rec, dict) else None
                if ip and Path(ip).is_dir():
                    add(Path(ip), pid, "plugin", "plugin")
                else:
                    skipped.append({"name": pid, "path": str(ip), "reason": "plugin não encontrado em disco"})
    return targets, skipped


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Etapa 1 do auditor de risco de skills (somente leitura).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="lista skills e plugins encontrados")
    g.add_argument("--scope", choices=["all"], help="varre todos os alvos encontrados")
    g.add_argument("--target", help="nome da skill/plugin ou caminho de uma pasta")
    ap.add_argument("--cwd", default=os.getcwd(), help="pasta do projeto (para skills de projeto)")
    args = ap.parse_args()

    cwd = Path(args.cwd)
    targets, skipped = discover(cwd)

    if args.list:
        print(json.dumps({"targets": targets, "skipped": skipped}, ensure_ascii=False, indent=1))
        return 0

    if args.target:
        wanted = args.target.strip().lower()
        chosen = [t for t in targets if t["name"].lower() == wanted or Path(t["path"]).name.lower() == wanted]
        if not chosen:
            p = Path(args.target).expanduser()
            if p.is_dir():
                if p.resolve() == SELF_DIR:
                    print(json.dumps({"error": "Esse caminho é o próprio auditor."}, ensure_ascii=False))
                    return 2
                name = skill_name_of(p) if (p / "SKILL.md").exists() else p.name
                chosen = [{"name": name, "kind": "skill" if (p / "SKILL.md").exists() else "pasta",
                           "location": "caminho informado", "path": str(p)}]
        if not chosen:
            print(json.dumps({"error": f"Nenhuma skill ou plugin encontrado com o nome ou caminho '{args.target}'.",
                              "available": [t["name"] for t in targets]}, ensure_ascii=False, indent=1))
            return 2
        targets, skipped = chosen, []

    results = [scan_target(t) for t in targets]
    out = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scope": "all" if args.scope else f"target:{args.target}",
        "cwd": str(cwd),
        "targets_scanned": len(results),
        "skipped": skipped,
        "results": results,
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
