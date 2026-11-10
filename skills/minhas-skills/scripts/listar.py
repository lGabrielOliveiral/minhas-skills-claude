"""Resumo das skills globais do usuário em Markdown (só biblioteca padrão, somente leitura).

Uso: python listar.py [--todas] [--max N]
  --todas  inclui também as skills sincronizadas do claude.ai (pasta synced)
  --max N  tamanho máximo da descrição curta (padrão 110 caracteres)
"""
import argparse
import json
import os
import pathlib
import re
import sys

HOME = pathlib.Path.home()
PASTAS = [HOME / '.claude' / 'skills', HOME / '.agents' / 'skills']
LOCKS = [HOME / '.agents' / '.skill-lock.json', HOME / '.claude' / '.skill-lock.json']
AUTOR_LOCAL = 'Você (criada localmente)'


def frontmatter(texto):
    """Lê o bloco YAML inicial de forma simples (chave: valor, blocos > e |, metadata aninhado)."""
    m = re.match(r'^---\s*\n(.*?)\n---', texto, re.S)
    if not m:
        return {}
    dados, chave, pai = {}, None, None
    for linha in m.group(1).splitlines():
        if not linha.strip():
            continue
        recuo = len(linha) - len(linha.lstrip())
        k = re.match(r'^\s*([\w-]+):\s*(.*)$', linha)
        if k and recuo == 0:
            chave, valor = k.group(1), k.group(2).strip()
            pai = chave if valor == '' else None
            dados[chave] = '' if valor in ('>', '|', '>-', '|-') else valor.strip('"\'')
        elif k and pai and recuo > 0:
            dados[f'{pai}.{k.group(1)}'] = k.group(2).strip().strip('"\'')
        elif chave:
            dados[chave] = (dados[chave] + ' ' + linha.strip()).strip()
    return dados


def curta(desc, limite):
    desc = re.sub(r'\s+', ' ', desc).strip()
    frase = re.split(r'(?<=[.!?])\s', desc, maxsplit=1)[0]
    if len(frase) > limite:
        frase = frase[:limite].rsplit(' ', 1)[0].rstrip(',;:-') + '…'
    return frase.replace('|', '\\|')


def carregar_locks():
    fontes = {}
    for lock in LOCKS:
        try:
            for nome, info in json.loads(lock.read_text(encoding='utf-8')).get('skills', {}).items():
                fontes[nome] = info.get('source') or info.get('sourceUrl', '')
        except (OSError, ValueError):
            pass
    return fontes


def autor(fm, texto, nome, fontes):
    declarado = fm.get('author') or fm.get('metadata.author')
    if nome in fontes:  # instalada por `npx skills add`: o dono do repositório é o autor
        return declarado or f'{fontes[nome].split("/")[0]} (`{fontes[nome]}`)', 'terceiro'
    if declarado:
        return declarado, 'propria'
    m = re.search(r'[Dd]erivada d[aoe] .*?reposit[óo]rio `([^`]+)`', texto)
    if m:
        return f'Você (adaptada de `{m.group(1)}`)', 'propria'
    return AUTOR_LOCAL, 'propria'


def coletar(todas):
    vistos, linhas = set(), []
    fontes = carregar_locks()
    for base in PASTAS:
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if d.name == 'synced':
                continue
            arq = d / 'SKILL.md'
            if not arq.is_file():
                continue
            real = os.path.realpath(d)
            texto = arq.read_text(encoding='utf-8', errors='replace')
            fm = frontmatter(texto)
            nome = fm.get('name') or d.name
            if real in vistos or nome in vistos:  # atalho ou cópia da mesma skill
                continue
            vistos.update((real, nome))
            quem, tipo = autor(fm, texto, nome, fontes)
            linhas.append({'nome': nome, 'autor': quem, 'tipo': tipo,
                           'desc': fm.get('description', ''), 'pasta': real})
    if todas:
        for man in (HOME / '.claude' / 'skills' / 'synced').glob('*/manifest.json'):
            try:
                for s in json.loads(man.read_text(encoding='utf-8')).get('skills', []):
                    linhas.append({'nome': s.get('name', '?'), 'autor': 'Anthropic (claude.ai)',
                                   'tipo': 'claude', 'desc': s.get('description', ''), 'pasta': str(man.parent)})
            except (OSError, ValueError):
                pass
    return linhas


def tabela(itens, limite):
    out = ['| Skill | Autor | Descrição curta |', '|---|---|---|']
    for i in sorted(itens, key=lambda x: x['nome'].lower()):
        out.append(f"| **{i['nome']}** | {i['autor']} | {curta(i['desc'], limite)} |")
    return '\n'.join(out)


def main():
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding='utf-8')
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument('--todas', action='store_true')
    ap.add_argument('--max', type=int, default=110)
    a = ap.parse_args()

    itens = coletar(a.todas)
    grupos = [('propria', '🛠️ Criadas por você'), ('terceiro', '📦 Instaladas de terceiros'),
              ('claude', '☁️ Sincronizadas do claude.ai')]
    print(f'# 🧰 Suas skills globais · {len(itens)} no total\n')
    for chave, titulo in grupos:
        g = [i for i in itens if i['tipo'] == chave]
        if g:
            print(f'## {titulo} ({len(g)})\n')
            print(tabela(g, a.max) + '\n')
    print(f'📁 Pasta: `{PASTAS[1]}` (a pasta `{PASTAS[0]}` só tem atalhos para ela)')


if __name__ == '__main__':
    main()
