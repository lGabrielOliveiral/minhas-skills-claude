"""Conversão e conferência de documentos Office com LibreOffice headless (só biblioteca padrão).

Uso: python office.py <comando> <arquivo|pasta> [opções]
Comandos: verificar, pdf, texto, capa, csv, recalcular, converter, lote
"""
import argparse
import glob
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from xml.etree import ElementTree as ET

W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
A = '{http://schemas.openxmlformats.org/drawingml/2006/main}'

CANDIDATOS = [
    r'C:\Program Files\LibreOffice\program\soffice.exe',
    r'C:\Program Files (x86)\LibreOffice\program\soffice.exe',
    '/Applications/LibreOffice.app/Contents/MacOS/soffice',
    '/usr/bin/soffice', '/usr/local/bin/soffice', '/snap/bin/libreoffice',
]


def achar_soffice():
    env = os.environ.get('SOFFICE')
    if env and pathlib.Path(env).exists():
        return env
    for nome in ('soffice', 'soffice.exe', 'libreoffice'):
        p = shutil.which(nome)
        if p:
            return p
    for c in CANDIDATOS + sorted(glob.glob('/opt/libreoffice*/program/soffice')):
        if pathlib.Path(c).exists():
            return c
    sys.exit('ERRO: LibreOffice (soffice) não encontrado. Instale-o ou defina a variável SOFFICE.')


def rodar_soffice(args, timeout):
    perfil = tempfile.mkdtemp(prefix='lo_perfil_')
    cmd = [achar_soffice(), '--headless', '--norestore', '--nologo', '--nodefault', '--nolockcheck',
           f'-env:UserInstallation={pathlib.Path(perfil).as_uri()}', *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        sys.exit(f'ERRO: o LibreOffice passou de {timeout}s. Tente --timeout maior ou um arquivo menor.')
    finally:
        shutil.rmtree(perfil, ignore_errors=True)
    return r


def converter(arquivos, fmt, saida, timeout=120):
    saida.mkdir(parents=True, exist_ok=True)
    r = rodar_soffice(['--convert-to', fmt, '--outdir', str(saida), *map(str, arquivos)], timeout * len(arquivos))
    ext = fmt.split(':')[0]
    gerados = []
    for a in arquivos:
        alvo = saida / f'{pathlib.Path(a).stem}.{ext}'
        if alvo.exists():
            gerados.append(alvo)
        else:
            print(f'FALHOU: {a} -> {ext}. {r.stderr.strip()[-300:]}', file=sys.stderr)
    return gerados


def pasta_saida(arq, opc):
    return pathlib.Path(opc) if opc else pathlib.Path(arq).resolve().parent / '_convertido'


def paginas_pdf(pdf):
    try:
        import pymupdf  # opcional
        with pymupdf.open(pdf) as d:
            return len(d), [p.get_text().strip().splitlines()[:3] for p in d]
    except ImportError:
        dados = pathlib.Path(pdf).read_bytes()
        return len(re.findall(rb'/Type\s*/Page(?![s\w])', dados)), None


# ---------- extração de texto (sem LibreOffice para docx/pptx) ----------

def texto_docx(arq):
    with zipfile.ZipFile(arq) as z:
        raiz = ET.fromstring(z.read('word/document.xml'))
        n_img = len([n for n in z.namelist() if n.startswith('word/media/')])
    linhas, titulos = [], []
    for p in raiz.iter(f'{W}p'):
        txt = ''.join(t.text or '' for t in p.iter(f'{W}t')).strip()
        if not txt:
            continue
        estilo = p.find(f'{W}pPr/{W}pStyle')
        nome = estilo.get(f'{W}val', '') if estilo is not None else ''
        if re.match(r'(Heading|T[ií]tulo|Title)', nome, re.I):
            titulos.append(txt)
            txt = '# ' + txt
        linhas.append(txt)
    info = {'tabelas': len(list(raiz.iter(f'{W}tbl'))), 'imagens': n_img, 'titulos': titulos}
    return linhas, info


def texto_pptx(arq):
    with zipfile.ZipFile(arq) as z:
        slides = sorted((n for n in z.namelist() if re.match(r'ppt/slides/slide\d+\.xml$', n)),
                        key=lambda n: int(re.search(r'(\d+)', n.rsplit('/', 1)[1]).group(1)))
        linhas, titulos = [], []
        for i, s in enumerate(slides, 1):
            raiz = ET.fromstring(z.read(s))
            pars = [''.join(t.text or '' for t in p.iter(f'{A}t')).strip() for p in raiz.iter(f'{A}p')]
            pars = [p for p in pars if p]
            titulos.append(pars[0] if pars else '(sem texto)')
            linhas.append(f'## Slide {i}')
            linhas.extend(pars)
    return linhas, {'slides': len(slides), 'titulos': titulos}


def texto_qualquer(arq, timeout):
    arq = pathlib.Path(arq)
    ext = arq.suffix.lower()
    if ext == '.docx':
        return texto_docx(arq)
    if ext == '.pptx':
        return texto_pptx(arq)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix='office_txt_'))
    try:
        if ext in ('.doc', '.odt', '.rtf', '.wpd'):
            g = converter([arq], 'docx', tmp, timeout)
            return texto_docx(g[0]) if g else ([], {})
        if ext in ('.ppt', '.odp', '.pps', '.ppsx'):
            g = converter([arq], 'pptx', tmp, timeout)
            return texto_pptx(g[0]) if g else ([], {})
        if ext in ('.xlsx', '.xls', '.ods', '.xlsm'):
            g = converter([arq], 'csv:Text - txt - csv (StarCalc):44,34,76,1', tmp, timeout)
            return (g[0].read_text(encoding='utf-8', errors='replace').splitlines() if g else []), {}
        g = converter([arq], 'txt:Text (encoded):UTF8', tmp, timeout)
        return (g[0].read_text(encoding='utf-8', errors='replace').splitlines() if g else []), {}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------- comandos ----------

def cmd_verificar(a):
    linhas, info = texto_qualquer(a.arquivo, a.timeout)
    pdf = converter([a.arquivo], 'pdf', pasta_saida(a.arquivo, a.saida), a.timeout)
    if pdf:
        n, por_pagina = paginas_pdf(pdf[0])
        print(f'pdf: {pdf[0]}')
        print(f'paginas: {n}')
    for k, v in info.items():
        if k != 'titulos':
            print(f'{k}: {v}')
    if info.get('titulos'):
        print('titulos:')
        for t in info['titulos']:
            print(f'  - {t[:100]}')
    print(f'linhas de texto: {len(linhas)} · palavras: {sum(len(l.split()) for l in linhas)}')
    if pdf and por_pagina:
        print('inicio de cada pagina:')
        for i, ls in enumerate(por_pagina, 1):
            print(f'  p{i}: ' + (' | '.join(x[:60] for x in ls) if ls else '(vazia)'))


def cmd_pdf(a):
    for g in converter([a.arquivo], 'pdf', pasta_saida(a.arquivo, a.saida), a.timeout):
        print(f'pdf: {g} · paginas: {paginas_pdf(g)[0]}')


def cmd_texto(a):
    linhas, _ = texto_qualquer(a.arquivo, a.timeout)
    for l in linhas[:a.max]:
        print(l)
    if len(linhas) > a.max:
        print(f'... ({len(linhas) - a.max} linhas omitidas; use --max)')


def cmd_capa(a):
    for g in converter([a.arquivo], 'png', pasta_saida(a.arquivo, a.saida), a.timeout):
        print(f'png (1a pagina): {g}')


def cmd_csv(a):
    for g in converter([a.arquivo], 'csv:Text - txt - csv (StarCalc):44,34,76,1',
                       pasta_saida(a.arquivo, a.saida), a.timeout):
        print(f'csv (1a aba): {g}')


def cmd_recalcular(a):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix='office_recalc_'))
    try:
        g = converter([a.arquivo], 'xlsx:Calc MS Excel 2007 XML', tmp, a.timeout)
        if g:
            src = pathlib.Path(a.arquivo)
            dest = src.with_name(f'{src.stem}_recalculado.xlsx')
            shutil.move(str(g[0]), dest)
            print(f'recalculado: {dest} (confira os valores com o comando csv)')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cmd_converter(a):
    for g in converter([a.arquivo], a.para, pasta_saida(a.arquivo, a.saida), a.timeout):
        print(f'gerado: {g}')


def cmd_lote(a):
    arqs = sorted(p for p in pathlib.Path(a.arquivo).glob(a.padrao) if p.is_file() and not p.name.startswith('~$'))
    if not arqs:
        sys.exit(f'Nenhum arquivo com o padrão {a.padrao} em {a.arquivo}')
    saida = pathlib.Path(a.saida) if a.saida else pathlib.Path(a.arquivo) / '_convertido'
    gerados = converter(arqs, a.para, saida, a.timeout)
    print(f'{len(gerados)} de {len(arqs)} convertidos em {saida}')


def main():
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding='utf-8')
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    for nome in ('verificar', 'pdf', 'texto', 'capa', 'csv', 'recalcular', 'converter', 'lote'):
        p = sub.add_parser(nome)
        p.add_argument('arquivo')
        p.add_argument('--saida')
        p.add_argument('--timeout', type=int, default=120)
        if nome == 'texto':
            p.add_argument('--max', type=int, default=200)
        if nome in ('converter', 'lote'):
            p.add_argument('--para', required=True, help='ex.: pdf, docx, xlsx, pptx, odt, html')
        if nome == 'lote':
            p.add_argument('--padrao', default='*.*')
    a = ap.parse_args()
    if not pathlib.Path(a.arquivo).exists():
        sys.exit(f'ERRO: não encontrado: {a.arquivo}')
    globals()[f'cmd_{a.cmd}'](a)


if __name__ == '__main__':
    main()
