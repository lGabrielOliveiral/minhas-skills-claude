---
name: libreoffice-economia
description: Converte e confere documentos Office (Word, PowerPoint, Excel e formatos antigos .doc/.ppt/.xls) com o LibreOffice em modo headless e um script local, em vez de renderizar páginas como imagem ou automatizar o Word. Use SEMPRE que precisar gerar PDF de um .docx/.pptx/.xlsx, conferir se um documento gerado ficou certo, ler o conteúdo de um arquivo Office, contar páginas ou slides, ver só a capa, transformar planilha em CSV, recalcular fórmulas de um Excel gerado por código, converter arquivos antigos ou converter vários arquivos de uma vez. Prefira esta skill a abrir páginas como imagem para revisão, mesmo que o usuário não fale em LibreOffice.
---

# Documentos Office com economia de tokens

Imagens de página custam muito contexto; texto custa pouco. Esta skill troca "olhar cada página" por "converter com uma ferramenta local e ler o resultado em texto". O script `scripts/office.py` faz as conversões com o LibreOffice (sem interface) e devolve resumos curtos.

## Regra de ouro

1. **Gere** o documento com a biblioteca da linguagem (python-docx, python-pptx, openpyxl).
2. **Converta e confira em texto** com `office.py` (`verificar`, `texto`, `pdf`).
3. **Olhe em imagem só 1 ou 2 páginas-chave** (capa, uma página com gráfico), em baixa resolução, e só quando o visual importar.
4. **Não automatize o Word via COM/AppleScript** para converter: ele trava em segundo plano e prende arquivos. O LibreOffice é independente e roda sem janela.

## Comandos

Rode com o Python do sistema (só usa a biblioteca padrão). No Windows, se `python` não existir, use `py -3`.

```
python "<pasta desta skill>/scripts/office.py" <comando> <arquivo ou pasta> [opções]
```

| Comando | O que faz | Quando usar |
|---|---|---|
| `verificar ARQ` | Gera o PDF, conta páginas, lista títulos/slides, tabelas e imagens (e o início de cada página, se o PyMuPDF estiver instalado) | Conferir um documento que você acabou de gerar |
| `pdf ARQ [--saida DIR]` | Converte para PDF | Entregar PDF ao usuário |
| `texto ARQ [--max N]` | Extrai o texto (docx, pptx, xlsx, odt, rtf, doc, ppt) | Ler conteúdo sem abrir o arquivo |
| `capa ARQ [--saida DIR]` | PNG só da 1ª página/slide | Checagem visual mínima |
| `csv ARQ [--saida DIR]` | Planilha → CSV (primeira aba) | Ler dados de Excel |
| `recalcular ARQ` | Abre e salva pelo LibreOffice, gravando os valores das fórmulas | Excel gerado por código, antes de ler valores |
| `converter ARQ --para FMT` | Qualquer conversão suportada (docx, xlsx, pptx, odt, html, txt…) | Arquivos antigos .doc/.xls/.ppt e outros formatos |
| `lote PASTA --para FMT [--padrao *.docx]` | Converte todos os arquivos da pasta | Muitos arquivos de uma vez |

Saída padrão: uma pasta `_convertido` ao lado do arquivo. O original nunca é alterado (exceto `recalcular`, que grava uma cópia `*_recalculado.xlsx`).

## Como ler o resultado

- `verificar` imprime algo como `paginas: 9`, a lista de títulos, quantas tabelas e imagens existem e, com PyMuPDF, as primeiras linhas de cada página. Compare com o que você pretendia: seções na ordem, números corretos, nenhuma página em branco ou quebra estranha.
- Se precisar do visual, use `capa` (1 imagem) em vez de converter todas as páginas.
- A renderização do LibreOffice pode diferir levemente do Word (espaçamento, quebras de linha). Para fontes do sistema (Segoe UI, Calibri, Arial) o resultado é fiel. Se o usuário for abrir no Word, avise que pequenas diferenças de quebra são normais.

## Instalação do LibreOffice

O script encontra o `soffice` pela variável `SOFFICE`, pelo PATH ou nos locais padrão (Windows, macOS, Linux). Se não achar, diga ao usuário e sugira:

- Windows: `winget install --id TheDocumentFoundation.LibreOffice --exact --override "/qn REGISTER_NO_MSO_TYPES=1"` (não assume os tipos de arquivo do Office)
- macOS: `brew install --cask libreoffice`
- Linux: `sudo apt install libreoffice-core libreoffice-writer libreoffice-calc libreoffice-impress`

Peça confirmação antes de instalar; é um programa de cerca de 350 MB.

## Cuidados

- O script usa um perfil temporário próprio do LibreOffice, então não interfere em um LibreOffice aberto pelo usuário e não trava na primeira execução.
- Cada conversão tem tempo limite (padrão 120 s). Se estourar, o script avisa em vez de ficar preso.
- Documentos de cliente continuam sendo dados sensíveis: as conversões acontecem só na máquina local, dentro da pasta do projeto.
