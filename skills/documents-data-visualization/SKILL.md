---
name: documents-data-visualization
description: Cria gráficos em Python (matplotlib, seaborn) para DOCUMENTOS - relatórios em Word (.docx), PDF, apresentações PowerPoint e material impresso - gerando imagens PNG prontas para inserir. Use sempre que o gráfico for parar dentro de um documento, relatório técnico, relatório de consultoria ou slide, incluindo escolher o tipo de gráfico, formatar para página A4 e impressão em preto e branco. Para gráficos que vão para documentos, esta skill tem PRECEDÊNCIA sobre a skill dataviz. Para páginas web, artifacts HTML e dashboards interativos, use a dataviz.
user-invocable: true
---

# Gráficos para documentos (Word, PDF, PowerPoint)

Guia para escolher o gráfico, gerar o código em Python e entregar uma imagem que funciona dentro de um documento: legível em A4, correta nos números e boa também impressa em preto e branco.

## Precedência sobre a skill dataviz

Esta skill e a `dataviz` podem ser carregadas ao mesmo tempo. Para não haver regras conflitantes:

| Destino do gráfico | Skill que manda |
|---|---|
| Word / .docx, PDF, PowerPoint / .pptx, relatório impresso, PNG ou SVG estático para anexar | **documents-data-visualization (esta)** |
| Página web, artifact HTML, dashboard, React, gráfico interativo | dataviz |

Quando o destino é um documento e a `dataviz` também estiver no contexto:

- **Siga esta skill** em paleta, tamanho de fonte, rótulos, layout, dimensões e formato de saída.
- **Ignore da dataviz** o que só serve para tela interativa: hover, tooltip, crosshair, filtros, modo escuro, cantos arredondados de 4 px, tabela embutida na página.
- **Pode aproveitar da dataviz**, porque não conflita: nunca usar eixo Y duplo, a cor segue a entidade (não a posição no ranking), e o catálogo de anti-padrões como checagem final.
- O validador de paleta da dataviz é **opcional** aqui. Use só se trocar a paleta padrão desta skill por outra.

Se houver dúvida sobre o destino, pergunte ao usuário onde o gráfico será usado.

## Padrão para documentos (aplique em todo gráfico)

Estas regras vieram de um benchmark com gráficos reais de relatório. Seguem os erros que mais custaram pontos.

### Dimensões e fontes

- Largura útil de A4 com margens normais: **16 cm (6,3 pol.)**. Use `figsize=(6.3, altura)` e salve com `dpi=200`.
- Altura máxima de **12 cm (4,7 pol.)** para caber com texto na mesma página. Mais alto que isso, divida em dois gráficos.
- Fonte mínima de **9 pt no tamanho final** (ticks e rótulos) e 12 pt no título. Gere já no tamanho final; nunca dependa de o Word reduzir a imagem.
- Texto em cinza escuro (`#222222` para títulos e valores, `#444444` para eixos e subtítulos). **Nunca cinza claro** para texto: some na impressão.

### Conteúdo obrigatório

- **Título que afirma a conclusão** ("Conexões nunca passam de 19% do limite"), não só o tema.
- **Subtítulo** com período, unidade e filtro aplicado.
- **Rótulo nos dois eixos**, com unidade.
- **Linha de fonte** no rodapé: `Fonte: <origem dos dados>, <período>`.

### Números nos textos: calcule, nunca digite

Todo número que aparece em título, subtítulo ou anotação deve ser **calculado no código a partir dos dados** e inserido com f-string. Nunca escreva valores aproximados à mão.

```python
pico = df['conexoes'].max()
pct = pico / limite * 100
titulo = f'Conexões nunca passam de {pct:.0f}% do limite'
```

Antes de salvar, confira que cada afirmação do texto é verdadeira para **todos** os pontos mostrados. Ex.: não escreva "com ~300 conexões a CPU fica entre 60% e 99%" se o próprio gráfico tem pontos com 300 conexões e CPU de 10%.

### Datas e eixos

- Limite o eixo X ao intervalo dos dados (`ax.set_xlim(df.date.min(), df.date.max())`), para não aparecer um tick depois do último dado.
- Use vírgula decimal e ponto de milhar no padrão brasileiro quando o documento for em português (veja o helper abaixo).
- Barras sempre começam em zero.

### Rótulos em barras e segmentos

- Não coloque número **dentro** de segmento estreito ou com hachura. Se o segmento for menor que ~6% da largura, ponha o valor fora da barra ou omita.
- Com mais de 25 categorias, mostre as principais e agrupe o resto em "demais (n)", ou use dois gráficos. Nomes de categoria nunca abaixo de 9 pt.

### Preto e branco e daltonismo

- Nunca dependa só de cor. Use também hachura (`hatch='//'`) em barras de destaque ou estilos de linha diferentes (sólida, tracejada, pontilhada).
- Use a hachura com moderação: só no grupo de destaque, não em todas as barras.
- Destaque o achado com uma cor forte e deixe o restante em cinza médio.

### Revisão final

Abra o PNG gerado e confira: textos cortados, sobreposições, fonte pequena demais, números dos títulos batendo com os dados. Só depois insira no documento.

## Configuração base

```python
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import pandas as pd
import numpy as np

plt.rcParams.update({
    'figure.figsize': (6.3, 3.9),   # 16 cm x 10 cm
    'figure.dpi': 100,
    'savefig.dpi': 200,
    'savefig.bbox': 'tight',
    'font.size': 10,
    'axes.titlesize': 12,
    'axes.titleweight': 'bold',
    'axes.labelsize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'text.color': '#222222',
    'axes.labelcolor': '#444444',
    'xtick.color': '#444444',
    'ytick.color': '#444444',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'axes.grid': True,
    'grid.color': '#E3E3E3',
    'grid.linewidth': 0.6,
})

# Paleta amigável para daltonismo e legível impressa
PALETTE_CATEGORICAL = ['#4C72B0', '#DD8452', '#55A868', '#C44E52', '#8172B3', '#937860']
COR_DESTAQUE = '#DD8452'
COR_NEUTRA = '#9A9A9A'
PALETTE_SEQUENTIAL = 'YlOrRd'
PALETTE_DIVERGING = 'RdBu_r'


def fonte(fig, texto):
    """Linha de fonte no rodapé da figura."""
    fig.text(0.01, -0.02, texto, fontsize=8, color='#444444', ha='left', va='top')
```

## Escolha do gráfico

| O que mostrar | Melhor gráfico | Alternativas |
|---|---|---|
| **Tendência no tempo** | Linha | Área (acumulado ou composição) |
| **Comparação entre categorias** | Barra vertical | Barra horizontal (muitas categorias), lollipop |
| **Ranking** | Barra horizontal ordenada | Dot plot, slope chart (dois períodos) |
| **Parte do todo** | Barra empilhada | Barra 100% empilhada (foco na proporção), treemap |
| **Composição no tempo** | Área empilhada | Barra 100% empilhada |
| **Distribuição** | Histograma | Box plot (comparar grupos), violino |
| **Correlação (2 variáveis)** | Dispersão | Bolha (3ª variável no tamanho) |
| **Correlação (várias)** | Heatmap de correlação | Pair plot |
| **Duas medidas de escalas diferentes no tempo** | Painéis empilhados com o mesmo eixo X | Dispersão de uma contra a outra, índice com base 100 |
| **Desempenho x meta** | Bullet chart | Linha de referência |
| **Vários indicadores** | Small multiples | Gráficos separados |
| **Um número só** | Número em destaque no texto ou tabela | Não use gráfico |

### Quando NÃO usar

- **Pizza:** só com menos de 6 categorias e quando a proporção exata importa pouco. Prefira barras.
- **3D:** nunca.
- **Eixo Y duplo:** não use. Faça painéis separados com o mesmo eixo X.
- **Barra empilhada com muitas categorias:** difícil comparar os segmentos do meio. Use small multiples ou barras agrupadas.
- **Rosca:** mesmos problemas da pizza. No máximo para um indicador isolado.

## Padrões de código

### Linha com limite de referência

```python
fig, ax = plt.subplots()
ax.plot(df['timestamp'], df['valor'], color=PALETTE_CATEGORICAL[0], linewidth=1.6)
ax.axhline(limite, color='#C44E52', linestyle='--', linewidth=1.2)
ax.annotate(f'Limite: {limite:,}'.replace(',', '.'), xy=(df['timestamp'].iloc[-1], limite),
            xytext=(0, 4), textcoords='offset points', ha='right', fontsize=9, color='#C44E52')

i = df['valor'].idxmax()
ax.annotate(f'Pico: {df.valor[i]:.0f}', xy=(df.timestamp[i], df.valor[i]),
            xytext=(0, 8), textcoords='offset points', ha='center', fontsize=9)

ax.set_xlim(df['timestamp'].min(), df['timestamp'].max())
ax.set_ylim(0, limite * 1.08)
ax.set_ylabel('Conexões')
ax.set_title(f'Pico de {df.valor.max() / limite:.0%} do limite'.replace('.', ','), loc='left')
fonte(fig, 'Fonte: pgwatch2, 02 a 08/11/2026')
fig.savefig('caso_linha.png')
```

### Ranking com destaque

```python
d = df.sort_values('metrica', ascending=True)
destaque = d['metrica'] > corte
cores = np.where(destaque, COR_DESTAQUE, COR_NEUTRA)

fig, ax = plt.subplots(figsize=(6.3, 4.7))
bars = ax.barh(d['categoria'], d['metrica'], color=cores)
for b, h in zip(bars, destaque):
    if h:
        b.set_hatch('//')
        ax.text(b.get_width() + 0.1, b.get_y() + b.get_height() / 2,
                f'{b.get_width():.1f}%'.replace('.', ','), va='center', fontsize=9)

ax.axvline(corte, color='#444444', linestyle=':', linewidth=1)
ax.set_xlabel('Taxa (%)')
ax.grid(axis='y', visible=False)
fig.savefig('caso_ranking.png')
```

Rótulos de valor só nas barras de destaque, não em todas.

### Barra 100% empilhada (proporção por grupo)

```python
estados = ['active', 'idle in transaction', 'idle']
p = df.set_index('grupo')[estados]
p = p.div(p.sum(axis=1), axis=0) * 100

fig, ax = plt.subplots()
esquerda = np.zeros(len(p))
for estado, cor, hatch in zip(estados, ['#4C72B0', '#DD8452', '#D0D0D0'], ['', '//', '']):
    ax.barh(p.index, p[estado], left=esquerda, color=cor, hatch=hatch,
            edgecolor='white', linewidth=1, label=estado)
    esquerda += p[estado].values
ax.set_xlim(0, 100)
ax.xaxis.set_major_formatter(mticker.PercentFormatter())
ax.legend(ncols=3, loc='upper center', bbox_to_anchor=(0.5, -0.12), frameon=False)
fig.savefig('caso_composicao.png')
```

### Duas medidas no mesmo período (sem eixo duplo)

```python
fig, (a1, a2) = plt.subplots(2, 1, sharex=True, figsize=(6.3, 4.7))
a1.plot(df['timestamp'], df['cpu_pct'], color=PALETTE_CATEGORICAL[0], linewidth=1.4)
a1.set_ylabel('CPU (%)')
a1.set_ylim(0, 100)
a2.plot(df['timestamp'], df['conexoes'], color=PALETTE_CATEGORICAL[1], linewidth=1.4)
a2.set_ylabel('Conexões')
a2.set_ylim(0, None)
a2.set_xlim(df['timestamp'].min(), df['timestamp'].max())
r = df['cpu_pct'].corr(df['conexoes'])
fig.suptitle(f'CPU e conexões no mesmo período (correlação r = {r:.2f})'.replace('.', ','),
             x=0.01, ha='left', fontweight='bold')
fig.savefig('caso_paineis.png')
```

Correlação não é causa: escreva "acompanha" ou "coincide com", não "causa".

### Heatmap (dia x hora)

```python
import seaborn as sns
fig, ax = plt.subplots(figsize=(6.3, 3.0))
sns.heatmap(pivot, cmap=PALETTE_SEQUENTIAL, linewidths=0.4, linecolor='white',
            cbar_kws={'label': 'Média de conexões'}, ax=ax)
ax.set_xlabel('Hora do dia')
ax.set_ylabel('')
ax.tick_params(labelsize=9)
fig.savefig('caso_heatmap.png')
```

Com muitas células, não anote todas: destaque só a região ou o valor que sustenta o título.

### Histograma

```python
fig, ax = plt.subplots()
ax.hist(df['valor'], bins=30, color=PALETTE_CATEGORICAL[0], edgecolor='white')
media, mediana = df['valor'].mean(), df['valor'].median()
ax.axvline(media, color='#C44E52', linestyle='--', linewidth=1.2, label=f'Média: {media:,.1f}')
ax.axvline(mediana, color='#444444', linestyle=':', linewidth=1.2, label=f'Mediana: {mediana:,.1f}')
ax.set_xlabel('Valor')
ax.set_ylabel('Frequência')
ax.legend()
fig.savefig('caso_histograma.png')
```

### Formatação de números (padrão brasileiro)

```python
def br(val, casas=0, sufixo=''):
    """1234.5 -> '1.234,5'"""
    s = f'{val:,.{casas}f}'
    return s.replace(',', 'X').replace('.', ',').replace('X', '.') + sufixo


def compacto(val):
    for lim, suf in ((1e9, ' bi'), (1e6, ' mi'), (1e3, ' mil')):
        if abs(val) >= lim:
            return br(val / lim, 1) + suf
    return br(val)


ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, p: br(x)))
```

## Princípios de design

### Cor

- Cor codifica dado, não decora.
- Destaque o achado com uma cor forte e deixe o resto em cinza.
- Dados sequenciais: um só matiz, do claro ao escuro.
- Dados divergentes: dois matizes com ponto médio neutro.
- Categorias: no máximo 6 a 8 cores distintas.
- Evite só vermelho e verde. Use azul e laranja como par principal.

### Tipografia

- O título afirma o achado.
- O subtítulo dá o contexto: período, filtros, origem.
- Rótulos de eixo legíveis, sem girar 90 graus quando der para evitar.
- Rótulos de valor só nos pontos importantes.

### Layout

- Remova o que não informa: bordas, fundos, grades pesadas.
- Ordene categorias pelo valor, salvo ordem natural (meses, etapas).
- Séries temporais mais largas que altas.
- Mesma escala entre painéis que serão comparados.

### Acessibilidade no documento

- No Word, preencha o **texto alternativo** da imagem com a conclusão do gráfico.
- Quando os números exatos importam, coloque uma tabela no anexo.
- Confira se o gráfico funciona impresso em preto e branco.

### Checklist antes de inserir no documento

- [ ] 16 cm de largura, no máximo 12 cm de altura, 200 dpi
- [ ] Nenhum texto abaixo de 9 pt e nenhum texto em cinza claro
- [ ] Título afirma o achado e todos os números foram calculados dos dados
- [ ] Eixos com rótulo e unidade; eixo X limitado aos dados
- [ ] Linha de fonte presente
- [ ] Funciona sem cor (hachura, estilo de linha ou rótulo direto)
- [ ] Sem eixo duplo, sem 3D, barras começando em zero
- [ ] PNG aberto e revisado

## Origem e licença

Derivada da skill `data-visualization` do repositório `anthropics/knowledge-work-plugins` (plugin `data`, commit e050c2e, 06/11/2026), licenciada sob Apache License 2.0 (cópia em `LICENSE`, nesta pasta).

Modificações (09/11/2026): renomeada para `documents-data-visualization`; tradução para português; foco em gráficos para documentos (Word, PDF, PowerPoint); regras de precedência sobre a skill `dataviz`; padrões de dimensão, fonte, linha de fonte, números calculados, formato brasileiro e impressão em preto e branco; exemplos de código revisados; remoção dos exemplos interativos com plotly.
