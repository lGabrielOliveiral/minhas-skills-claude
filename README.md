# 🧰 Minhas skills para Claude Code

Coleção de skills globais para o Claude Code, criadas e adaptadas por **Gabriel Oliveira** (Power Tuning). Cada pasta em `skills/` é uma skill independente.

| Skill | Para que serve | Autor |
|---|---|---|
| [`minhas-skills`](skills/minhas-skills/SKILL.md) | Lista as suas skills globais em formato de tabela (nome, autor, descrição curta). Digite `/minhas-skills`. | Gabriel Oliveira |
| [`documents-data-visualization`](skills/documents-data-visualization/SKILL.md) | Gráficos em Python para documentos (Word, PDF, PowerPoint): tamanho A4, fontes legíveis e impressão em preto e branco. | Adaptada de `anthropics/knowledge-work-plugins` (Apache 2.0) |
| [`libreoffice-economia`](skills/libreoffice-economia/SKILL.md) | Converte e confere arquivos Office com o LibreOffice em modo headless, usando texto em vez de imagens de página. Economiza tokens. | Gabriel Oliveira |
| [`skill-risk-audit`](skills/skill-risk-audit/SKILL.md) | Audita skills e plugins em busca de comportamento malicioso e dá uma nota de risco de 0 a 4. | Gabriel Oliveira |

## ⚙️ Requisitos

- [Claude Code](https://claude.com/claude-code) instalado.
- **Python 3** (no Windows, `py -3` ou `python`).
- **Git**, para baixar o repositório.
- Para `libreoffice-economia`: LibreOffice (veja a seção da skill).
- Para `documents-data-visualization`: `matplotlib`, `pandas` e `seaborn` (`pip install matplotlib pandas seaborn`).

## 📥 Como instalar

Uma skill global fica em uma destas pastas, e o Claude Code a carrega sozinho na próxima sessão:

- `~/.claude/skills/` (no Windows: `C:\Users\SEU_USUARIO\.claude\skills\`)

### Opção 1: copiar as pastas (recomendado)

Baixe o repositório e copie só as skills que quiser:

```bash
git clone https://github.com/SEU_USUARIO/minhas-skills-claude.git
cd minhas-skills-claude
```

No macOS ou Linux:

```bash
mkdir -p ~/.claude/skills
cp -r skills/minhas-skills ~/.claude/skills/
```

No Windows (PowerShell), dentro da pasta do repositório:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse skills\minhas-skills "$env:USERPROFILE\.claude\skills\"
```

Para instalar todas, troque `minhas-skills` por cada nome da tabela, ou copie a pasta `skills` inteira:

```powershell
Copy-Item -Recurse skills\* "$env:USERPROFILE\.claude\skills\"
```

### Opção 2: link simbólico (para acompanhar atualizações)

Assim, um `git pull` atualiza as skills sem copiar de novo. No Windows, rode o PowerShell como administrador, ou ative o modo de desenvolvedor.

```bash
ln -s "$PWD/skills/minhas-skills" ~/.claude/skills/minhas-skills
```

### Como conferir se funcionou

1. Abra o Claude Code em qualquer pasta.
2. Digite `/` e veja se a skill aparece na lista.
3. Ou peça: "quais skills globais eu tenho?". Se for `minhas-skills`, ela responde com a tabela.

> ⚠️ **Não instale skills de quem você não conhece sem antes auditar.** Use a `skill-risk-audit` para checar o conteúdo antes.

## 🔐 Segurança

- As skills são só instruções em Markdown e scripts Python que leem ou convertem arquivos locais. Nenhuma faz uploads ou usa credenciais.
- Leia o `SKILL.md` e os scripts antes de instalar, principalmente se vierem de outra pessoa.

## 📄 Licença

As skills criadas por Gabriel Oliveira seguem a licença que o autor definir no repositório. A skill `documents-data-visualization` é derivada de `anthropics/knowledge-work-plugins` e mantém a licença Apache 2.0 (arquivo `LICENSE` dentro da pasta).
