# Manual de utilização da Maldet WebGUI

## 1. Visão geral

A Maldet WebGUI é a interface web do Linux Malware Detect (Maldet). Ela
permite iniciar e acompanhar scans, administrar quarentena, consultar
relatórios, controlar o monitor inotify, atualizar assinaturas e configurar
alertas.

Por padrão, a interface atende somente em `127.0.0.1:32501`. Isso reduz a
superfície de exposição: para acesso remoto, use um proxy reverso com
autenticação e TLS; não exponha o servidor diretamente sem proteção.

## 2. Instalação

No diretório do projeto ou do pacote universal:

```bash
cd /home/user/copilot-worktrees/linux-malware-detect/fls131313-literate-enigma
sudo bash install.sh
```

O instalador identifica a distribuição, verifica dependências e instala o
Maldet, a GUI e os launchers:

| Componente | Caminho |
|---|---|
| Servidor da GUI | `/usr/local/maldetect/gui/maldet_gui.py` |
| Launcher do servidor | `/usr/local/sbin/maldet-gui` |
| Iniciar servidor e navegador | `/usr/local/sbin/maldet-webgui` |
| Systray | `/usr/local/sbin/maldet-systray` |

Em um desktop compatível, o instalador também cria atalhos no menu de
aplicações e, quando possível, na área de trabalho do usuário.

## 3. Iniciar e parar

### Método recomendado

```bash
maldet-webgui
```

Esse comando inicia o servidor em segundo plano, espera o endpoint de saúde e
abre o navegador em `http://127.0.0.1:32501`.

Após uma instalação como root, o serviço `maldet-gui` é habilitado para
inicialização automática no boot quando systemd ou SysV está disponível.
A configuração fica em `/etc/default/maldet-gui` (ou
`/etc/sysconfig/maldet-gui`). Em systemd, use:

```bash
sudo systemctl status maldet-gui
sudo systemctl restart maldet-gui
```

### Servidor em primeiro plano

```bash
maldet-gui
```

Use `Ctrl+C` para encerrar. Para personalizar:

```bash
MALDET_GUI_PORT=9090 maldet-gui
MALDET_GUI_HOST=127.0.0.1 maldet-gui
```

O arquivo de log do launcher é normalmente
`~/.cache/maldet/gui.log`. O servidor pode ser executado diretamente:

```bash
python3 /usr/local/maldetect/gui/maldet_gui.py \
  --host 127.0.0.1   --port 32501 \
  --base-dir /usr/local/maldetect
```

## 4. Systray

Em um ambiente gráfico com `yad`, execute:

```bash
maldet-systray
```

O ícone mostra no tooltip a quantidade e o estado dos scans ativos. O menu
permite abrir a WebGUI. Se o servidor não estiver ativo, o systray tenta
iniciá-lo automaticamente.

Variáveis úteis:

```bash
MALDET_GUI_URL=http://127.0.0.1:32501
MALDET_SYSTRAY_INTERVAL=5
MALDET_SYSTRAY_START_GUI=1
```

## 5. Páginas da interface

### Seleção de idioma

Use o seletor **Language/Idioma** no canto superior direito. Estão disponíveis
**English** e **Português (Brasil)**. A escolha é salva no armazenamento local
do navegador e permanece após novos acessos no mesmo navegador. A troca
recarrega a interface para garantir que todos os textos sejam renderizados no
idioma selecionado.

### Dashboard

Apresenta versão do Maldet, versão das assinaturas, estado do monitor,
informações do sistema e scans ativos. Use o botão de atualização para
recarregar os dados.

### Scanner

Permite iniciar:

- scan completo de um diretório;
- scan de arquivos modificados recentemente;
- scan a partir de uma lista de arquivos;
- opções de inclusão/exclusão por expressão regular;
- substituições de configuração específicas da execução.

Confira o caminho antes de iniciar. Scans iniciados em segundo plano aparecem
em **Scan Management**.

### Scan Management

Lista somente scans que estão realmente em execução ou pausados. A página
atualiza por polling e mostra progresso quando o mecanismo fornece essa
informação. As ações disponíveis podem incluir pausar, continuar, parar e
encerrar. Use **Stop** para uma finalização controlada e **Kill** somente
quando o processo estiver travado.

Um scan inexistente não deve permanecer como ativo. Se aparecer um estado
stale, atualize a página e consulte o relatório; o backend reconcilia PID,
estado persistido e lista ativa.

### Quarantine

Mostra arquivos colocados em quarentena, estatísticas e ações de restauração.
Restaure somente arquivos analisados e confirmados como legítimos. Operações
em massa devem ser usadas com cuidado.

### Reports

Exibe relatórios históricos e detalhes de cada scan, incluindo arquivos
analisados, hits, itens limpos e quarentena. Use os relatórios para confirmar
o resultado depois que um scan termina.

### Monitoring

Permite iniciar, parar ou recarregar o monitor inotify e visualizar os paths
monitorados. O monitor reage a arquivos criados ou alterados nos diretórios
configurados.

### Updates

Atualiza assinaturas e, quando suportado, a versão do Maldet. Faça updates
antes de uma investigação importante e evite interromper uma atualização.

### Configuration

Edita opções do `conf.maldet`. Salve apenas alterações intencionais. Mudanças
de workers, limites de CPU/IO, engine, alertas e monitoramento podem alterar
significativamente o consumo de recursos.

### Test Alerts

Selecione o canal e envie um alerta de teste. Se o teste funcionar mas eventos
reais não forem enviados, verifique a configuração persistida, reinicie o
monitor depois de atualizar scripts e consulte o Event Log.

### Event Log

Mostra eventos do Maldet e facilita diagnosticar início, progresso, hits,
erros, finalização e falhas de alertas.

### Ignore Lists

Edita `ignore_paths`, extensões ignoradas, assinaturas ignoradas e regras de
inotify. Use regras específicas para não ocultar malware por engano.

### Maintenance

Executa tarefas administrativas e operações de retenção/purge. Ações de purge
podem remover dados históricos; confirme o escopo antes de executar.

### System Info

Exibe caminhos, comandos disponíveis, versão, uso de disco/memória e dados do
ambiente necessários para suporte.

## 6. Alertas Telegram

Configure os campos Telegram na página **Configuration** e valide primeiro em
**Test Alerts**. Nunca compartilhe o token do bot em logs, screenshots ou
relatórios. Os eventos de ciclo de scan podem gerar notificações de início,
hits e fim; falhas de entrega devem ser investigadas no Event Log.

## 7. API e diagnóstico

Verifique a saúde:

```bash
curl -sS http://127.0.0.1:32501/api/check
curl -sS http://127.0.0.1:32501/api/scans/active
```

Endpoints úteis:

| Endpoint | Uso |
|---|---|
| `/api/check` | saúde e versão |
| `/api/system` | informações do sistema |
| `/api/scans/active` | scans em execução |
| `/api/scans` | relatórios |
| `/api/logs` | eventos |
| `/api/config` | configuração |

Se a página ficar em “Loading...”:

1. recarregue com `Ctrl+F5`;
2. verifique `/api/check` com `curl`;
3. confirme que `python3` está instalado;
4. leia `~/.cache/maldet/gui.log`;
5. confirme se a porta configurada está livre.

Se a GUI iniciar mas as operações falharem, confirme o caminho do Maldet e as
permissões do usuário que executa o servidor. A maioria das operações de
administração exige root.

## 8. Segurança e operação

- Mantenha o bind local quando acesso remoto não for necessário.
- Use proxy reverso, autenticação e TLS para acesso remoto.
- Restrinja permissões de configuração, quarentena e logs.
- Faça backup antes de purge, restauração em massa ou alterações amplas.
- Monitore CPU, memória e workers durante scans grandes.
- Após alterar scripts instalados, reinicie o monitor para carregar o código
  atualizado.

## 9. Desinstalação

```bash
sudo bash /usr/local/maldetect/uninstall.sh
```

O desinstalador remove os launchers, atalhos e arquivos instalados conforme o
escopo normal do pacote. Preserve previamente relatórios ou configurações que
precisem ser mantidos.
