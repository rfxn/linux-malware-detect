/* =========================================================================
   Maldet GUI — Frontend Application
   Linux Malware Detect Web Interface
   ========================================================================= */

(function() {
    'use strict';

    // ----- API Helper -----
    var API = {
        base: '/api',
        timeout: 10000,
        _fetch: function(path, options) {
            var self = this;
            options = options || {};
            return new Promise(function(resolve, reject) {
                var xhr = new XMLHttpRequest();
                var timer = setTimeout(function() {
                    xhr.abort();
                    reject(new Error('Request timed out'));
                }, self.timeout);
                xhr.open(options.method || 'GET', self.base + path, true);
                xhr.setRequestHeader('Accept', 'application/json');
                if (options.body) xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.onreadystatechange = function() {
                    if (xhr.readyState !== 4) return;
                    clearTimeout(timer);
                    var data = {};
                    try { data = xhr.responseText ? JSON.parse(xhr.responseText) : {}; }
                    catch (e) { reject(new Error('Invalid server response')); return; }
                    if (xhr.status === 401) {
                        showAuthScreen(data.setup_required);
                        reject(new Error(data.error || 'Authentication required'));
                    } else if (xhr.status >= 200 && xhr.status < 300) resolve(data);
                    else reject(new Error(data.error || ('Request failed (' + xhr.status + ')')));
                };

                xhr.onerror = function() {
                    clearTimeout(timer);
                    reject(new Error('Network error'));
                };
                xhr.send(options.body || null);
            });
        },
        get: function(path) { return this._fetch(path, { method: 'GET' }); },
        post: function(path, body) {
            return this._fetch(path, { method: 'POST', body: JSON.stringify(body || {}) });
        },
        put: function(path, body) {
            return this._fetch(path, { method: 'PUT', body: JSON.stringify(body || {}) });
        },
        del: function(path, body) {
            return this._fetch(path, { method: 'DELETE', body: JSON.stringify(body || {}) });
        }
    };

    function showAuthScreen(setup) {
        var existing = document.getElementById('auth-screen');
        if (existing) return;
        var content = document.getElementById('content');
        if (content) content.innerHTML = '';
        var screen = document.createElement('div');
        screen.id = 'auth-screen';
        screen.className = 'auth-screen';
        screen.innerHTML = '<div class="auth-card"><h1>Maldet GUI</h1><p>' +
            (setup ? 'Defina a senha inicial da WebGUI.' : 'Informe a senha da WebGUI.') +
            '</p><form id="auth-form"><input id="auth-password" type="password" minlength="8" required placeholder="Senha (mínimo 8 caracteres)">' +
            '<button class="btn btn-primary" type="submit">' + (setup ? 'Definir senha' : 'Entrar') + '</button><p id="auth-error" class="auth-error"></p></form></div>';
        (content || document.body).appendChild(screen);
        screen.querySelector('#auth-form').addEventListener('submit', function(e) {
            e.preventDefault();
            var password = screen.querySelector('#auth-password').value;
            API.post(setup ? '/auth/setup' : '/auth/login', { password: password }).then(function() {
                screen.remove();
                Router.init();
                initStatusIndicator();
            }).catch(function(err) {
                screen.querySelector('#auth-error').textContent = err.message;
            });
        });
    }

    // ----- Toast Notifications -----
    function toast(message, type, duration) {
        type = type || 'info';
        duration = duration || 5000;
        var container = document.getElementById('toast-container');
        if (!container) return;
        var el = document.createElement('div');
        el.className = 'toast toast-' + type;
        el.textContent = message;
        container.appendChild(el);
        setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, duration);
    }

    // ----- Format Helpers -----
    function fmtTime(epoch) {
        if (!epoch || epoch === 0) return 'n/a';
        return new Date(epoch * 1000).toLocaleString();
    }
    function fmtSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        var k = 1024, units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
    }
    function fmtDuration(seconds) {
        if (!seconds || seconds === 0) return 'n/a';
        seconds = parseInt(seconds);
        var d = Math.floor(seconds / 86400);
        var h = Math.floor((seconds % 86400) / 3600);
        var m = Math.floor((seconds % 3600) / 60);
        var s = seconds % 60;
        if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
        if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
        if (m > 0) return m + 'm ' + s + 's';
        return s + 's';
    }
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        var div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    // ----- UI language -----
    var I18N = {
        lang: localStorage.getItem('maldet.gui.language') || 'en',
        pt: {
            'Language': 'Idioma', 'English': 'Inglês', 'Português (Brasil)': 'Português (Brasil)',
            'Dashboard': 'Painel', 'Scanner': 'Scanner', 'Scan Management': 'Gerenciamento de scans',
            'About Maldet': 'Sobre o Maldet',
            'Quarantine': 'Quarentena', 'Reports': 'Relatórios', 'Monitoring': 'Monitoramento',
            'Updates': 'Atualizações', 'Configuration': 'Configuração', 'Test Alerts': 'Testar alertas',
            'Event Log': 'Log de eventos', 'Ignore Lists': 'Listas de exclusão', 'Maintenance': 'Manutenção',
            'System Info': 'Informações do sistema', 'Checking...': 'Verificando...',
            'Offline': 'Offline', 'maldet not found': 'maldet não encontrado',
            'Online · Monitor ON': 'Online · Monitor ligado', 'Online · Monitor OFF': 'Online · Monitor desligado',
            'Loading...': 'Carregando...', 'Error': 'Erro', 'System Information': 'Informações do sistema',
            'Binary Detection': 'Detecção de binários', 'Scan Configuration': 'Configuração do scan',
            'Scan Type': 'Tipo de scan', 'Scanner engine': 'Mecanismo do scanner', 'Path': 'Caminho',
            'Browse': 'Procurar', 'Modified within (days)': 'Modificados nos últimos (dias)',
            'Config Overrides (-co)': 'Substituições de configuração (-co)', 'Include Regex (-i)': 'Regex de inclusão (-i)',
            'Exclude Regex (-x)': 'Regex de exclusão (-x)', 'Options': 'Opções',
            'Run in background (recommended)': 'Executar em segundo plano (recomendado)',
            'Start Scan': 'Iniciar scan', 'Preparing...': 'Preparando...', 'Starting...': 'Iniciando...',
            'Choose scan folder': 'Escolher pasta do scan', 'Cancel': 'Cancelar',
            'Select this folder': 'Selecionar esta pasta', 'Active Scans': 'Scans ativos',
            'Live updates every 5s': 'Atualização ao vivo a cada 5 s',
            'Live updates every 10s': 'Atualização ao vivo a cada 10 s', 'Details': 'Detalhes',
            'Stop': 'Parar', 'Stopping...': 'Parando...', 'Close': 'Fechar',
            'Quarantined Files': 'Arquivos em quarentena', 'Scan Reports': 'Relatórios de scans',
            'Quarantine': 'Quarentenar', 'Restore': 'Restaurar', 'Inotify Monitoring': 'Monitoramento inotify',
            'Start': 'Iniciar', 'Reload': 'Recarregar', 'Update': 'Atualizar', 'Beta': 'Beta',
            'Update Sigs': 'Atualizar assinaturas', 'Save Changes': 'Salvar alterações',
            'Test Alerts': 'Testar alertas', 'Type': 'Tipo', 'Channel': 'Canal',
            'Send Test Alert': 'Enviar alerta de teste', 'Event Log': 'Log de eventos',
            'entries': 'entradas', 'Maintenance': 'Manutenção', 'Run Maintenance': 'Executar manutenção',
            'Purge All Data': 'Apagar todos os dados', 'Maldet Version': 'Versão do Maldet',
            'Signature Set': 'Conjunto de assinaturas', 'Monitor': 'Monitor',
            'ONLINE': 'ATIVO', 'OFFLINE': 'INATIVO', 'Maldet native (live file progress)': 'Maldet nativo (progresso em tempo real)',
            'ClamAV/clamdscan (faster, limited progress)': 'ClamAV/clamdscan (mais rápido, progresso limitado)',
            'Ready to run': 'Pronto para executar', 'Scan complete - hits found!': 'Scan concluído — ameaças encontradas!',
            'Scan complete - no malware': 'Scan concluído — nenhum malware encontrado',
            'Scan started in background': 'Scan iniciado em segundo plano', 'Monitor started': 'Monitor iniciado',
            'Monitor stopped': 'Monitor parado', 'Monitor reloaded': 'Monitor recarregado',
            'Real-time monitoring (inotify)': 'Monitoramento em tempo real (inotify)',
            'Inotify': 'inotify',
            'Monitoring status': 'Status do monitoramento', 'RUNNING': 'ATIVO', 'STOPPED': 'PARADO',
            'Warning:': 'Aviso:', 'the GUI is not running with root privileges.': 'a GUI não está executando com privilégios de root.',
            'Inotify monitoring usually requires root (the maldet config and state directories are root-only).':
                'O monitoramento inotify geralmente requer root (a configuração e os diretórios de estado do maldet são exclusivos do root).',
            'Start the GUI as root to enable the monitor.': 'Inicie a GUI como root para habilitar o monitor.',
            'Start': 'Iniciar', 'Stop': 'Parar', 'Reload': 'Recarregar',
            'Users monitored': 'Usuários monitorados',
            'Select the users whose home directories should be monitored. Changes take effect after Reload.':
                'Selecione os usuários cujos diretórios home serão monitorados. As alterações entram em vigor após Recarregar.',
            'Save user selection': 'Salvar seleção de usuários',
            'No eligible home users found.': 'Nenhum usuário elegível em /home foi encontrado.',
            'Enabled': 'Habilitado', 'Disabled': 'Desabilitado'
        }
    };
    function tr(text) {
        return I18N.lang === 'pt-BR' ? (I18N.pt[text] || text) : text;
    }
    function translateDom(root) {
        if (I18N.lang !== 'pt-BR') return;
        var walker = document.createTreeWalker(root || document.body, NodeFilter.SHOW_TEXT);
        var node;
        while ((node = walker.nextNode())) {
            var value = node.nodeValue.trim();
            if (value && I18N.pt[value]) node.nodeValue = node.nodeValue.replace(value, I18N.pt[value]);
        }
        document.documentElement.lang = 'pt-BR';
    }
    function applyLanguage() {
        var select = document.getElementById('language-select');
        if (select) select.value = I18N.lang;
        document.documentElement.lang = I18N.lang;
        translateDom(document.body);
        Router.navigate(Router.currentPage);
    }

    // ----- Status Indicator (sidebar footer) -----
    var _statusTimer = null;
    var _scanManagementTimer = null;
    var _scanManagementInterval = 5000;
    var _scanPreparing = false;
    var _scanCompletionPending = false;
    var _scanCompletionIds = {};
    var _scanCompletionPrompted = {};
    function updateStatusIndicator() {
        API.get('/system', { timeout: 5000 }).then(function(data) {
            var sys = data.system || {};
            var dot = document.getElementById('status-dot');
            var text = document.getElementById('status-text');
            if (!dot || !text) return;
            var md = sys.maldet_path;
            if (!md) {
                dot.className = 'status-dot offline';
                text.textContent = 'maldet not found';
                return;
            }
            var running = !!sys.monitor_running;
            dot.className = 'status-dot ' + (running ? 'online' : 'warn');
            text.textContent = running ? 'Online · Monitor ON' : 'Online · Monitor OFF';
        }).catch(function() {
            var dot = document.getElementById('status-dot');
            var text = document.getElementById('status-text');
            if (!dot || !text) return;
            dot.className = 'status-dot offline';
            text.textContent = 'Offline';
        });
    }
    function initStatusIndicator() {
        if (_statusTimer) clearInterval(_statusTimer);
        updateStatusIndicator();
        _statusTimer = setInterval(updateStatusIndicator, 5000);
    }

    // ----- Router -----
    var Router = {
        currentPage: 'dashboard',
        routes: {},
        register: function(name, fn) { this.routes[name] = fn; },
        navigate: function(name) {
            if (this.currentPage === 'scan-management' && name !== 'scan-management') {
                stopScanManagementRefresh();
            }
            this.currentPage = name;
            var items = document.querySelectorAll('.nav-item');
            for (var i = 0; i < items.length; i++) {
                items[i].classList.remove('active');
                if (items[i].dataset.page === name) items[i].classList.add('active');
            }
            var titles = {
                dashboard: tr('Dashboard'), scanner: tr('Scanner'), 'scan-management': tr('Scan Management'),
                quarantine: tr('Quarantine'), reports: tr('Reports'), monitoring: tr('Monitoring'),
                updates: tr('Updates'), config: tr('Configuration'), alerts: tr('Test Alerts'),
                logs: tr('Event Log'), ignore: tr('Ignore Lists'), maintenance: tr('Maintenance'), system: tr('System Info'),
                about: tr('About Maldet')
            };
            document.getElementById('page-title').textContent = titles[name] || name;
            var content = document.getElementById('content');
            content.innerHTML = '<div class="loading">Loading...</div>';
            var self = this;
            if (this.routes[name]) {
                Promise.resolve(this.routes[name]()).then(function(html) {
                    content.innerHTML = html;
                    translateDom(content);
                    if (name === 'scan-management') startScanManagementRefresh();
                }).catch(function(err) {
                    content.innerHTML = '<div class="card"><p style="color:red;">Error: ' + escapeHtml(err.message) + '</p></div>';
                });
            }
        },
        init: function() {
            var self = this;
            document.getElementById('sidebar-nav').addEventListener('click', function(e) {
                var item = e.target.closest('.nav-item');
                if (item) {
                    e.preventDefault();
                    self.navigate(item.dataset.page);
                }
            });
            var languageSelect = document.getElementById('language-select');
            if (languageSelect) {
                languageSelect.value = I18N.lang;
                languageSelect.addEventListener('change', function() {
                    I18N.lang = this.value;
                    localStorage.setItem('maldet.gui.language', I18N.lang);
                    // Reload from the original English template so switching
                    // back from Portuguese never leaves mixed-language nodes.
                    window.location.reload();
                });
            }
            document.getElementById('refresh-btn').addEventListener('click', function() {
                self.navigate(self.currentPage);
            });
            var settingsBtn = document.getElementById('settings-btn');
            if (settingsBtn) {
                settingsBtn.addEventListener('click', function() {
                    self.navigate('config');
                });
            }
            // Delegated click handler for all dynamically rendered buttons/tabs.
            // Uses data-action attributes (CSP-safe, no inline onclick needed).
            document.addEventListener('click', function(e) {
                var el = e.target.closest('[data-action]');
                if (!el) return;
                var action = el.getAttribute('data-action');
                if (action === 'start-scan') startScan();
                else if (action === 'folder-picker') openFolderPicker();
                else if (action === 'scan-details') openScanDetails(el.getAttribute('data-id'));
                else if (action === 'scan-details-close') closeScanDetails();
                else if (action === 'report-details') openReportDetails(el.getAttribute('data-id'));
                else if (action === 'report-details-close') closeReportDetails();
                else if (action === 'folder-up') browseFolder(el.getAttribute('data-path'));
                else if (action === 'folder-select') selectFolder(el.getAttribute('data-path'));
                else if (action === 'folder-close') closeFolderPicker();
                else if (action === 'scan-stop') stopScan(el.getAttribute('data-id'));
                else if (action === 'scan-quarantine') scanAction(el.getAttribute('data-id'), 'quarantine');
                else if (action === 'scan-restore') scanAction(el.getAttribute('data-id'), 'restore');
                else if (action === 'quarantine-details') openQuarantineDetails(el.getAttribute('data-file'));
                else if (action === 'quarantine-details-close') closeQuarantineDetails();
                else if (action === 'monitor-start') monitorStart();
                else if (action === 'monitor-stop') monitorStop();
                else if (action === 'monitor-reload') monitorReload();
                else if (action === 'monitor-save-users') saveMonitorUsers();
                else if (action === 'update-ver') updateVer(false);
                else if (action === 'update-ver-beta') updateVer(true);
                else if (action === 'update-sigs') updateSigs();
                else if (action === 'save-config') saveConfig();
                else if (action === 'change-password') changePassword();
                else if (action === 'send-alert') sendAlert();
                else if (action === 'ignore-tab') showIgnoreTab(el.getAttribute('data-name'));
                else if (action === 'scanner-tab') switchScannerTab(el.getAttribute('data-tab'));
                else if (action === 'run-maint') runMaint();
                else if (action === 'run-purge') runPurge();
                else if (action === 'about-language') document.getElementById('language-select').focus();
                else if (action === 'about-refresh') Router.navigate('about');
                else if (action === 'about-settings') Router.navigate('config');
            });
            document.getElementById('content').addEventListener('change', function(e) {
                if (e.target && e.target.id === 'scan_type') updateScanTypeFields(e.target.value);
            });
            document.getElementById('content').addEventListener('input', function(e) {
                if (e.target && (e.target.id === 'scan_path' || e.target.id === 'scan_days')) updateScanSummary();
            });
            this.navigate('dashboard');
            translateDom(document.body);
        }
    };

    // ----- Dashboard -----
    function renderDashboard() {
        return API.get('/system').then(function(data) {
            var sys = data.system;
            var h = '';
            h += '<div class="grid grid-4" style="margin-bottom:20px;">';
            h += '<div class="stat"><div class="stat-value">' + escapeHtml(sys.version || 'unknown') + '</div><div class="stat-label">Maldet Version</div></div>';
            h += '<div class="stat"><div class="stat-value">' + escapeHtml(sys.signature_version || '?') + '</div><div class="stat-label">Signature Set</div></div>';
            h += '<div class="stat success"><div class="stat-value">' + (sys.active_scans ? sys.active_scans.length : 0) + '</div><div class="stat-label">Active Scans</div></div>';
            h += '<div class="stat ' + (sys.monitor_running ? 'success' : 'danger') + '"><div class="stat-value">' + (sys.monitor_running ? 'ONLINE' : 'OFFLINE') + '</div><div class="stat-label">Monitor</div></div>';
            h += '</div>';
            h += '<div class="card"><div class="card-header"><span class="card-title">System Information</span></div>';
            h += '<div class="grid grid-2"><div><table>';
            h += '<tr><th>Hostname</th><td>' + escapeHtml(sys.hostname) + '</td></tr>';
            h += '<tr><th>OS</th><td>' + escapeHtml(sys.system) + ' ' + escapeHtml(sys.release) + '</td></tr>';
            h += '<tr><th>CPU</th><td>' + escapeHtml(sys.cpu || 'unknown') + ' (' + (sys.cpu_cores || 0) + ' cores)</td></tr>';
            h += '</table></div><div><table>';
            h += '<tr><th>Memory</th><td>' + (sys.mem_total_mb || 0) + ' MB total / ' + (sys.mem_available_mb || 0) + ' MB available</td></tr>';
            h += '<tr><th>Disk</th><td>' + (sys.disk_total_gb || 0) + ' GB total / ' + (sys.disk_free_gb || 0) + ' GB free</td></tr>';
            h += '<tr><th>Install Path</th><td>' + escapeHtml(sys.base_dir) + '</td></tr>';
            h += '<tr><th>Log Directory</th><td>' + escapeHtml(sys.log_dir) + '</td></tr>';
            h += '</table></div></div></div>';
            h += '<div class="card" style="margin-top:16px;"><div class="card-header"><span class="card-title">Binary Detection</span></div>';
            h += '<table><thead><tr><th>Binary</th><th>Path</th><th>Status</th></tr></thead><tbody>';
            var binaries = sys.binaries || {};
            for (var name in binaries) {
                var path = binaries[name];
                h += '<tr><td>' + escapeHtml(name) + '</td><td>' + escapeHtml(path || 'not found') + '</td>';
                h += '<td>' + (path ? '<span class="badge bg-success">Found</span>' : '<span class="badge bg-danger">Missing</span>') + '</td></tr>';
            }
            h += '</tbody></table></div>';
            return h;
        });
    }

    // ----- Scanner -----
    function renderScanner() {
        return API.get('/config').then(function(data) {
            var cm = {};
            for (var k in data.config) cm[k] = data.config[k].value;
            var h = '<div class="card"><div class="card-header"><span class="card-title">Scan Configuration</span></div>';
            h += '<div class="tabs"><div class="tab active" data-action="scanner-tab" data-tab="basic">Basic</div>';
            h += '<div class="tab" data-action="scanner-tab" data-tab="adv">Advanced</div></div>';
            h += '<div id="tab-basic"><div class="form-group"><label class="form-label">Scan Type</label>';
            h += '<select class="form-input" id="scan_type"><option value="all">Full Scan</option><option value="recent">Recent Scan</option></select><small class="form-help" id="scan_type_help">Scans all files below the selected path.</small></div>';
            h += '<div class="form-group"><label class="form-label">Scanner engine</label><div class="form-input" aria-readonly="true">Maldet nativo</div><small class="form-help">Todos os scans usam exclusivamente o mecanismo nativo do Maldet.</small></div>';
            h += '<div class="form-group"><label class="form-label">Path</label><div class="path-picker-row"><input type="text" class="form-input" id="scan_path" value="/home" required placeholder="/home/user"><button type="button" class="btn btn-ghost" data-action="folder-picker">Browse</button></div><small class="form-help">Choose a folder or enter an absolute directory path manually.</small></div>';
            h += '<div class="form-group" id="scan_days_group" style="display:none;"><label class="form-label">Modified within (days)</label><input type="number" class="form-input" id="scan_days" value="2" min="1" step="1"><small class="form-help">Only files modified in this many days will be scanned.</small></div></div>';
            h += '<div id="tab-adv" style="display:none;"><div class="form-group"><label class="form-label">Config Overrides (-co)</label><input type="text" class="form-input" id="scan_co" placeholder="scan_yara=1,scan_hashtype=sha256"></div>';
            h += '<div class="form-group"><label class="form-label">Include Regex (-i)</label><input type="text" class="form-input" id="scan_inc" placeholder=".*\\.php$"></div>';
            h += '<div class="form-group"><label class="form-label">Exclude Regex (-x)</label><input type="text" class="form-input" id="scan_exc" placeholder=".*\\.log"></div></div>';
            h += '<div class="form-group"><label class="form-label">Options</label><label style="font-size:13px;"><input type="checkbox" id="scan_bg" checked> Run in background (recommended)</label></div>';
            h += '<div id="scan_summary" class="alert alert-info">Ready to scan <strong>/home</strong>.</div>';
            h += '<button class="btn btn-primary" id="start-scan-btn" data-action="start-scan">Start Scan</button></div>';
            return h;
        });
    }

    function updateScanTypeFields(type) {
        var daysGroup = document.getElementById('scan_days_group');
        var help = document.getElementById('scan_type_help');
        if (daysGroup) daysGroup.style.display = type === 'recent' ? 'block' : 'none';
        if (help) help.textContent = type === 'recent' ? 'Scans files changed within the selected number of days.' :
            'Scans all files below the selected path.';
        updateScanSummary();
    }

    function updateScanSummary() {
        var path = document.getElementById('scan_path');
        var type = document.getElementById('scan_type');
        var summary = document.getElementById('scan_summary');
        if (!path || !type || !summary) return;
        var label = type.options[type.selectedIndex].text;
        summary.innerHTML = 'Ready to run <strong>' + escapeHtml(label) + '</strong> on <code>' +
            escapeHtml(path.value.trim() || '(enter a path)') + '</code>.';
    }

    function closeFolderPicker() {
        var modal = document.getElementById('folder-picker-modal');
        if (modal) modal.remove();
    }

    function selectFolder(path) {
        var input = document.getElementById('scan_path');
        if (input) {
            input.value = path;
            updateScanSummary();
        }
        closeFolderPicker();
    }

    function browseFolder(path) {
        var body = document.getElementById('folder-picker-body');
        if (body) body.innerHTML = '<p class="form-help">Loading folders...</p>';
        API.get('/directories?path=' + encodeURIComponent(path)).then(function(data) {
            var rows = '';
            if (data.parent !== null && data.parent !== undefined) {
                rows += '<button class="folder-entry folder-parent" data-action="folder-up" data-path="' + escapeHtml(data.parent) + '">↩ ..</button>';
            }
            (data.directories || []).forEach(function(dir) {
                rows += '<button class="folder-entry" data-action="folder-enter" data-path="' + escapeHtml(dir.path) + '">📁 ' + escapeHtml(dir.name) + '<span class="folder-entry-hint">Open</span></button>';
            });
            var current = document.getElementById('folder-picker-path');
            if (body) body.innerHTML = rows || '<p class="form-help">No subfolders found.</p>';
            if (current) current.textContent = data.path;
            var select = document.getElementById('folder-select-current');
            if (select) {
                select.disabled = false;
                select.setAttribute('data-path', data.path);
            }
        }).catch(function(err) {
            if (body) body.innerHTML = '<p class="form-help folder-error">Cannot read this directory: ' + escapeHtml(err.message) + '</p>';
            var select = document.getElementById('folder-select-current');
            if (select) select.disabled = true;
        });
    }

    function openFolderPicker() {
        closeFolderPicker();
        var modal = document.createElement('div');
        modal.id = 'folder-picker-modal';
        modal.className = 'modal-backdrop';
        modal.innerHTML = '<div class="modal"><div class="modal-header"><span class="modal-title">Choose scan folder</span>' +
            '<button class="modal-close" data-action="folder-close">×</button></div><div class="modal-body">' +
            '<div class="folder-current" id="folder-picker-path">Loading...</div><div id="folder-picker-body" class="folder-list"></div></div>' +
            '<div class="modal-footer"><button class="btn btn-ghost" data-action="folder-close">Cancel</button>' +
            '<button class="btn btn-primary" id="folder-select-current" data-action="folder-select" disabled>Select this folder</button></div></div>';
        document.body.appendChild(modal);
        modal.addEventListener('click', function(e) {
            var el = e.target.closest('[data-action]');
            if (!el) return;
            var action = el.getAttribute('data-action');
            if (action === 'folder-close') closeFolderPicker();
            else if (action === 'folder-up') browseFolder(el.getAttribute('data-path'));
            else if (action === 'folder-enter') browseFolder(el.getAttribute('data-path'));
            else if (action === 'folder-select') selectFolder(el.getAttribute('data-path'));
        });
        browseFolder(document.getElementById('scan_path').value.trim() || '/');
    }

    function switchScannerTab(tab) {
        var basic = document.getElementById('tab-basic');
        var adv = document.getElementById('tab-adv');
        if (tab === 'adv') {
            if (basic) basic.style.display = 'none';
            if (adv) adv.style.display = 'block';
        } else {
            if (basic) basic.style.display = 'block';
            if (adv) adv.style.display = 'none';
        }
    }

    function startScan() {
        var scanTypeEl = document.getElementById('scan_type');
        var scanPathEl = document.getElementById('scan_path');
        var scanDaysEl = document.getElementById('scan_days');
        var scanCoEl = document.getElementById('scan_co');
        var scanIncEl = document.getElementById('scan_inc');
        var scanExcEl = document.getElementById('scan_exc');
        var scanBgEl = document.getElementById('scan_bg');
        if (!scanTypeEl || !scanPathEl) {
            toast('Scan form not loaded yet - please wait and try again', 'error');
            return;
        }
        var type = scanTypeEl.value;
        var path = scanPathEl.value.trim();
        if (!path) {
            toast('Enter a scan path before starting', 'error');
            scanPathEl.focus();
            return;
        }
        if (type === 'recent' && (!scanDaysEl.value || parseInt(scanDaysEl.value, 10) < 1)) {
            toast('Recent scans require at least 1 day', 'error');
            scanDaysEl.focus();
            return;
        }
        var button = document.getElementById('start-scan-btn');
        var body = {
            type: type,
            path: path,
            days: (scanDaysEl && scanDaysEl.value) || '2',
            config_overrides: ((scanCoEl && scanCoEl.value) || '') +
                ((scanCoEl && scanCoEl.value) ? ',' : '') +
                'scan_clamscan=0',
            include_regex: (scanIncEl && scanIncEl.value) || '',
            exclude_regex: (scanExcEl && scanExcEl.value) || '',
            background: !!(scanBgEl && scanBgEl.checked)
        };
        if (button) {
            button.disabled = true;
            button.textContent = 'Starting...';
        }
        toast('Preparing scan...', 'info');
        if (button) button.textContent = 'Preparing...';
        setTimeout(function() {
            if (button && button.disabled) button.textContent = 'Starting...';
        }, 500);
        _scanPreparing = true;
        Router.navigate('scan-management');
        API.post('/scan', body).then(function(resp) {
            _scanPreparing = false;
            if (resp.scan_started) {
                _scanCompletionPending = true;
                _scanCompletionIds = {};
                _scanCompletionPrompted = {};
            }
            if (resp.hits_found) toast('Scan complete - hits found!', 'error');
            else if (resp.clean) toast('Scan complete - no malware', 'success');
            else if (resp.scan_started) toast('Scan started in background', 'success');
            else toast(resp.message || 'Scan started', 'info');
            Router.navigate(body.background ? 'scan-management' : 'reports');
        }).catch(function(e) {
            _scanPreparing = false;
            toast('Error: ' + e.message, 'error');
            Router.navigate('scan-management');
        });
    }

    // ----- Scan Management -----
    function buildScanManagementHtml(active) {
        var refreshLabel = active.length > 0 ? 'Live updates every 10s' : 'Live updates every 5s';
        var h = '<div class="card"><div class="card-header"><span class="card-title">Active Scans (' + active.length + ')</span><span style="font-size:12px;color:var(--text-muted);">' + tr(refreshLabel) + '</span></div>';
        if (_scanPreparing) {
            h += '<div class="alert alert-info" style="margin:12px 0;"><strong>Preparing scan...</strong><br><small>Validating the path and starting the Maldet process.</small></div>';
        }
        if (active.length === 0) {
            h += '<p style="padding:12px;color:var(--text-muted);">No active scans.</p>';
        } else {
            h += '<table><thead><tr><th>Scan ID</th><th>Directory</th><th>State</th><th>Engine</th><th>PID</th><th>Files scanned</th><th>Hits</th><th>Elapsed</th><th>Actions</th></tr></thead><tbody>';
            for (var i = 0; i < active.length; i++) {
                var s = active[i];
                var progress = s.progress || {};
                var scanned = Number(progress.position || s.files_scanned || 0);
                var total = Number(progress.total || s.total_files || 0);
                var opaqueEngine = s.engine === 'clamdscan' || s.engine === 'yara';
                var percent = total > 0 ? Math.min(100, Math.max(0, (scanned / total) * 100)) : 0;
                var progressText = (opaqueEngine && scanned === 0) ? 'Progress unavailable' :
                    (total > 0 ? Math.round(percent) + '%' : 'Progress unavailable');
                var currentFile = progress.current_file || s.current_file || '';
                var currentFileHtml = currentFile ? '<div class="scan-current-file" title="' + escapeHtml(currentFile) + '">Current: ' + escapeHtml(currentFile) + '</div>' : '';
                var progressBar = '<div class="scan-progress" role="progressbar" aria-label="Scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + Math.round(percent) + '">' +
                    '<div class="scan-progress-track"><div class="scan-progress-fill" style="width:' + percent.toFixed(1) + '%;"></div></div>' +
                    '<span class="scan-progress-label">' + progressText + '</span>' + currentFileHtml + '</div>';
                var filesText = (opaqueEngine && scanned === 0) ? ('total ' + total + ' <small class="form-help">progress unavailable</small>') :
                    ((scanned > 0 || total > 0) ? (scanned + ' / ' + total) : 'n/a');
                h += '<tr><td>' + escapeHtml(s.scan_id) + '</td><td style="font-size:12px;max-width:260px;word-break:break-all;">' + escapeHtml(s.path || '-') + '</td><td>' + escapeHtml(s.state) + '</td><td>' + escapeHtml(s.engine || '-') + '</td>';
                var hitCount = Number(s.hits || 0);
                var hitLabel = hitCount > 0 ?
                    '<span class="badge bg-danger">' + hitCount + ' detected</span>' :
                    '<span class="badge bg-success">No hits</span>';
                h += '<td>' + (s.pid || '-') + '</td><td>' + progressBar + '<div class="scan-files-count">' + filesText + '</div></td><td>' + hitLabel + '</td><td>' + fmtDuration(s.elapsed) + '</td>';
                h += '<td><button class="btn btn-ghost btn-sm" data-action="scan-details" data-id="' + escapeHtml(s.scan_id || '') + '">Details</button> ';
                h += '<button class="btn btn-danger btn-sm" data-action="scan-stop" data-id="' + escapeHtml(s.scan_id || '') + '">Stop</button></td></tr>';
            }
            h += '</tbody></table>';
        }
        return h + '</div>';
    }

    function refreshScanManagementView() {
        if (Router.currentPage !== 'scan-management') return;
        API.get('/scans/active').then(function(data) {
            if (Router.currentPage !== 'scan-management') return;
            var active = data.active_scans || [];
            if (_scanCompletionPending) {
                for (var i = 0; i < active.length; i++) {
                    if (active[i].scan_id) _scanCompletionIds[active[i].scan_id] = true;
                }
                if (active.length === 0) {
                    var completedId = Object.keys(_scanCompletionIds).filter(function(id) {
                        return !_scanCompletionPrompted[id];
                    })[0];
                    if (completedId) {
                        _scanCompletionPrompted[completedId] = true;
                        _scanCompletionPending = false;
                        if (window.confirm('Scan ' + completedId + ' concluído. Deseja exibir o relatório?')) {
                            Router.navigate('reports');
                        }
                    }
                }
            }
            var content = document.getElementById('content');
            if (content) content.innerHTML = buildScanManagementHtml(active);
            var desiredInterval = active.length > 0 ? 10000 : 5000;
            if (_scanManagementInterval !== desiredInterval) {
                _scanManagementInterval = desiredInterval;
                startScanManagementRefresh();
            }
        }).catch(function(err) {
            if (Router.currentPage !== 'scan-management') return;
            var content = document.getElementById('content');
            if (content) content.innerHTML = '<div class="card"><p style="color:red;">Error: ' + escapeHtml(err.message) + '</p></div>';
        });
    }

    function startScanManagementRefresh() {
        stopScanManagementRefresh();
        _scanManagementTimer = setInterval(refreshScanManagementView, _scanManagementInterval);
    }

    function stopScanManagementRefresh() {
        if (_scanManagementTimer) {
            clearInterval(_scanManagementTimer);
            _scanManagementTimer = null;
        }
    }

    function renderScanManagement() {
        return API.get('/scans/active').then(function(data) {
            return buildScanManagementHtml(data.active_scans || []);
        });
    }

    function closeScanDetails() {
        var modal = document.getElementById('scan-details-modal');
        if (modal) modal.remove();
    }

    function openScanDetails(scanId) {
        closeScanDetails();
        var modal = document.createElement('div');
        modal.id = 'scan-details-modal';
        modal.className = 'modal-backdrop';
        modal.innerHTML = '<div class="modal scan-details-modal"><div class="modal-header"><span class="modal-title">Scan details</span>' +
            '<button class="modal-close" data-action="scan-details-close">×</button></div><div class="modal-body">' +
            '<div class="loading">Loading scan ' + escapeHtml(scanId) + '...</div></div>' +
            '<div class="modal-footer"><button class="btn btn-ghost" data-action="scan-details-close">Close</button></div></div>';
        document.body.appendChild(modal);
        modal.addEventListener('click', function(e) {
            var el = e.target.closest('[data-action]');
            if (el && el.getAttribute('data-action') === 'scan-details-close') closeScanDetails();
        });
        API.get('/scan/' + encodeURIComponent(scanId)).then(function(data) {
            var body = modal.querySelector('.modal-body');
            if (!body) return;
            var h = '';
            var detections = data.hits || data.detections || [];
            if (detections.length) {
                h += '<h4 style="margin:0 0 10px;">Detected files (' + detections.length + ')</h4>';
                h += '<div style="overflow-x:auto;"><table class="scan-details-table"><thead><tr><th>Signature</th><th>File</th><th>Type</th><th>Status</th></tr></thead><tbody>';
                detections.forEach(function(hit) {
                    var status = hit.quarantined ? 'Quarantined' : 'Detected';
                    h += '<tr><td><code>' + escapeHtml(hit.signature || '-') + '</code></td>' +
                        '<td style="word-break:break-all;">' + escapeHtml(hit.file || hit.path || '-') + '</td>' +
                        '<td>' + escapeHtml(hit.hit_type_label || hit.hit_type || '-') + '</td>' +
                        '<td>' + escapeHtml(status) + '</td></tr>';
                });
                h += '</tbody></table></div>';
            } else {
                h += '<p class="form-help">No detected files in this scan.</p>';
            }
            var entries = '';
            Object.keys(data).forEach(function(key) {
                if (key === 'hits' || key === 'detections') return;
                var value = data[key];
                if (value && typeof value === 'object') value = JSON.stringify(value);
                entries += '<tr><th>' + escapeHtml(key) + '</th><td>' + escapeHtml(value) + '</td></tr>';
            });
            if (entries) h += '<h4 style="margin:16px 0 10px;">Scan summary</h4><table class="scan-details-table"><tbody>' + entries + '</tbody></table>';
            body.innerHTML = h;
        }).catch(function(err) {
            var body = modal.querySelector('.modal-body');
            if (body) body.innerHTML = '<p style="color:var(--danger);">Error loading details: ' + escapeHtml(err.message) + '</p>';
        });
    }

    // ----- Quarantine -----
    function renderQuarantine() {
        return API.get('/quarantine').then(function(data) {
            var files = data.files || [];
            var h = '<div class="card"><div class="card-header"><span class="card-title">Quarantined Files (' + files.length + ')</span></div>';
            if (files.length === 0) {
                h += '<p style="padding:12px;color:var(--text-muted);">No files in quarantine.</p>';
            } else {
                h += '<table><thead><tr><th>File</th><th>Signature</th><th>Original Path</th><th>Size</th><th>Actions</th></tr></thead><tbody>';
                for (var i = 0; i < files.length; i++) {
                    var f = files[i];
                    h += '<tr><td><code>' + escapeHtml(f.name) + '</code></td><td>' + escapeHtml(f.signature || '-') + '</td>';
                    h += '<td style="font-size:12px;">' + escapeHtml(f.original_path || '-') + '</td><td>' + fmtSize(f.size) + '</td>';
                    h += '<td><button class="btn btn-ghost btn-sm" data-action="quarantine-details" data-file="' + escapeHtml(f.name) + '">Details</button></td></tr>';
                }
                h += '</tbody></table>';
            }
            h += '</div>';
            return h;
        });
    }

    function openQuarantineDetails(filename) {
        var old = document.getElementById('quarantine-details-modal');
        if (old) old.remove();
        var modal = document.createElement('div');
        modal.id = 'quarantine-details-modal';
        modal.className = 'modal-backdrop';
        modal.innerHTML = '<div class="modal"><div class="modal-header"><span class="modal-title">Infection details</span>' +
            '<button class="modal-close" data-action="quarantine-details-close">×</button></div>' +
            '<div class="modal-body"><p class="form-help">Loading details...</p></div>' +
            '<div class="modal-footer"><button class="btn btn-ghost" data-action="quarantine-details-close">Close</button></div></div>';
        document.body.appendChild(modal);
        API.get('/quarantine/details?file=' + encodeURIComponent(filename)).then(function(data) {
            var body = modal.querySelector('.modal-body');
            var rows = '';
            Object.keys(data).forEach(function(key) {
                var value = data[key];
                if (value && typeof value === 'object') value = JSON.stringify(value);
                rows += '<tr><th>' + escapeHtml(key) + '</th><td style="word-break:break-all;">' + escapeHtml(String(value)) + '</td></tr>';
            });
            body.innerHTML = '<table class="scan-details-table"><tbody>' + rows + '</tbody></table>';
        }).catch(function(err) {
            var body = modal.querySelector('.modal-body');
            body.innerHTML = '<p style="color:var(--danger);">Error loading details: ' + escapeHtml(err.message) + '</p>';
        });
    }

    function closeQuarantineDetails() {
        var modal = document.getElementById('quarantine-details-modal');
        if (modal) modal.remove();
    }

    function openReportDetails(scanId) {
        var old = document.getElementById('report-details-modal');
        if (old) old.remove();
        var modal = document.createElement('div');
        modal.id = 'report-details-modal';
        modal.className = 'modal-backdrop';
        modal.innerHTML = '<div class="modal report-details-modal"><div class="modal-header"><span class="modal-title">Scan report</span>' +
            '<button class="modal-close" data-action="report-details-close">×</button></div>' +
            '<div class="modal-body"><div class="loading">Loading report ' + escapeHtml(scanId) + '...</div></div>' +
            '<div class="modal-footer"><button class="btn btn-ghost" data-action="report-details-close">Close</button></div></div>';
        document.body.appendChild(modal);
        API.get('/scan/' + encodeURIComponent(scanId)).then(function(data) {
            var body = modal.querySelector('.modal-body');
            if (body) body.innerHTML = '<pre class="report-json">' + escapeHtml(JSON.stringify(data, null, 2)) + '</pre>';
        }).catch(function(err) {
            var body = modal.querySelector('.modal-body');
            if (body) body.innerHTML = '<p style="color:var(--danger);">Error loading report: ' + escapeHtml(err.message) + '</p>';
        });
    }

    function closeReportDetails() {
        var modal = document.getElementById('report-details-modal');
        if (modal) modal.remove();
    }

    // ----- Reports -----
    function renderReports() {
        return API.get('/scans').then(function(data) {
            var reports = data.reports || [];
            var h = '<div class="card"><div class="card-header"><span class="card-title">Scan Reports (' + reports.length + ')</span></div>';
            if (reports.length === 0) {
                h += '<p style="padding:12px;color:var(--text-muted);">No reports found.</p>';
            } else {
                h += '<table><thead><tr><th>Scan ID</th><th>Type</th><th>Path</th><th>Started</th><th>Files</th><th>Hits</th><th>Actions</th></tr></thead><tbody>';
                for (var i = 0; i < reports.length; i++) {
                    var r = reports[i];
                    h += '<tr><td><code>' + escapeHtml(r.scan_id || '-') + '</code></td><td>' + escapeHtml(r.type || '-') + '</td>';
                    h += '<td style="font-size:12px;">' + escapeHtml(r.path || '-') + '</td><td>' + fmtTime(r.started_epoch) + '</td>';
                    h += '<td>' + (r.total_files || 0) + '</td><td>' + (r.total_hits || 0) + '</td>';
                    h += '<td><button class="btn btn-primary btn-sm" data-action="report-details" data-id="' + escapeHtml(r.scan_id || '') + '">Exibir relatório</button> ';
                    h += '<button class="btn btn-ghost btn-sm" data-action="scan-quarantine" data-id="' + escapeHtml(r.scan_id || '') + '">Quarantine</button> ';
                    h += '<button class="btn btn-ghost btn-sm" data-action="scan-restore" data-id="' + escapeHtml(r.scan_id || '') + '">Restore</button></td></tr>';
                }
                h += '</tbody></table>';
            }
            h += '</div>';
            return h;
        });
    }

    function scanAction(id, action) {
        var button = null;
        var stopButtons = document.querySelectorAll('[data-action="scan-stop"]');
        for (var i = 0; i < stopButtons.length; i++) {
            if (stopButtons[i].getAttribute('data-id') === id) {
                button = stopButtons[i];
                break;
            }
        }
        if (button) {
            button.disabled = true;
            button.textContent = action === 'stop' ? 'Stopping...' : 'Working...';
        }
        API.post('/scan/' + encodeURIComponent(id) + '/' + action, {}).then(function(r) {
            if (r.returncode !== undefined && r.returncode !== 0 && r.returncode !== 2) {
                throw new Error(r.stderr || r.stdout || (action + ' failed'));
            }
            toast(action + ' complete', 'success');
            if (Router.currentPage === 'scan-management') {
                refreshScanManagementView();
            }
            else if (Router.currentPage === 'reports') Router.navigate('reports');
        }).catch(function(e) {
            toast('Error: ' + e.message, 'error');
            if (button) {
                button.disabled = false;
                button.textContent = 'Stop';
            }
        });
    }

    function stopScan(id) {
        if (!confirm('Stop scan ' + id + '?')) return;
        scanAction(id, 'stop');
    }

    // ----- Monitoring -----
    function renderMonitoring() {
        return Promise.all([API.get('/system'), API.get('/monitor/users')]).then(function(results) {
            var data = results[0], userData = results[1];
            var sys = data.system;
            var h = '<div class="monitor-grid">';
            h += '<div class="card monitor-status-card"><div class="card-header"><span class="card-title">' + tr('Real-time monitoring (inotify)') + '</span><span class="monitor-badge">' + tr('Inotify') + '</span></div>';
            if (!sys.is_root) {
                h += '<div class="alert alert-warning"><strong>' + tr('Warning:') + '</strong> ' + tr('the GUI is not running with root privileges.') + ' ' +
                    tr('Inotify monitoring usually requires root (the maldet config and state directories are root-only).') + ' ' +
                    tr('Start the GUI as root to enable the monitor.') + '</div>';
            }
            h += '<div class="monitor-status-row"><span>' + tr('Monitoring status') + '</span><strong class="monitor-state ' +
                (sys.monitor_running ? 'is-running' : 'is-stopped') + '">' + tr(sys.monitor_running ? 'RUNNING' : 'STOPPED') + '</strong></div>';
            h += '<div class="monitor-actions"><button class="btn btn-primary" data-action="monitor-start">' + tr('Start') + '</button> ';
            h += '<button class="btn btn-danger" data-action="monitor-stop">' + tr('Stop') + '</button> ';
            h += '<button class="btn btn-warning" data-action="monitor-reload">' + tr('Reload') + '</button></div></div>';
            h += '<div class="card monitor-users-card"><div class="card-header"><span class="card-title">' + tr('Users monitored') + '</span></div>';
            h += '<p>' + tr('Select the users whose home directories should be monitored. Changes take effect after Reload.') + '</p>';
            h += '<div class="user-monitor-list">';
            if (!(userData.users || []).length) h += '<p class="form-help">' + tr('No eligible home users found.') + '</p>';
            (userData.users || []).forEach(function(user) {
                h += '<label class="checkbox-row"><input type="checkbox" class="monitor-user-toggle" data-user="' +
                    escapeHtml(user.name) + '"' + (user.enabled ? ' checked' : '') + '> ' +
                    '<strong>' + escapeHtml(user.name) + '</strong> <span class="muted">(' +
                    escapeHtml(user.home) + ')</span></label>';
            });
            h += '</div><button class="btn btn-primary" data-action="monitor-save-users">' + tr('Save user selection') + '</button></div></div>';
            return h;
        });
    }

    function clearMonitorPollers() {
        // Cancel any in-flight monitor polling timers (start/stop).
        var t;
        while ((t = _monitorPollTimers.pop()) !== undefined) {
            clearInterval(t);
        }
    }
    var _monitorPollTimers = [];
    function monitorStart() {
        API.post('/monitor', { action: 'start', mode: 'users' }).then(function(data) {
            if (data.status === 'stopping' || data.status === 'starting') {
                // Systemd start/stop runs in the background; poll the real state.
                if (data.status === 'stopping') { clearMonitorPollers(); }
                toast(data.status === 'stopping'
                    ? 'Stopping monitor... (may take up to 2 minutes)'
                    : 'Starting monitor...', 'info', 6000);
                if (data.status === 'starting') pollMonitorStarted();
                else pollMonitorStopped();
                return;
            }
            if (data && data.message === 'Monitor is already running') {
                toast('Monitor is already running', 'info');
                Router.navigate('monitoring');
                return;
            }
            toast('Monitor started', 'success');
            Router.navigate('monitoring');
        })
        .catch(function(e) { toast('Error: ' + e.message, 'error'); });
    }
    function monitorStop() {
        clearMonitorPollers();
        API.post('/monitor', { action: 'stop' }).then(function(data) {
            toast('Stopping monitor... (may take up to 2 minutes)', 'info', 6000);
            pollMonitorStopped();
        })
        .catch(function(e) { toast('Error: ' + e.message, 'error'); });
    }
    function monitorReload() {
        API.post('/monitor', { action: 'reload' }).then(function(data) {
            toast((data && data.message) || 'Monitor reloaded', 'success');
            updateStatusIndicator();
            Router.navigate('monitoring');
            // Reloading systemd can briefly leave the old status in the page;
            // fetch the post-restart state again after the unit settles.
            setTimeout(function() {
                if (Router.currentPage === 'monitoring') {
                    updateStatusIndicator();
                    Router.navigate('monitoring');
                }
            }, 1000);
        })
        .catch(function(e) { toast('Error: ' + e.message, 'error'); });
    }
    function saveMonitorUsers() {
        var disabled = [];
        document.querySelectorAll('.monitor-user-toggle').forEach(function(input) {
            if (!input.checked) disabled.push(input.getAttribute('data-user'));
        });
        API.put('/monitor/users', { users: disabled }).then(function(data) {
            toast((data && data.message) || 'User selection saved; reload the monitor', 'success');
        }).catch(function(e) { toast('Error: ' + e.message, 'error'); });
    }
    function pollMonitorStarted() {
        // Poll system status until the monitor is fully up (max ~90s).
        var tries = 0;
        var timer = setInterval(function() {
            tries++;
            API.get('/system').then(function(data) {
                var running = data.system && data.system.monitor_running;
                if (running) {
                    clearInterval(timer);
                    updateStatusIndicator();
                    toast('Monitor started', 'success');
                    Router.navigate('monitoring');
                } else if (tries > 45) {
                    clearInterval(timer);
                    updateStatusIndicator();
                    toast('Timed out waiting for the monitor to start', 'error');
                    Router.navigate('monitoring');
                }
            }).catch(function() {
                // keep polling on transient errors
            });
        }, 2000);
        _monitorPollTimers.push(timer);
    }
    function pollMonitorStopped() {
        // Poll system status until the monitor is fully down (max ~130s).
        var tries = 0;
        var timer = setInterval(function() {
            tries++;
            API.get('/system').then(function(data) {
                var running = data.system && data.system.monitor_running;
                if (!running) {
                    clearInterval(timer);
                    updateStatusIndicator();
                    toast('Monitor stopped', 'success');
                    Router.navigate('monitoring');
                    setTimeout(function() {
                        if (Router.currentPage === 'monitoring') {
                            updateStatusIndicator();
                            Router.navigate('monitoring');
                        }
                    }, 500);
                } else if (tries > 65) {
                    clearInterval(timer);
                    updateStatusIndicator();
                    toast('Timed out waiting for the monitor to stop', 'error');
                    Router.navigate('monitoring');
                }
            }).catch(function() {
                // keep polling on transient errors
            });
        }, 2000);
        _monitorPollTimers.push(timer);
    }

    // ----- Updates -----
    function renderUpdates() {
        return API.get('/system').then(function(data) {
            var sys = data.system;
            var h = '<div class="card"><div class="card-header"><span class="card-title">Updates</span></div><table>';
            h += '<tr><td>LMD Version</td><td>' + escapeHtml(sys.version || 'unknown') + '</td>';
            h += '<td><button class="btn btn-primary btn-sm" data-action="update-ver">Update</button> <button class="btn btn-warning btn-sm" data-action="update-ver-beta">Beta</button></td></tr>';
            h += '<tr><td>Signatures</td><td>' + escapeHtml(sys.signature_version || 'unknown') + '</td>';
            h += '<td><button class="btn btn-primary btn-sm" data-action="update-sigs">Update Sigs</button></td></tr>';
            h += '</table></div>';
            return h;
        });
    }

    function updateVer(beta) {
        API.post('/update/version', { beta: beta }).then(function() { toast('Update complete', 'success'); });
    }
    function updateSigs() {
        API.post('/update/sigs', {}).then(function() { toast('Signatures updated', 'success'); });
    }

    // ----- Config -----
    function renderConfig() {
        return API.get('/config').then(function(data) {
            var config = data.config || {};
            var h = '<div class="config-page"><div class="card config-intro"><div class="card-header"><span class="card-title">Configuration</span></div>';
            h += '<p class="config-path">File: <code>' + escapeHtml(data.path) + '</code></p>';
            h += '<p class="form-help">Edit values below and save only the settings you changed.</p></div>';
            var groups = {};
            var groupOrder = [];
            for (var key in config) {
                var opt = config[key];
                if (key === '__error__') continue;
                var group = opt.section || 'General';
                if (key.indexOf('email_') === 0) group = 'E-mail';
                else if (key.indexOf('telegram_') === 0) group = 'Telegram';
                if (!groups[group]) {
                    groups[group] = [];
                    groupOrder.push(group);
                }
                groups[group].push({ key: key, opt: opt });
            }
            groupOrder.forEach(function(group) {
                h += '<div class="card config-section"><div class="config-section-title">' + escapeHtml(group) + '</div><div class="config-options">';
                groups[group].forEach(function(item) {
                    var key = item.key, opt = item.opt;
                    h += '<div class="config-option"><label class="config-option-label" for="config-' + escapeHtml(key) + '"><code>' + escapeHtml(key) + '</code></label>';
                    h += '<input id="config-' + escapeHtml(key) + '" type="text" class="form-input" value="' + escapeHtml(opt.value) + '" data-key="' + escapeHtml(key) + '">';
                    if (opt.comment) h += '<small class="config-comment">' + escapeHtml(opt.comment) + '</small>';
                    h += '</div>';
                });
                h += '</div></div>';
            });
            h += '<div class="config-actions"><button class="btn btn-success" id="save-config-btn" data-action="save-config">Save Changes</button></div></div>';
            h += '<div class="card config-section"><div class="config-section-title">Security</div>' +
                '<p class="form-help">Change the password used to access the WebGUI.</p>' +
                '<div class="config-password-grid">' +
                '<div class="form-group"><label class="form-label" for="current-password">Current password</label><input id="current-password" class="form-input" type="password" autocomplete="current-password"></div>' +
                '<div class="form-group"><label class="form-label" for="new-password">New password</label><input id="new-password" class="form-input" type="password" minlength="8" autocomplete="new-password"></div>' +
                '<div class="form-group"><label class="form-label" for="confirm-password">Confirm new password</label><input id="confirm-password" class="form-input" type="password" minlength="8" autocomplete="new-password"></div>' +
                '</div><div class="config-actions"><button class="btn btn-primary" data-action="change-password">Change Password</button></div></div>';
            return h;
        });
    }

    function changePassword() {
        var current = document.getElementById('current-password');
        var next = document.getElementById('new-password');
        var confirm = document.getElementById('confirm-password');
        if (!current || !next || !confirm) return;
        if (next.value.length < 8) {
            toast('New password must contain at least 8 characters', 'error');
            return;
        }
        if (next.value !== confirm.value) {
            toast('New passwords do not match', 'error');
            return;
        }
        var button = document.querySelector('[data-action="change-password"]');
        if (button) button.disabled = true;
        API.post('/auth/change', {
            current_password: current.value,
            new_password: next.value,
            confirm_password: confirm.value
        }).then(function() {
            current.value = '';
            next.value = '';
            confirm.value = '';
            toast('Password changed successfully', 'success');
        }).catch(function(err) {
            toast('Password change failed: ' + err.message, 'error');
        }).then(function() {
            if (button) button.disabled = false;
        });
    }

    function saveConfig() {
        var inputs = document.querySelectorAll('#content input[data-key]');
        var changes = [];
        inputs.forEach(function(inp) {
            if (inp.value !== inp.defaultValue) {
                changes.push(API.put('/config', { key: inp.dataset.key, value: inp.value }));
            }
        });
        if (!changes.length) {
            toast('No configuration changes to save', 'info');
            return;
        }
        var button = document.getElementById('save-config-btn');
        if (button) {
            button.disabled = true;
            button.textContent = 'Saving...';
        }
        Promise.all(changes).then(function() {
            toast('Saved ' + changes.length + ' configuration change(s)', 'success');
            Router.navigate('config');
        }).catch(function(err) {
            toast('Configuration save failed: ' + err.message, 'error');
            if (button) {
                button.disabled = false;
                button.textContent = 'Save Changes';
            }
        });
    }

    // ----- Alerts -----
    function renderAlerts() {
        return '<div class="card"><div class="card-header"><span class="card-title">Test Alerts</span></div>' +
            '<div class="form-group"><label class="form-label">Type</label><select class="form-input" id="alert_type"><option value="scan">Scan</option><option value="digest">Digest</option></select></div>' +
            '<div class="form-group"><label class="form-label">Channel</label><select class="form-input" id="alert_chan"><option value="email">Email</option><option value="telegram">Telegram</option></select></div>' +
            '<button class="btn btn-primary" data-action="send-alert">Send Test Alert</button></div>';
    }

    function sendAlert() {
        var type = document.getElementById('alert_type').value;
        var chan = document.getElementById('alert_chan').value;
        var button = document.querySelector('[data-action="send-alert"]');
        if (button) {
            button.disabled = true;
            button.textContent = 'Sending...';
        }
        API.post('/test-alert', { type: type, channel: chan }).then(function(data) {
            var output = data.stderr || data.stdout || '';
            toast(output || 'Alert sent successfully', 'success');
        }).catch(function(err) {
            toast('Alert failed: ' + err.message, 'error', 8000);
        }).finally(function() {
            if (button) {
                button.disabled = false;
                button.textContent = 'Send Test Alert';
            }
        });
    }

    // ----- Logs -----
    function renderLogs() {
        return API.get('/logs?lines=50').then(function(data) {
            var logs = data.logs || [];
            var h = '<div class="card"><div class="card-header"><span class="card-title">Event Log (' + logs.length + ' entries)</span></div>';
            h += '<div style="max-height:60vh;overflow-y:auto;"><table style="width:100%;"><tbody>';
            for (var i = 0; i < logs.length; i++) {
                h += '<tr><td style="font-family:monospace;font-size:12px;white-space:pre-wrap;">' + escapeHtml(logs[i]) + '</td></tr>';
            }
            h += '</tbody></table></div></div>';
            return h;
        });
    }

    // ----- Ignore -----
    function renderIgnore() {
        return API.get('/ignore').then(function(data) {
            var files = data.files || {};
            var h = '<div class="card"><div class="card-header"><span class="card-title">Ignore Lists</span></div><div class="tabs">';
            var first = true;
            for (var name in files) {
                h += '<div class="tab" data-action="ignore-tab" data-name="' + escapeHtml(name) + '">' + escapeHtml(name) + '</div>';
                first = false;
            }
            h += '</div>';
            for (var name in files) {
                var info = files[name];
                h += '<div id="ignore-' + name + '" style="display:' + (name === Object.keys(files)[0] ? 'block' : 'none') + ';">';
                h += '<p style="font-size:12px;color:var(--text-muted);">' + escapeHtml(info.description) + '</p>';
                h += '<textarea class="form-textarea" rows="10" style="width:100%;">' + info.lines.map(function(l) { return escapeHtml(l); }).join('\n') + '</textarea></div>';
            }
            h += '</div>';
            return h;
        });
    }

    function showIgnoreTab(name) {
        var tabs = document.querySelectorAll('[id^="ignore-"]');
        for (var i = 0; i < tabs.length; i++) tabs[i].style.display = 'none';
        document.getElementById('ignore-' + name).style.display = 'block';
    }

    // ----- Maintenance -----
    function renderMaintenance() {
        return '<div class="card"><div class="card-header"><span class="card-title">Maintenance</span></div>' +
            '<button class="btn btn-warning" data-action="run-maint">Run Maintenance</button> ' +
            '<button class="btn btn-danger" data-action="run-purge">Purge All Data</button></div>';
    }

    function runMaint() {
        API.post('/maintenance', {}).then(function() { toast('Maintenance complete', 'success'); });
    }
    function runPurge() {
        if (!confirm('Clear all logs, quarantine, and temp data?')) return;
        API.post('/purge', {}).then(function() { toast('Purge complete', 'success'); });
    }

    // ----- System Info -----
    function renderSystemInfo() {
        return API.get('/system').then(function(data) {
            var sys = data.system;
            var h = '<div class="card"><div class="card-header"><span class="card-title">System Info</span></div><table>';
            for (var key in sys) {
                if (key === 'binaries' || key === 'active_scans') continue;
                h += '<tr><th>' + escapeHtml(key) + '</th><td>' + escapeHtml(String(sys[key])) + '</td></tr>';
            }

            h += '</table></div>';
            return h;
        });
    }

    // ----- About -----
    function renderAbout() {
        return '<div class="about-html-page">' +
            '<header class="about-html-header"><div class="about-logo-area"><h1>Linux Malware Detect</h1><span>Maldet</span></div>' +
            '<div class="about-actions" aria-label="Ferramentas e Idioma">' +
            '<button class="about-action" title="Idioma" data-action="about-language">🌐</button>' +
            '<button class="about-action" title="Atualizar" data-action="about-refresh">🔄</button>' +
            '<button class="about-action" title="Configurações" data-action="about-settings">⚙️</button></div></header>' +
            '<main>' +
            '<section class="about-html-card"><h2>Sobre o Maldet / About Maldet</h2>' +
            '<div class="about-lang-section"><div class="about-lang-title">Português (Brasil)</div>' +
            '<p>Uma camada prática de detecção de malware para servidores Linux, com varredura nativa, quarentena, monitoramento em tempo real e WebGUI.</p>' +
            '<p>O Maldet analisa arquivos em busca de assinaturas conhecidas e indicadores de comprometimento. Você pode iniciar scans completos ou recentes, acompanhar o progresso, revisar detalhes das infecções e restaurar arquivos da quarentena.</p></div>' +
            '<hr class="about-divider"><div class="about-lang-section"><div class="about-lang-title">English</div>' +
            '<p>A practical malware detection layer for Linux servers, with native scanning, quarantine, real-time monitoring, and a WebGUI.</p>' +
            '<p>Maldet scans files for known signatures and indicators of compromise. You can start full or recent scans, follow progress, review infection details, and restore quarantined files.</p></div></section>' +
            '<section class="about-html-card"><h2>Recursos / Key Features</h2><div class="about-feature-grid">' +
            '<div><div class="about-lang-title">Português (Brasil)</div><ul><li>Engine nativo do Maldet</li><li>Quarentena e detalhes por arquivo</li><li>Monitoramento inotify por usuário</li><li>Alertas e relatórios</li><li>Assinaturas atualizáveis</li></ul></div>' +
            '<div><div class="about-lang-title">English</div><ul><li>Maldet native engine</li><li>Quarantine with per-file details</li><li>Per-user inotify monitoring</li><li>Alerts and reports</li><li>Updatable signatures</li></ul></div></div></section>' +
            '</main><footer class="about-html-footer"><p><strong>Uso responsável / Responsible use:</strong><br>Use o Maldet em sistemas que você administra e mantenha as assinaturas atualizadas.<br><em>Use Maldet on systems you administer and keep signatures up to date.</em></p></footer></div>';
    }

    // ----- Register Routes -----
    Router.register('dashboard', renderDashboard);
    Router.register('scanner', renderScanner);
    Router.register('scan-management', renderScanManagement);
    Router.register('quarantine', renderQuarantine);
    Router.register('reports', renderReports);
    Router.register('monitoring', renderMonitoring);
    Router.register('updates', renderUpdates);
    Router.register('config', renderConfig);
    Router.register('alerts', renderAlerts);
    Router.register('logs', renderLogs);
    Router.register('ignore', renderIgnore);
    Router.register('maintenance', renderMaintenance);
    Router.register('system', renderSystemInfo);
    Router.register('about', renderAbout);

    // ----- Initialize -----
    document.addEventListener('DOMContentLoaded', function() {
        window.__maldet_booted = true;
        API.get('/auth/status').then(function(status) {
            if (status.authenticated) {
                Router.init();
                initStatusIndicator();
            } else {
                showAuthScreen(status.setup_required);
            }
        }).catch(function() { showAuthScreen(true); });
    });

    // ----- Global exposure (backward compatibility) -----
    // Buttons now use delegated data-action clicks (see Router.init), which
    // work regardless of scope/CSP.  These exports are kept so any cached
    // HTML or console calls to fn() keep working.
    window.startScan = startScan;
    window.stopScan = stopScan;
    window.scanAction = scanAction;
    window.monitorStart = monitorStart;
    window.monitorStop = monitorStop;
    window.runMaint = runMaint;
    window.runPurge = runPurge;
    window.saveConfig = saveConfig;
    window.sendAlert = sendAlert;
    window.showIgnoreTab = showIgnoreTab;
    window.updateVer = updateVer;
    window.updateSigs = updateSigs;
})();
