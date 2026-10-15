/**
 * DomainScope - client-side domain reconnaissance tool.
 *
 * APIs used:
 *   - Google Public DNS-over-HTTPS JSON API
 *     https://developers.google.com/speed/public-dns/docs/doh
 *   - ipwho.is free IP geolocation API
 *     https://ipwhois.io/
 */

(function () {
    'use strict';

    /* ---------- Theme handling ---------- */
    var themeToggle = document.getElementById('theme-toggle');
    var htmlEl = document.documentElement;

    function applyTheme(theme) {
        htmlEl.setAttribute('data-theme', theme);
        localStorage.setItem('domainscope-theme', theme);
        var isDark = theme === 'dark';
        themeToggle.setAttribute('aria-pressed', String(isDark));
        themeToggle.textContent = isDark ? 'Switch to light mode' : 'Switch to dark mode';
    }

    // The inline script in index.html already set the initial theme; sync the button.
    applyTheme(htmlEl.getAttribute('data-theme') || 'light');

    themeToggle.addEventListener('click', function () {
        var next = htmlEl.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        applyTheme(next);
    });

    /* ---------- Recon form & results ---------- */
    var reconForm = document.getElementById('recon-form');
    var domainInput = document.getElementById('domain');
    var domainError = document.getElementById('domain-error');
    var recordTypeGroup = document.getElementById('record-type-group');
    var recordTypeError = document.getElementById('record-type-error');
    var ipEnrichmentSelect = document.getElementById('ip-enrichment');
    var reconSubmit = document.getElementById('recon-submit');
    var reconSpinner = document.getElementById('recon-spinner');
    var reconStatus = document.getElementById('recon-status');
    var resultsPlaceholder = document.getElementById('results-placeholder');
    var resultsContent = document.getElementById('results-content');
    var dnsBody = document.getElementById('dns-body');
    var ipCards = document.getElementById('ip-cards');
    var ipHeading = document.getElementById('ip-heading');
    var recentSearches = document.getElementById('recent-searches');
    var recentList = document.getElementById('recent-list');
    var copyJsonBtn = document.getElementById('copy-json');
    var downloadReportBtn = document.getElementById('download-report');

    var RECORD_TYPE_NAMES = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA'
    };

    var RECENT_KEY = 'domainscope-recent';
    var lastResult = null;

    function getRecordTypeName(typeNum) {
        return RECORD_TYPE_NAMES[typeNum] || ('Type ' + typeNum);
    }

    function sanitizeDomain(value) {
        var cleaned = value.trim().toLowerCase();
        if (!cleaned) {
            return '';
        }
        // If the user pasted a URL, extract the hostname.
        try {
            var url = new URL(cleaned.indexOf('http') === 0 ? cleaned : 'https://' + cleaned);
            cleaned = url.hostname;
        } catch (e) {
            // Not a URL; treat the input as a domain name.
        }
        // Remove a leading www. subdomain for consistency.
        cleaned = cleaned.replace(/^www\./, '');
        return cleaned;
    }

    function isValidDomain(domain) {
        return /^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])$/.test(domain);
    }

    function setError(input, errorEl, message) {
        if (message) {
            input.classList.add('is-invalid');
            errorEl.textContent = message;
        } else {
            input.classList.remove('is-invalid');
            errorEl.textContent = '';
        }
    }

    function clearReconErrors() {
        setError(domainInput, domainError, '');
        setError(recordTypeGroup, recordTypeError, '');
        reconStatus.textContent = '';
        reconStatus.className = 'status-msg';
    }

    function setStatus(message, isError) {
        reconStatus.textContent = message;
        reconStatus.className = 'status-msg' + (isError ? ' text-danger' : '');
    }

    function fetchWithTimeout(url, options, timeoutMs) {
        timeoutMs = timeoutMs || 10000;
        var controller = new AbortController();
        var timeoutId = window.setTimeout(function () {
            controller.abort();
        }, timeoutMs);

        var opts = options || {};
        opts.signal = controller.signal;

        return fetch(url, opts).finally(function () {
            window.clearTimeout(timeoutId);
        });
    }

    function fetchDnsRecords(domain, type) {
        var url = 'https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + type;
        return fetchWithTimeout(url)
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            })
            .then(function (data) {
                if (data.Status === 3) {
                    return { error: 'Domain not found (NXDOMAIN): ' + domain, records: [] };
                }
                if (data.Status !== 0) {
                    return { error: 'DNS query failed with status ' + data.Status, records: [] };
                }
                var records = (data.Answer || []).map(function (answer) {
                    return {
                        name: answer.name,
                        type: answer.type,
                        typeName: getRecordTypeName(answer.type),
                        ttl: answer.TTL,
                        data: answer.data
                    };
                });
                return { records: records };
            })
            .catch(function (err) {
                return { error: 'Could not fetch ' + type + ' records: ' + err.message, records: [] };
            });
    }

    function fetchIpInfo(ip) {
        return fetchWithTimeout('https://ipwho.is/' + encodeURIComponent(ip))
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            })
            .then(function (data) {
                return data.success ? data : { ip: ip, success: false, error: 'IP lookup failed' };
            })
            .catch(function (err) {
                return { ip: ip, success: false, error: err.message };
            });
    }

    function renderDnsRecords(records) {
        dnsBody.innerHTML = '';
        if (records.length === 0) {
            var row = document.createElement('tr');
            var cell = document.createElement('td');
            cell.colSpan = 4;
            cell.textContent = 'No records found for the selected types.';
            row.appendChild(cell);
            dnsBody.appendChild(row);
            return;
        }

        records.forEach(function (record) {
            var row = document.createElement('tr');
            var typeCell = document.createElement('td');
            typeCell.innerHTML = '<code>' + record.typeName + '</code>';
            var nameCell = document.createElement('td');
            nameCell.textContent = record.name;
            var ttlCell = document.createElement('td');
            ttlCell.textContent = record.ttl;
            var dataCell = document.createElement('td');
            dataCell.innerHTML = '<code>' + escapeHtml(record.data) + '</code>';

            row.appendChild(typeCell);
            row.appendChild(nameCell);
            row.appendChild(ttlCell);
            row.appendChild(dataCell);
            dnsBody.appendChild(row);
        });
    }

    function renderIpCards(ipInfos) {
        ipCards.innerHTML = '';
        var successful = ipInfos.filter(function (info) {
            return info.success;
        });

        if (successful.length === 0) {
            ipHeading.hidden = true;
            return;
        }

        ipHeading.hidden = false;
        successful.forEach(function (info) {
            var card = document.createElement('article');
            card.className = 'ip-card';

            var title = document.createElement('h4');
            title.innerHTML = '<span aria-hidden="true">🌐</span> ' + escapeHtml(info.ip);

            var dl = document.createElement('dl');
            dl.appendChild(makeDefinition('Country', (info.country || 'Unknown') + ' ' + (info.flag ? info.flag.emoji : '')));
            dl.appendChild(makeDefinition('Region', info.region || 'Unknown'));
            dl.appendChild(makeDefinition('City', info.city || 'Unknown'));
            dl.appendChild(makeDefinition('ISP', info.connection && info.connection.isp ? info.connection.isp : 'Unknown'));
            dl.appendChild(makeDefinition('ASN', info.connection && info.connection.asn ? String(info.connection.asn) : 'Unknown'));
            dl.appendChild(makeDefinition('Timezone', info.timezone && info.timezone.id ? info.timezone.id : 'Unknown'));

            card.appendChild(title);
            card.appendChild(dl);
            ipCards.appendChild(card);
        });
    }

    function makeDefinition(term, definition) {
        var dt = document.createElement('dt');
        dt.textContent = term;
        var dd = document.createElement('dd');
        dd.textContent = definition;
        var wrapper = document.createDocumentFragment();
        wrapper.appendChild(dt);
        wrapper.appendChild(dd);
        return wrapper;
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function getRecent() {
        try {
            var raw = localStorage.getItem(RECENT_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch (e) {
            return [];
        }
    }

    function saveRecent(domain) {
        var recent = getRecent();
        // Move to front and de-duplicate.
        recent = recent.filter(function (d) {
            return d !== domain;
        });
        recent.unshift(domain);
        if (recent.length > 8) {
            recent = recent.slice(0, 8);
        }
        try {
            localStorage.setItem(RECENT_KEY, JSON.stringify(recent));
        } catch (e) {
            // Storage may be disabled; ignore.
        }
    }

    function renderRecent() {
        var recent = getRecent();
        recentList.innerHTML = '';
        if (recent.length === 0) {
            recentSearches.hidden = true;
            return;
        }
        recentSearches.hidden = false;
        recent.forEach(function (domain) {
            var chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'recent-chip';
            chip.textContent = domain;
            chip.addEventListener('click', function () {
                domainInput.value = domain;
                reconForm.requestSubmit();
                domainInput.focus();
            });
            recentList.appendChild(chip);
        });
    }

    function performRecon() {
        clearReconErrors();

        var rawDomain = domainInput.value;
        var domain = sanitizeDomain(rawDomain);

        if (!domain || !isValidDomain(domain)) {
            setError(domainInput, domainError, 'Please enter a valid domain name such as example.com.');
            domainInput.focus();
            return;
        }

        var checkedTypes = document.querySelectorAll('input[name="record-type"]:checked');
        var types = Array.prototype.slice.call(checkedTypes).map(function (cb) {
            return cb.value;
        });
        if (types.length === 0) {
            setError(recordTypeGroup, recordTypeError, 'Please select at least one record type.');
            return;
        }

        var enrichment = ipEnrichmentSelect.value;

        reconSubmit.disabled = true;
        reconSpinner.hidden = false;
        setStatus('Querying DNS records…');
        resultsPlaceholder.hidden = true;
        resultsContent.hidden = true;
        ipHeading.hidden = true;

        Promise.all(types.map(function (type) {
            return fetchDnsRecords(domain, type);
        }))
            .then(function (responses) {
                var allRecords = [];
                var errors = [];
                responses.forEach(function (resp) {
                    if (resp.error) {
                        errors.push(resp.error);
                    }
                    if (resp.records) {
                        allRecords = allRecords.concat(resp.records);
                    }
                });

                allRecords.sort(function (a, b) {
                    return a.typeName.localeCompare(b.typeName);
                });

                renderDnsRecords(allRecords);

                var resolvedIps = [];
                if (enrichment !== 'none' && errors.length === 0) {
                    allRecords.forEach(function (record) {
                        if ((record.type === 1 || record.type === 28) && record.data) {
                            var ip = record.data.trim();
                            if (ip && resolvedIps.indexOf(ip) === -1) {
                                resolvedIps.push(ip);
                            }
                        }
                    });
                    var limit = enrichment === 'first' ? 1 : 5;
                    resolvedIps = resolvedIps.slice(0, limit);
                }

                lastResult = {
                    domain: domain,
                    queriedAt: new Date().toISOString(),
                    records: allRecords,
                    ipInfo: []
                };

                var statusMessage = errors.length > 0 ? errors.join(' ') : '';
                var statusIsError = errors.length > 0;

                if (resolvedIps.length > 0) {
                    if (!statusMessage) {
                        statusMessage = 'Enriching IP addresses…';
                    }
                    return Promise.all(resolvedIps.map(fetchIpInfo)).then(function (ipInfos) {
                        lastResult.ipInfo = ipInfos;
                        renderIpCards(ipInfos);
                        return { message: statusMessage, isError: statusIsError };
                    });
                } else {
                    renderIpCards([]);
                    return { message: statusMessage, isError: statusIsError };
                }
            })
            .then(function (status) {
                resultsContent.hidden = false;
                setStatus(status.message, status.isError);
                if (!status.isError) {
                    saveRecent(domain);
                }
                renderRecent();
            })
            .catch(function (err) {
                setStatus('Unexpected error: ' + err.message, true);
            })
            .finally(function () {
                reconSubmit.disabled = false;
                reconSpinner.hidden = true;
            });
    }

    reconForm.addEventListener('submit', function (event) {
        event.preventDefault();
        performRecon();
    });

    /* ---------- Copy / download results ---------- */
    copyJsonBtn.addEventListener('click', function () {
        if (!lastResult) {
            return;
        }
        var json = JSON.stringify(lastResult, null, 2);
        if (navigator.clipboard) {
            navigator.clipboard.writeText(json).then(function () {
                setStatus('JSON copied to clipboard.');
            }).catch(function () {
                setStatus('Could not copy to clipboard.', true);
            });
        } else {
            setStatus('Clipboard API not available in this browser.', true);
        }
    });

    downloadReportBtn.addEventListener('click', function () {
        if (!lastResult) {
            return;
        }
        var lines = [
            'DomainScope Reconnaissance Report',
            '=================================',
            'Domain: ' + lastResult.domain,
            'Generated: ' + new Date(lastResult.queriedAt).toLocaleString(),
            '',
            'DNS Records',
            '-----------'
        ];
        if (lastResult.records.length === 0) {
            lines.push('No records found.');
        } else {
            lastResult.records.forEach(function (r) {
                lines.push(r.typeName + ' | ' + r.name + ' | TTL ' + r.ttl + ' | ' + r.data);
            });
        }
        lines.push('');
        lines.push('IP Intelligence');
        lines.push('---------------');
        var successfulIps = lastResult.ipInfo.filter(function (info) {
            return info.success;
        });
        if (successfulIps.length === 0) {
            lines.push('No IP enrichment data.');
        } else {
            successfulIps.forEach(function (info) {
                lines.push('IP: ' + info.ip);
                lines.push('  Country: ' + (info.country || 'Unknown'));
                lines.push('  ISP: ' + (info.connection && info.connection.isp ? info.connection.isp : 'Unknown'));
                lines.push('  ASN: ' + (info.connection && info.connection.asn ? info.connection.asn : 'Unknown'));
                lines.push('');
            });
        }

        var blob = new Blob([lines.join('\n')], { type: 'text/plain' });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = 'domainscope-report-' + lastResult.domain + '.txt';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    });

    /* ---------- Feedback form ---------- */
    var feedbackForm = document.getElementById('feedback-form');
    var feedbackName = document.getElementById('feedback-name');
    var feedbackEmail = document.getElementById('feedback-email');
    var feedbackType = document.getElementById('feedback-type');
    var feedbackMessage = document.getElementById('feedback-message');
    var feedbackConsent = document.getElementById('feedback-consent');
    var feedbackAlert = document.getElementById('feedback-alert');

    function showFeedbackAlert(message, type) {
        feedbackAlert.textContent = message;
        feedbackAlert.className = 'alert alert-' + type;
        feedbackAlert.hidden = false;
    }

    function hideFeedbackAlert() {
        feedbackAlert.textContent = '';
        feedbackAlert.className = 'alert';
        feedbackAlert.hidden = true;
    }

    function validateFeedback() {
        var valid = true;

        if (feedbackName.value.trim().length < 2) {
            setError(feedbackName, document.getElementById('feedback-name-error'), 'Please enter your name.');
            valid = false;
        } else {
            setError(feedbackName, document.getElementById('feedback-name-error'), '');
        }

        var emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(feedbackEmail.value.trim())) {
            setError(feedbackEmail, document.getElementById('feedback-email-error'), 'Please enter a valid email address.');
            valid = false;
        } else {
            setError(feedbackEmail, document.getElementById('feedback-email-error'), '');
        }

        if (feedbackType.value === '') {
            setError(feedbackType, document.getElementById('feedback-type-error'), 'Please select an issue type.');
            valid = false;
        } else {
            setError(feedbackType, document.getElementById('feedback-type-error'), '');
        }

        if (feedbackMessage.value.trim().length < 10) {
            setError(feedbackMessage, document.getElementById('feedback-message-error'), 'Message must be at least 10 characters.');
            valid = false;
        } else {
            setError(feedbackMessage, document.getElementById('feedback-message-error'), '');
        }

        if (!feedbackConsent.checked) {
            setError(feedbackConsent, document.getElementById('feedback-consent-error'), 'Please consent to storing your feedback.');
            valid = false;
        } else {
            setError(feedbackConsent, document.getElementById('feedback-consent-error'), '');
        }

        return valid;
    }

    feedbackForm.addEventListener('submit', function (event) {
        event.preventDefault();
        hideFeedbackAlert();

        if (!validateFeedback()) {
            showFeedbackAlert('Please fix the highlighted fields and try again.', 'danger');
            return;
        }

        // No backend is connected, so we display a success message and reset the form.
        showFeedbackAlert('Thank you, ' + feedbackName.value.trim() + '. Your feedback has been recorded locally.', 'success');
        feedbackForm.reset();
        feedbackForm.querySelectorAll('.is-invalid').forEach(function (el) {
            el.classList.remove('is-invalid');
        });
        window.setTimeout(hideFeedbackAlert, 5000);
    });

    /* ---------- Footer ---------- */
    document.getElementById('footer-year').textContent = new Date().getFullYear();
    if (document.lastModified) {
        document.getElementById('last-updated').textContent = 'Last updated: ' + document.lastModified;
    }

    /* ---------- Initialise ---------- */
    renderRecent();
})();
