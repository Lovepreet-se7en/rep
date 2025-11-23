// Utility functions for rep+

export function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

export function formatTime(capturedAt) {
    if (!capturedAt) return '';

    const date = new Date(capturedAt);
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const seconds = date.getSeconds().toString().padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
}

export function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

export function testRegex(pattern, text) {
    try {
        const regex = new RegExp(pattern);
        return regex.test(text);
    } catch (e) {
        // Invalid regex pattern - don't match anything
        return false;
    }
}

export function decodeJWT(jwt) {
    try {
        // Remove whitespace
        jwt = jwt.trim();

        // Split JWT into parts (header.payload.signature)
        const parts = jwt.split('.');

        if (parts.length !== 3) {
            throw new Error('Invalid JWT format. Expected format: header.payload.signature');
        }

        // Base64URL decode helper
        function base64UrlDecode(str) {
            // Replace base64url characters with base64 characters
            str = str.replace(/-/g, '+').replace(/_/g, '/');

            // Add padding if needed
            while (str.length % 4) {
                str += '=';
            }

            // Decode base64
            try {
                const decoded = atob(str);
                // Convert to JSON string
                return decodeURIComponent(
                    decoded.split('').map(function (c) {
                        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                    }).join('')
                );
            } catch (e) {
                throw new Error('Failed to decode base64: ' + e.message);
            }
        }

        // Decode header
        let header;
        try {
            const headerJson = base64UrlDecode(parts[0]);
            header = JSON.parse(headerJson);
        } catch (e) {
            throw new Error('Failed to decode JWT header: ' + e.message);
        }

        // Decode payload
        let payload;
        try {
            const payloadJson = base64UrlDecode(parts[1]);
            payload = JSON.parse(payloadJson);
        } catch (e) {
            throw new Error('Failed to decode JWT payload: ' + e.message);
        }

        // Format output
        let output = 'JWT Decoded:\n\n';
        output += '=== HEADER ===\n';
        output += JSON.stringify(header, null, 2);
        output += '\n\n=== PAYLOAD ===\n';
        output += JSON.stringify(payload, null, 2);
        output += '\n\n=== SIGNATURE ===\n';
        output += parts[2] + '\n';
        output += '(Signature verification not performed)';

        // Add helpful info if exp claim exists
        if (payload.exp) {
            const expDate = new Date(payload.exp * 1000);
            const now = new Date();
            const isExpired = expDate < now;
            output += '\n\n=== TOKEN INFO ===\n';
            output += `Expiration: ${expDate.toISOString()}\n`;
            output += `Status: ${isExpired ? 'EXPIRED' : 'VALID'}\n`;
            if (isExpired) {
                output += `Expired ${Math.floor((now - expDate) / 1000 / 60)} minutes ago`;
            } else {
                output += `Expires in ${Math.floor((expDate - now) / 1000 / 60)} minutes`;
            }
        }

        return output;

    } catch (error) {
        throw new Error('JWT decode failed: ' + error.message);
    }
}

export function highlightHTTP(text) {
    if (!text) return '';

    const lines = text.split('\n');
    let inBody = false;
    let bodyStartIndex = -1;

    // Find where body starts (first empty line)
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim() === '') {
            inBody = true;
            bodyStartIndex = i;
            break;
        }
    }

    let highlighted = '';

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (i === 0) {
            // Request line: METHOD PATH VERSION
            const parts = line.split(' ');
            if (parts.length >= 2) {
                highlighted += `<span class="http-method">${escapeHtml(parts[0])}</span> `;
                highlighted += `<span class="http-path">${escapeHtml(parts.slice(1, -1).join(' '))}</span> `;
                if (parts.length > 2) {
                    highlighted += `<span class="http-version">${escapeHtml(parts[parts.length - 1])}</span>`;
                }
            } else {
                highlighted += escapeHtml(line);
            }
        } else if (!inBody || i < bodyStartIndex) {
            // Header line
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                const headerName = line.substring(0, colonIndex);
                const headerValue = line.substring(colonIndex + 1);
                highlighted += `<span class="http-header-name">${escapeHtml(headerName)}</span>`;
                highlighted += '<span class="http-colon">:</span>';
                highlighted += `<span class="http-header-value">${escapeHtml(headerValue)}</span>`;
            } else {
                highlighted += escapeHtml(line);
            }
        } else if (i === bodyStartIndex) {
            // Empty line between headers and body
            highlighted += '';
        } else {
            // Body - try to detect and highlight JSON
            const bodyContent = lines.slice(bodyStartIndex + 1).join('\n');
            highlighted += highlightJSON(bodyContent);
            break;
        }

        if (i < lines.length - 1) {
            highlighted += '\n';
        }
    }

    return highlighted;
}

function highlightJSON(text) {
    try {
        // Try to parse as JSON
        JSON.parse(text);

        // If successful, highlight JSON syntax
        return text.replace(
            /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
            (match) => {
                let cls = 'json-number';
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        cls = 'json-key';
                    } else {
                        cls = 'json-string';
                    }
                } else if (/true|false/.test(match)) {
                    cls = 'json-boolean';
                } else if (/null/.test(match)) {
                    cls = 'json-null';
                }
                return `<span class="${cls}">${escapeHtml(match)}</span>`;
            }
        );
    } catch (e) {
        // Not JSON, return as-is
        return escapeHtml(text);
    }
}

export function renderDiff(baseline, current) {
    if (typeof Diff === 'undefined') {
        return highlightHTTP(current);
    }

    const diff = Diff.diffLines(baseline, current);
    let html = '<pre style="margin: 0; padding: 10px; font-family: monospace; font-size: 12px; line-height: 1.5;">';

    diff.forEach(part => {
        const lines = part.value.split('\n');
        lines.forEach((line, idx) => {
            if (idx === lines.length - 1 && line === '') return; // Skip trailing empty line

            if (part.added) {
                html += `<div class="diff-add">+ ${escapeHtml(line)}</div>`;
            } else if (part.removed) {
                html += `<div class="diff-remove">- ${escapeHtml(line)}</div>`;
            } else {
                html += `<div>  ${escapeHtml(line)}</div>`;
            }
        });
    });

    html += '</pre>';
    return html;
}

export async function copyToClipboard(text, btn) {
    try {
        // Try modern API first
        await navigator.clipboard.writeText(text);
        showCopySuccess(btn);
    } catch (err) {
        console.warn('Clipboard API failed, trying fallback:', err);

        // Fallback: create temporary textarea
        try {
            const textArea = document.createElement('textarea');
            textArea.value = text;

            // Ensure it's not visible but part of DOM
            textArea.style.position = 'fixed';
            textArea.style.left = '-9999px';
            textArea.style.top = '0';
            document.body.appendChild(textArea);

            textArea.focus();
            textArea.select();

            const successful = document.execCommand('copy');
            document.body.removeChild(textArea);

            if (successful) {
                showCopySuccess(btn);
            } else {
                throw new Error('execCommand copy failed');
            }
        } catch (fallbackErr) {
            console.error('Copy failed:', fallbackErr);
            // Show error state on button
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" fill="#f28b82"/></svg>';
            setTimeout(() => {
                btn.innerHTML = originalHtml;
            }, 1500);
        }
    }
}

function showCopySuccess(btn) {
    const originalHtml = btn.innerHTML;
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" fill="#81c995"/></svg>';

    setTimeout(() => {
        btn.innerHTML = originalHtml;
    }, 1500);
}
