const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const app = express();

// ════════════════════════════════════════════════════════════
//  ★ EDITABLE CONFIG
// ════════════════════════════════════════════════════════════
const PROXY_PASSWORD = process.env.PROXY_PASSWORD || 'changeme';
// ════════════════════════════════════════════════════════════

app.use(cors());
app.use(express.json());
app.set('trust proxy', true);

// ── Auth middleware ───────────────────────────────────────────────────────────
function checkAuth(req, res, next) {
  const pw = req.headers['x-proxy-password'] || req.query.password;
  if (pw !== PROXY_PASSWORD) return res.status(403).json({ error: 'Unauthorized' });
  next();
}

// ── Fetch helper ──────────────────────────────────────────────────────────────
function fetchUrl(targetUrl, headers = {}) {
  return new Promise((resolve, reject) => {
    try {
      const parsed = new URL(targetUrl);
      const lib = parsed.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'identity',
          'Connection': 'close',
          'Host': parsed.hostname,
          ...headers
        },
        timeout: 15000,
        rejectUnauthorized: false // allow self-signed certs
      };

      const reqObj = lib.request(options, (response) => {
        // Handle redirects
        if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
          let redirectUrl = response.headers.location;
          if (redirectUrl.startsWith('/')) {
            redirectUrl = `${parsed.protocol}//${parsed.hostname}${redirectUrl}`;
          } else if (!redirectUrl.startsWith('http')) {
            redirectUrl = `${parsed.protocol}//${parsed.hostname}/${redirectUrl}`;
          }
          return fetchUrl(redirectUrl, headers).then(resolve).catch(reject);
        }

        let data = '';
        response.setEncoding('utf8');
        response.on('data', chunk => data += chunk);
        response.on('end', () => resolve({
          body: data,
          status: response.statusCode,
          contentType: response.headers['content-type'] || 'text/html',
          finalUrl: targetUrl
        }));
      });

      reqObj.on('timeout', () => { reqObj.destroy(); reject(new Error('Request timed out')); });
      reqObj.on('error', reject);
      reqObj.end();
    } catch(e) { reject(e); }
  });
}

// ── Rewrite HTML ─────────────────────────────────────────────────────────────
// Rewrites links/assets in fetched HTML so they route through the proxy
function rewriteHtml(html, baseUrl, serverUrl, password) {
  const base = new URL(baseUrl);
  const origin = `${base.protocol}//${base.hostname}`;

  function proxyUrl(url) {
    if (!url || url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:') || url.startsWith('#') || url.startsWith('mailto:')) return url;
    try {
      let absolute;
      if (url.startsWith('//')) absolute = base.protocol + url;
      else if (url.startsWith('/')) absolute = origin + url;
      else if (!url.startsWith('http')) absolute = origin + '/' + url;
      else absolute = url;
      return `${serverUrl}/proxy?url=${encodeURIComponent(absolute)}&password=${encodeURIComponent(password)}`;
    } catch { return url; }
  }

  // Inject base tag and proxy script at top of head
  const injectedScript = `
<script>
(function() {
  // Intercept link clicks to route through proxy
  document.addEventListener('click', function(e) {
    const a = e.target.closest('a');
    if (!a || !a.href) return;
    const href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) return;
    e.preventDefault();
    const msg = { type: 'proxy_navigate', url: a.href };
    window.parent.postMessage(msg, '*');
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    e.preventDefault();
    const form = e.target;
    const method = (form.method || 'get').toLowerCase();
    let action = form.action || window.location.href;
    if (method === 'get') {
      const params = new URLSearchParams(new FormData(form)).toString();
      action = action.split('?')[0] + (params ? '?' + params : '');
    }
    window.parent.postMessage({ type: 'proxy_navigate', url: action }, '*');
  }, true);
})();
<\/script>`;

  // Rewrite href and src attributes
  html = html
    .replace(/<head([^>]*)>/i, `<head$1>${injectedScript}`)
    // src attributes (images, scripts, iframes)
    .replace(/\s(src|href|action)=["']([^"']+)["']/gi, (match, attr, url) => {
      const proxied = proxyUrl(url.trim());
      return ` ${attr}="${proxied}"`;
    })
    // srcset
    .replace(/\ssrcset=["']([^"']+)["']/gi, (match, srcset) => {
      const rewritten = srcset.split(',').map(part => {
        const [url, size] = part.trim().split(/\s+/);
        return proxyUrl(url) + (size ? ' ' + size : '');
      }).join(', ');
      return ` srcset="${rewritten}"`;
    })
    // CSS url()
    .replace(/url\(["']?([^"')]+)["']?\)/gi, (match, url) => {
      return `url("${proxyUrl(url.trim())}")`;
    });

  return html;
}

// ── Main proxy route ──────────────────────────────────────────────────────────
app.get('/proxy', checkAuth, async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'No URL provided' });

  // Validate URL
  let parsed;
  try {
    parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.status(400).json({ error: 'Only HTTP and HTTPS URLs are supported' });
    }
  } catch(e) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Block localhost/private IPs to prevent SSRF
  const hostname = parsed.hostname;
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' ||
      hostname.startsWith('192.168.') || hostname.startsWith('10.') || hostname.startsWith('172.')) {
    return res.status(403).json({ error: 'Access to private networks is not allowed' });
  }

  try {
    const result = await fetchUrl(targetUrl);
    const contentType = result.contentType || '';

    // Only rewrite HTML responses — pass through CSS/images/etc directly
    if (contentType.includes('text/html')) {
      const serverUrl = `${req.protocol}://${req.get('host')}`;
      const rewritten = rewriteHtml(result.body, result.finalUrl, serverUrl, PROXY_PASSWORD);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.send(rewritten);
    } else if (contentType.includes('text/css') || contentType.includes('javascript') || contentType.includes('text/plain')) {
      res.setHeader('Content-Type', contentType);
      res.send(result.body);
    } else {
      // For binary content (images etc), redirect to original URL
      res.redirect(targetUrl);
    }
  } catch(e) {
    console.error('Proxy error:', e.message);
    if (e.message.includes('timed out')) {
      res.status(504).json({ error: 'The page took too long to load' });
    } else if (e.code === 'ENOTFOUND') {
      res.status(502).json({ error: `Could not find host: ${parsed.hostname}` });
    } else if (e.code === 'ECONNREFUSED') {
      res.status(502).json({ error: 'Connection refused by the target server' });
    } else {
      res.status(502).json({ error: `Failed to load page: ${e.message}` });
    }
  }
});

// Handle navigation messages from iframe
app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Proxy server running on port ${PORT}`));
