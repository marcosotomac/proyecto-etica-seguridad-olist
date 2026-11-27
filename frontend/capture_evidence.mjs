// Capturas de evidencia sobre el servidor HTTPS real (py app.py run).
// Uso:
//   OLIST_ADMIN_USER=... OLIST_ADMIN_PASS=... OLIST_READER_USER=... OLIST_READER_PASS=... node capture_evidence.mjs
// Las credenciales solo se leen del entorno; nunca se escriben en el repositorio.
// Chrome confía únicamente en el certificado del servidor emitido por la CA propia (SPKI fijado).
import puppeteer from 'puppeteer-core'
import { X509Certificate, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '..')
const out = path.join(root, 'informe')
const base = process.env.OLIST_URL || 'https://127.0.0.1:5000'
const env = name => process.env[name] || (() => { throw new Error(`Falta la variable ${name}`) })()
const chrome = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

const cert = new X509Certificate(readFileSync(path.join(root, 'instance/pki/server.crt')))
const spki = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64')

const browser = await puppeteer.launch({
  executablePath: chrome, headless: true,
  args: [`--ignore-certificate-errors-spki-list=${spki}`],
  defaultViewport: { width: 1280, height: 800, deviceScaleFactor: 2 },
})

async function login(page, user, pass) {
  await page.goto(`${base}/login`, { waitUntil: 'networkidle2' })
  await page.type('input[name="username"]', user)
  await page.type('input[name="password"]', pass)
  await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle2' }), page.click('button[type="submit"]')])
}

const shot = (page, name, height) => page.screenshot({ path: path.join(out, name), clip: { x: 0, y: 0, width: 1280, height } })

const admin = await browser.newPage()
await login(admin, env('OLIST_ADMIN_USER'), env('OLIST_ADMIN_PASS'))
await admin.waitForFunction(() => /96[.,\s]470/.test(document.body.innerText))
await shot(admin, 'fig1_kpi_general.png', 780)
await admin.goto(`${base}/?state=MA`, { waitUntil: 'networkidle2' })
await admin.waitForFunction(() => /17[.,]4/.test(document.body.innerText))
await shot(admin, 'fig2_filtro_estado.png', 780)

const ctx = await browser.createBrowserContext()
const reader = await ctx.newPage()
await reader.setViewport({ width: 1280, height: 800, deviceScaleFactor: 2 })
await login(reader, env('OLIST_READER_USER'), env('OLIST_READER_PASS'))
const denied = await reader.goto(`${base}/audit`)
console.log('Lector en /audit:', denied.status())
await admin.goto(`${base}/audit`, { waitUntil: 'networkidle2' })
await shot(admin, 'fig3_auditoria_rbac.png', 760)

// Figura 4: salida textual real de scripts/verify_live.py (no es una maqueta).
const report = readFileSync(path.join(out, 'evidencias/verificacion-final.txt'), 'utf8')
const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
const body = esc(report).split('\n').map(l => l.startsWith('[OK') ? `<span class="ok">[OK ]</span>${l.slice(5)}` : l.startsWith('[FALLA') ? `<span class="ko">${l}</span>` : l).join('\n')
const term = await browser.newPage()
await term.setViewport({ width: 1280, height: 800, deviceScaleFactor: 2 })
await term.setContent(`<html><body style="margin:0;background:#0b0f19;padding:24px;font:13px/1.55 ui-monospace,Menlo,monospace;color:#e2e8f0">
<div style="color:#94a3b8;margin-bottom:10px">$ python scripts/verify_live.py</div><pre style="margin:0;white-space:pre-wrap">${body}</pre>
<style>.ok{color:#34d399;font-weight:700}.ko{color:#f87171}</style></body></html>`)
const height = await term.evaluate(() => document.body.scrollHeight)
await term.screenshot({ path: path.join(out, 'fig4_seguridad_recuperacion.png'), clip: { x: 0, y: 0, width: 1280, height } })
await browser.close()
console.log('Capturas actualizadas en informe/')
