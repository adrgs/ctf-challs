const Redis = require("ioredis")
const puppeteer = require("puppeteer")

const USERNAME = 'admin@hacktm.ro';
const PASSWORD = process.env.ADMIN_PASSWORD;
const BASE_URL = 'http://' + process.env.APP_HOST + '/';
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = 6379;
const TIMEOUT = 5000;

const redis = new Redis({
    host: REDIS_HOST,
    port: REDIS_PORT
})

let browser;
let page;

const crawl = async (path) => {
    try {
        browser = await puppeteer.launch({
            args: [
              "--no-sandbox",
              "--disable-background-networking",
              "--disk-cache-dir=/dev/null",
              "--disable-default-apps",
              "--disable-extensions",
              "--disable-desktop-notifications",
              "--disable-gpu",
              "--disable-sync",
              "--disable-translate",
              "--disable-dev-shm-usage",
              "--hide-scrollbars",
              "--metrics-recording-only",
              "--mute-audio",
              "--no-first-run",
              "--safebrowsing-disable-auto-update",
              "--window-size=1440,900",
            ],
        });

        page = await browser.newPage()

        await page.goto(BASE_URL + "login", {
            waitUntil: "networkidle2",
            timeout: 3000,
        });
        await page.type('input[name="email"]', USERNAME)
        await page.type('input[name="password"]', PASSWORD)
        await Promise.all([
            page.click('button[type="submit"]'),
            page.waitForNavigation({
                waitUntil: "networkidle2",
                timeout: TIMEOUT,
            })
        ])

        await page.goto(BASE_URL + path, {
            waitUntil: "networkidle2",
            timeout: TIMEOUT,
        })
        await page.close()

        await browser.close()
    } catch(e) {
        console.log(`[*] error(${path}): ${e}`)
    }
}

(async () => {    
    while (true) {
        console.log(
            "[*] progress: ",
            await redis.get("proceeded_count"),
            "/",
            await redis.get("queued_count")
        )
        await redis
            .blpop("query", 0)
            .then((v) => {
                const path = v[1];
                console.log(`[*] crawl ${path}`)
                return crawl(path)
            })
            .then(() => {
                return redis.incr("proceeded_count")
            })
    }
})()