// background.js - 负责管理图标状态

// Dynamic rule for exploit requests only.
// We add this rule right before an exploit and remove it immediately after.
// This prevents the Origin/Referer stripping from affecting normal site traffic
// (which was causing WebSocket/socket failures on sites like speedtest.net).
const EXPLOIT_RULE = {
    id: 1,
    priority: 1,
    action: {
        type: "modifyHeaders",
        requestHeaders: [
            { header: "Referer", operation: "set", value: "Referer-modified-value" },
            { header: "Origin", operation: "remove" }
        ]
    },
    condition: {
        urlFilter: "*",
        resourceTypes: ["xmlhttprequest"]
    }
};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    // Badge update when RSC is passively detected
    if (request.action === "update_badge" && sender.tab) {
        chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#FF0000" });
        chrome.action.setBadgeText({ tabId: sender.tab.id, text: "!" });
    }

    // Enable header-stripping rule right before exploit fires
    if (request.action === "exploit_start") {
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [1],
            addRules: [EXPLOIT_RULE]
        }, () => sendResponse({ ok: true }));
        return true; // async
    }

    // Remove rule immediately after exploit completes
    if (request.action === "exploit_end") {
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [1]
        }, () => sendResponse({ ok: true }));
        return true; // async
    }
});
