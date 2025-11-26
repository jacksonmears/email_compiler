import { RBTree } from "https://cdn.skypack.dev/bintrees";


class MessageInfo {
    constructor(msg) {
        this.internalDate = msg.internalDate ?? 0;
        this.id = msg.id ?? "";
        this.labelIds = msg.labelIds ?? [];
        this.from = msg.from ?? "";
        this.to = msg.to ?? "";
        this.bodyPlain = msg.bodyPlain ?? "";
        this.bodyHtml = msg.bodyHtml ?? "";
    }
}

class ThreadInfo {
    constructor(thread) {
        this.threadId = thread.threadId ?? "";
        this.threadDate = thread.threadDate ?? 0;
        this.threadSubject = thread.threadSubject ?? "";
        this.readThread = thread.readThread ?? false;
        this.unsubscribeLink = thread.unsubscribeLink ?? "";
        this.token = thread.token ?? "";
        this.messages = (thread.messages ?? []).map(msg => new MessageInfo(msg));
    }
}




/**
 * Create a new RBTree with descending threadDate order
 */
function createThreadTree() {
    return new RBTree((a, b) => b.threadDate - a.threadDate);
}

/**
 * Fill a tree from an array of threads
 * @param {RBTree} tree
 * @param {Array} threads
 */
function fillTree(tree, threads) {
    threads.forEach(thread => {
        tree.insert({
            id: thread.id,
            threadDate: thread.threadDate
        });
    });
}

/**
 * Initialize all inbox and label trees from fetched JSON
 * @param {Object} data - fetched JSON
 */
function buildTrees(data) {
    const inboxBuckets = data.buckets.inbox;
    const labelBuckets = data.buckets.labels;

    // --- Inbox trees ---
    const inboxTrees = {
        Primary: createThreadTree(),
        Promotions: createThreadTree(),
        Social: createThreadTree(),
        Forums: createThreadTree()
    };

    Object.entries(inboxBuckets).forEach(([bucketName, threads]) => {
        if (inboxTrees[bucketName]) {
            fillTree(inboxTrees[bucketName], threads);
        }
    });

    // --- Label trees ---
    const labelTrees = {
        Starred: createThreadTree(),
        Important: createThreadTree(),
        Spam: createThreadTree(),
        Sent: createThreadTree(),
        Draft: createThreadTree(),
        Chat: createThreadTree(),
        Snoozed: createThreadTree(),
        Trash: createThreadTree()
    };

    Object.entries(labelBuckets).forEach(([labelName, threads]) => {
        if (labelTrees[labelName]) {
            fillTree(labelTrees[labelName], threads);
        }
    });

    return { inboxTrees, labelTrees };
}



function fetchThreadsMap(data) {
    const threadMap = new Map();

    Object.values(data.threads).forEach(threadJson => {
        const thread = new ThreadInfo(threadJson);
        threadMap.set(thread.threadId, thread);
    });

    return threadMap; // Map<string, ThreadInfo>
}








// function renderThreadDetail(thread) {
//     const list = document.getElementById('thread-list');
//     const detail = document.getElementById('thread-detail');

//     // Hide the inbox list
//     list.style.display = "none";

//     // Show the detail container
//     detail.style.display = "block";

//     detail.innerHTML = `
//         <button class="back-btn" id="back-to-list">← Back</button>

//         <h2>Thread Debug View</h2>
//         <pre style="
//             margin-top: 12px;
//             background:#f5f5f5;
//             padding:12px;
//             border-radius:8px;
//             white-space:pre-wrap;
//             word-wrap:break-word;
//         ">${JSON.stringify(thread, null, 2)}</pre>
//     `;

//     // Back button restores list
//     document.getElementById('back-to-list').addEventListener('click', () => {
//         detail.style.display = "none";
//         list.style.display = "block";
//     });
// }


function decodeB64UrlUtf8(str) {
    if (!str) return "";
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';

    // decode Base64 → binary string
    let binary = atob(str);

    // binary → UTF-8 string
    let utf8 = '';
    for (let i = 0; i < binary.length; i++) {
        utf8 += String.fromCharCode(binary.charCodeAt(i));
    }

    try {
        return decodeURIComponent(escape(utf8));
    } catch {
        return utf8;
    }
}


function extractGmailNewHtml(html, isFirstMessage) {
    if (!html || isFirstMessage) return html;   // Keep first message unchanged

    let lower = html.toLowerCase();

    // List of Gmail quote markers
    const markers = [
        '<div class="gmail_quote',
        '<div class="gmail_quote_container',
        '<blockquote class="gmail_quote',
        '<div class="gmail_attr"',
        '>on ',                            // fallback for inline: ">On Tue..."
        '\non ',                           // fallback in plain text
    ];

    // Find earliest marker
    let cutIndex = -1;
    for (const m of markers) {
        let idx = lower.indexOf(m);
        if (idx !== -1 && (cutIndex === -1 || idx < cutIndex)) {
            cutIndex = idx;
        }
    }

    // If nothing found → return whole HTML
    if (cutIndex === -1) return html;

    // Return only new content BEFORE quoted history
    return html.slice(0, cutIndex).trim();
}




function renderThreadDetail(thread) {
    const list = document.getElementById('thread-list');
    const detail = document.getElementById('thread-detail');

    list.style.display = "none";
    detail.style.display = "block";

    const subject = thread.threadSubject || "(No Subject)";
    const hasRead = thread.readThread || false;

    let msgsHtml = "";
    thread.messages.forEach((msg, i) => {
    const dateStr = new Date(msg.internalDate)
        .toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: 'numeric' });

    msgsHtml += `
        <div class="message-block">
            <div class="msg-header">
                <div class="msg-header-line1">
                    <span class="from">
                        <strong>From:</strong> ${msg.from}
                        ${thread.unsubscribeLink ? `<button class="unsubscribe-btn" onclick="window.open('${thread.unsubscribeLink}', '_blank')">Unsubscribe</button>` : ''}
                    </span>
                    <span class="date"><strong>Date:</strong> ${dateStr}</span>
                </div>
                <div class="msg-header-line2">
                    <span class="to"><strong>To:</strong> ${msg.to}</span>
                </div>
            </div>

            <div></div>

            <div class="msg-body">
                ${msg.bodyHtml 
                    ? `<iframe class="msg-body-iframe" id="iframe-${i}" sandbox="allow-same-origin"></iframe>` 
                    : msg.bodyPlain 
                        ? `<pre class="plain-body">${decodeB64UrlUtf8(msg.bodyPlain)}</pre>` 
                        : "<em>(no message content)</em>"
                }
            </div>
        </div>
    `;
});


    detail.innerHTML = `
        <button class="back-btn" id="back-to-list">← Back</button>
        <h1 class="email-subject">${subject}</h1>
        <div class="thread-container">
            ${msgsHtml}
        </div>
    `;

    // Populate iframes and auto-resize
    thread.messages.forEach((msg, i) => {
        if (msg.bodyHtml) {
            const iframe = document.getElementById(`iframe-${i}`);
            if (iframe) {
                const doc = iframe.contentDocument || iframe.contentWindow.document;
                doc.open();
                doc.write(extractGmailNewHtml(decodeB64UrlUtf8(msg.bodyHtml)));  // ✅ Use UTF-8 decoder here
                doc.close();

                const resizeIframe = () => {
                    iframe.style.width = "100%";
                    iframe.style.height = iframe.contentWindow.document.body.scrollHeight + "px";
                };

                resizeIframe();
                setTimeout(resizeIframe, 50);
                setTimeout(resizeIframe, 300);

                const observer = new MutationObserver(resizeIframe);
                observer.observe(doc.body, { childList: true, subtree: true, characterData: true });
            }
        }
    });

    // Back button
    document.getElementById('back-to-list').addEventListener('click', () => {
        detail.style.display = "none";
        list.style.display = "block";
    });
}





// fetch('api/threads')
//     .then(res => res.json())
//     .then(data => {
//         const { inboxTrees, labelTrees } = buildTrees(data);

//         // Example: print all Primary inbox threads (descending order)
//         console.log("Primary Inbox Threads:");
//         inboxTrees.Primary.each(thread => {
//             console.log(thread.id, thread.threadDate);
//         });

//         // Example: print Starred label threads
//         console.log("Starred Threads:");
//         labelTrees.Starred.each(thread => console.log(thread.id, thread.threadDate));
//     })
//     .catch(err => console.error(err));



fetch('api/threads')
    .then(res => res.json())
    .then(data => {
        const threadList = document.getElementById('thread-list');
        if (!threadList) return;

        const { inboxTrees } = buildTrees(data);
        const threadsMap = fetchThreadsMap(data);

        threadList.innerHTML = ""; // clear any existing content

        // Render all Primary inbox threads
        inboxTrees.Primary.each(threadSummary => {
            // Lookup full thread info
            const thread = threadsMap.get(threadSummary.id);
            if (!thread || thread.messages.length === 0) return;

            // Get most recent message (last in array)
            const lastMsg = thread.messages[thread.messages.length - 1];

            const div = document.createElement('div');

            const isUnread = !thread.readThread;
            div.className = "email-thread" + (isUnread ? " unread-thread" : " read-thread");
            div.innerHTML = `
                <span class="from">
                    ${isUnread ? '<span class="unread-dot"></span>' : ''}
                    ${lastMsg.from}
                </span>
                <span class="to">${lastMsg.to}</span>
                <span class="subject">${thread.threadSubject}</span>
                <span class="date">${new Date(thread.threadDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>
            `;
            threadList.appendChild(div);

            div.addEventListener('click', () => {

                renderThreadDetail(thread);
            });
        });
    })
    .catch(err => console.error(err));







