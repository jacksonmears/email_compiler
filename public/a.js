// ---------- Utilities ----------

// Clean and format "From" field with clickable grey email
function cleanFromField(from) {
    if (!from) return "";

    let cleaned = from.trim();
    const lastAngle = cleaned.lastIndexOf('<');
    if (lastAngle !== -1) {
        const name = cleaned.substring(0, lastAngle).trim();
        let email = cleaned.substring(lastAngle + 1, cleaned.length).replace('>', '').trim();
        return name;
        // return `${name} <a href="mailto:${email}" style="color: gray; text-decoration: none;">&lt;${email}&gt;</a>`;
    }
    return cleaned;
}


function cleanToField(from) {
    if (!from) return "";

    let cleaned = from.trim();
    const lastAngle = cleaned.lastIndexOf('<');
    if (lastAngle !== -1) {
        const name = cleaned.substring(0, lastAngle).trim();
        let email = cleaned.substring(lastAngle + 1, cleaned.length).replace('>', '').trim();
        return email;
        // return `${name} <a href="mailto:${email}" style="color: gray; text-decoration: none;">&lt;${email}&gt;</a>`;
    }
    return cleaned;
}

// Escape To field for HTML display
// function cleanToField(to) {
//     if (!to) return "";
//     return to
//         .replace(/&/g, "&amp;")
//         .replace(/</g, "&lt;")
//         .replace(/>/g, "&gt;").trim();
// }

// Decode Gmail Base64URL to UTF-8 string
function decodeBase64Url(encoded) {
    if (!encoded) return "";
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/');
    while (encoded.length % 4) encoded += '=';
    const str = atob(encoded);
    const bytes = Uint8Array.from(str, c => c.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
}

// ---------- DOM Elements ----------
const menuBtn = document.getElementById('menu-btn');
const sidebar = document.querySelector('.sidebar');
const threadContainer = document.getElementById('thread-list');

// ---------- Event Listeners ----------

// Toggle sidebar on small screens
menuBtn.addEventListener('click', () => {
    if (sidebar.style.display === 'flex') {
        sidebar.style.display = 'none';
    } else {
        sidebar.style.display = 'flex';
    }
});

// ---------- Render Inbox Threads ----------
function renderThreads(threads) {
    threadContainer.innerHTML = ''; // Clear existing threads

    threads.forEach(thread => {
        const newestMsg = thread.messages[thread.messages.length - 1];

        const threadDiv = document.createElement('div');
        threadDiv.classList.add('email-thread');

        const timestamp = Number(newestMsg.internalDate);
        const dateObj = new Date(timestamp);
        const options = { month: 'short', day: 'numeric' };
        const formattedDate = dateObj.toLocaleDateString('en-US', options);

        threadDiv.innerHTML = `
            <div class="from">${cleanFromField(newestMsg.from)}</div>
            <div class="to">${cleanToField(newestMsg.to)}</div>
            <div class="subject">${newestMsg.subject}</div>
            <div class="date">${formattedDate}</div>
        `;

        // Click on thread → render full thread
        threadDiv.addEventListener('click', () => {
            renderThreadMessages(thread);
        });

        threadContainer.appendChild(threadDiv);
    });
}

// ---------- Render Full Thread ----------
function renderThreadMessages(thread) {
    threadContainer.innerHTML = ''; // Clear inbox list

    // Back button
    const backBtn = document.createElement('button');
    backBtn.textContent = "← Back to Inbox";
    backBtn.className = 'back-btn';
    backBtn.addEventListener('click', () => {
        fetch('api/threads')
            .then(res => res.json())
            .then(threads => renderThreads(threads))
            .catch(err => console.error("Error fetching threads:", err));
    });
    threadContainer.appendChild(backBtn);

    // Render each message
    thread.messages.forEach(msg => {
        const msgDiv = document.createElement('div');
        msgDiv.classList.add('email-message');

        const timestamp = Number(msg.internalDate);
        const dateObj = new Date(timestamp);
        const formattedDate = dateObj.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

        const isHtml = !!msg.bodyHtml;
        const rawBody = isHtml ? decodeBase64Url(msg.bodyHtml) : decodeBase64Url(msg.bodyPlain);

        msgDiv.innerHTML = `
            <div class="header">
                <div class="from"><strong>From:</strong> ${cleanFromField(msg.from)}</div>
                <div class="to"><strong>To:</strong> ${cleanToField(msg.to)}</div>
                <div class="subject"><strong>Subject:</strong> ${msg.subject}</div>
                <div class="date">${formattedDate}</div>
            </div>
            <div class="body-container"></div>
        `;

        const bodyContainer = msgDiv.querySelector('.body-container');

        if (isHtml) {
            const iframe = document.createElement('iframe');
            iframe.style.width = '100%';
            iframe.style.border = 'none';
            iframe.style.minHeight = '200px';
            iframe.srcdoc = rawBody;

            // Resize iframe after it loads
            iframe.onload = () => {
                iframe.style.height = iframe.contentWindow.document.body.scrollHeight + 'px';
            };

            bodyContainer.appendChild(iframe);
        }
        else {
            // Plain text
            const p = document.createElement('div');
            p.className = 'body body-plain';
            p.textContent = rawBody || "(No content)";
            bodyContainer.appendChild(p);
        }

        threadContainer.appendChild(msgDiv);
    });

}



// ---------- Fetch Threads from Local API ----------
fetch('api/threads', { method: "GET" })
    .then(res => res.json())
    .then(threads => renderThreads(threads))
    .catch(err => console.error("Error fetching threads:", err));

