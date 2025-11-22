function cleanFromField(from) {
    // Split multiple senders by newline, take the last sender
    const parts = from.split(/\r?\n/);
    let last = parts[parts.length - 1].trim();

    // Remove non-breaking spaces and weird whitespace
    last = last.replace(/\s+/g, ' ').replace(/\u00A0/g, ' ');

    // Ensure format: Name <email>
    const match = last.match(/"?([^"]*)"?\s*<([^>]+)>/);
    if (match) {
        const name = match[1].trim() || match[2]; // fallback to email
        const email = match[2].trim();
        return `${name} <${email}>`;
    }
    return last; // fallback if parsing fails
}





document.getElementById("shutdown-btn").addEventListener("click", () => {
    fetch("/shutdown", { method: "POST" })
        .then(() => {
            window.close(); // Will work if triggered by click event
        });
});



// Fetch threads JSON from the server
fetch('api/threads', { method: "GET" })
    .then(res => res.json())
    .then(threads => renderThreads(threads))
    .catch(err => console.error("Error fetching threads:", err));

function renderThreads(threads) {
    const container = document.getElementById('thread-list');
    container.innerHTML = '';

    threads.forEach(thread => {
        const threadDiv = document.createElement('div');
        threadDiv.classList.add('thread');




        // Thread header
        // const header = document.createElement('div');
        // header.classList.add('thread-header');
        // header.textContent = `Thread ID: ${thread.threadId} | History ID: ${thread.historyId}`;
        // threadDiv.appendChild(header);

        // console.log("Newest Message Debug:");
        // console.log("FROM: [" + newestMsg.from + "]");
        // console.log("TO:   [" + newestMsg.to + "]");
        // console.log("SUBJ: [" + newestMsg.subject + "]");


        // Use the newest message in the thread
        const newestMsg = thread.messages[thread.messages.length - 1];

        // console.log("Newest Message Debug:");
        // console.log("FROM: [" + newestMsg.from + "]");
        // console.log("TO:   [" + newestMsg.to + "]");
        // console.log("SUBJ: [" + newestMsg.subject + "]");

        const header = document.createElement('div');
        header.classList.add('thread-header');

        // Multi-line display using innerHTML + <br>
        header.innerHTML = `
            <p><strong>From:</strong> ${cleanFromField(newestMsg.from)}</p>
            <p><strong>To:</strong> ${newestMsg.to}</p>
            <p><strong>Subject:</strong> ${newestMsg.subject}</p>
        `;

        // header.innerHTML = `
        //     <strong>From:</strong> ${newestMsg.from}<br>
        //     <strong>To:</strong> ${newestMsg.to}<br>
        //     <strong>Subject:</strong> ${newestMsg.subject}
        // `;


        threadDiv.appendChild(header);







        // Messages container
        const messagesDiv = document.createElement('div');
        messagesDiv.classList.add('messages');

        if (!thread.messages || thread.messages.length === 0) {
            messagesDiv.innerHTML = "<p>(No messages)</p>";
        }

        thread.messages.forEach(msg => {
            const msgDiv = document.createElement('div');
            msgDiv.classList.add('message');

            msgDiv.innerHTML += `<p>From: ${msg.from}</p>`;
            msgDiv.innerHTML += `<p>To: ${msg.to}</p>`;
            msgDiv.innerHTML += `<p class="subject">Subject: ${msg.subject}</p>`;

            const bodyDiv = document.createElement('div');
            bodyDiv.classList.add('body');

            // Prefer HTML body — fallback to plain text
            const decodedHtml = msg.bodyHtml ? decodeBase64Url(msg.bodyHtml) : null;
            const decodedText = msg.bodyPlain ? decodeBase64Url(msg.bodyPlain) : "(No content)";

            if (decodedHtml) {
                // Sanitize ➜ Render HTML
                bodyDiv.innerHTML = DOMPurify.sanitize(decodedHtml);
            } else {
                // Render text safely
                bodyDiv.textContent = decodedText;
            }

            msgDiv.appendChild(bodyDiv);
            messagesDiv.appendChild(msgDiv);
        });

        threadDiv.appendChild(messagesDiv);

        // Toggle messages on header click
        header.addEventListener('click', () => {
            messagesDiv.style.display =
                messagesDiv.style.display === 'none' ? 'block' : 'none';
        });

        container.appendChild(threadDiv);
    });
}

// Gmail Base64URL decoding (UTF-8 safe)
function decodeBase64Url(encoded) {
    if (!encoded) return "";

    // Convert base64url → base64
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/');

    // Add missing padding
    while (encoded.length % 4) {
        encoded += '=';
    }

    // Decode base64 → bytes
    const str = atob(encoded);
    const bytes = Uint8Array.from(str, c => c.charCodeAt(0));

    // Convert UTF-8 bytes → string
    return new TextDecoder('utf-8').decode(bytes);
}
