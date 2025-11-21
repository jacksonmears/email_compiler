// Fetch threads JSON from the server
fetch('http://localhost:8080')
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
        const header = document.createElement('div');
        header.classList.add('thread-header');
        header.textContent = `Thread ID: ${thread.threadId} | History ID: ${thread.historyId}`;
        threadDiv.appendChild(header);

        // Messages container
        const messagesDiv = document.createElement('div');
        messagesDiv.classList.add('messages');

        if (thread.messages.length === 0) {
            const emptyMsg = document.createElement('p');
            emptyMsg.textContent = "(No messages)";
            messagesDiv.appendChild(emptyMsg);
        }

        thread.messages.forEach(msg => {
            const msgDiv = document.createElement('div');
            msgDiv.classList.add('message');

            const from = document.createElement('p');
            from.textContent = `From: ${msg.from}`;
            msgDiv.appendChild(from);

            const to = document.createElement('p');
            to.textContent = `To: ${msg.to}`;
            msgDiv.appendChild(to);

            const subject = document.createElement('p');
            subject.textContent = `Subject: ${msg.subject}`;
            subject.classList.add('subject');
            msgDiv.appendChild(subject);

            const body = document.createElement('p');
            body.textContent = decodeBase64(msg.bodyPlain); // decode Base64URL
            body.classList.add('body');
            msgDiv.appendChild(body);

            messagesDiv.appendChild(msgDiv);
        });

        threadDiv.appendChild(messagesDiv);

        // Toggle messages on header click
        header.addEventListener('click', () => {
            messagesDiv.style.display = messagesDiv.style.display === 'none' ? 'block' : 'none';
        });

        container.appendChild(threadDiv);
    });
}

// Helper: decode Base64URL to readable text
function decodeBase64(base64url) {
    if (!base64url) return '';

    // Convert from Base64URL to standard Base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';

    try {
        return decodeURIComponent(escape(atob(base64)));
    } catch (e) {
        return "(Could not decode content)";
    }
}
