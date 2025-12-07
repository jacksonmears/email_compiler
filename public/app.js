function syntaxHighlight(json) {
    json = JSON.stringify(json, null, 4);

    return json
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(?=\s*:))/g, '<span class="key">$1</span>')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*")/g, '<span class="string">$1</span>')
        .replace(/\b(true|false)\b/g, '<span class="boolean">$1</span>')
        .replace(/\b(null)\b/g, '<span class="null">$1</span>')
        .replace(/\b(\d+|\d+\.\d+)\b/g, '<span class="number">$1</span>');
}

fetch("/playerInfo")
    .then(res => res.json())
    .then(data => {
        document.getElementById("jsonContainer").innerHTML = syntaxHighlight(data);
    })
    .catch(err => {
        document.getElementById("jsonContainer").textContent = "Error loading JSON: " + err;
    });
