import { RBTree } from "https://cdn.skypack.dev/bintrees";


class MessageInfo {
    constructor(msg) {
        this.read = msg.read ?? true;
        this.internalDate = msg.internalDate ?? 0;
        this.id = msg.id ?? "";
        this.labelIds = msg.labelIds ?? [];
        this.from = msg.from ?? "";
        this.to = msg.to ?? "";
        this.subject = msg.subject ?? "";
        this.bodyPlain = msg.bodyPlain ?? "";
        this.bodyHtml = msg.bodyHtml ?? "";
    }
}

class ThreadInfo {
    constructor(thread) {
        this.threadId = thread.threadId ?? "";
        this.threadDate = thread.threadDate ?? 0;
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
            div.className = "email-thread";
            div.innerHTML = `
                <span class="from">${lastMsg.from}</span>
                <span class="to">${lastMsg.to}</span>
                <span class="subject">${lastMsg.subject}</span>
                <span class="date">${new Date(lastMsg.internalDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>
            `;
            threadList.appendChild(div);

            threadList.appendChild(div);
        });
    })
    .catch(err => console.error(err));

