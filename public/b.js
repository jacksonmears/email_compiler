
// var RBTree = require('bintrees').RBTree;
 
// const tree = new RBTree((a, b) => b.date - a.date);

 
// tree.insert(2);
// tree.insert(-3);




// ---------- Fetch Threads from Local API ----------
fetch('api/threads')
  .then(res => res.json())
  .then(data => {
    const threadList = document.getElementById('thread-list');
    if (!threadList) return;

    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify(data, null, 2); // pretty JSON
    pre.style.whiteSpace = "pre-wrap"; // wrap long lines
    threadList.appendChild(pre);
  })
  .catch(err => console.error(err));






// fetch('api/threads', { method: "GET" })
//     .then(res => res.json())
//     .then(data => {
//         // Separate out the buckets
//         const inboxBuckets = data.buckets.inbox;
//         const labelBuckets = data.buckets.labels;

//         // For easier access, we can create a map from bucket name to array of thread IDs
//         const inbox = {
//             Primary: new Set(inboxBuckets.Primary || []),
//             Promotions: new Set(inboxBuckets.Promotions || []),
//             Social: new Set(inboxBuckets.Social || []),
//             Forums: new Set(inboxBuckets.Forums || [])
//         };

//         const labels = {
//             Important: new Set(labelBuckets.Important || []),
//             Starred: new Set(labelBuckets.Starred || []),
//             Sent: new Set(labelBuckets.Sent || []),
//             Draft: new Set(labelBuckets.Draft || []),
//             Spam: new Set(labelBuckets.Spam || []),
//             Chat: new Set(labelBuckets.Chat || []),
//             Snoozed: new Set(labelBuckets.Snoozed || []),
//             Trash: new Set(labelBuckets.Trash || [])
//         };


//         // Store all threads details
//         const threads = data.threads;

//         // Example: render Primary inbox threads
//         const threadList = document.getElementById('thread-list');
//         if (threadList) {
//             threadList.innerHTML = ''; // clear first

//             inbox.Primary.forEach(threadId => {
//                 const thread = threads[threadId];
//                 if (!thread) return;

//                 thread.messages.forEach(msg => {
//                     const div = document.createElement('div');
//                     div.className = 'thread-item';
//                     div.innerHTML = `
//                         <strong>From:</strong> ${msg.from} <br>
//                         <strong>To:</strong> ${msg.to} <br>
//                         <strong>Subject:</strong> ${msg.subject} <br>
//                         <strong>Labels:</strong> ${msg.labelIds.join(', ')} <br>
//                         <hr>
//                     `;
//                     threadList.appendChild(div);
//                 });
//             });
//         }

//         // You can repeat for other inbox / label buckets
//         console.log({ inbox, labels, threads });
//     })
//     .catch(err => console.error(err));
