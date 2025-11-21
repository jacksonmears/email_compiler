#include <windows.h>
#include <string>
#include <vector>
#include "include/threadInfo2.h"
// #include <WebView2.h>

// ICoreWebView2* webView = nullptr;

// Globals
HWND hListBox;
HWND hBackButton;
std::vector<ThreadInfo> threadInfo;
bool showingThreadMessages = false;

// Forward declaration
void PopulateListBoxWithThreads();
void PopulateListBoxWithMessages(const ThreadInfo& threadInfo);

// Window procedure
LRESULT CALLBACK ThreadListWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_COMMAND:
        if ((HWND)lParam == hListBox && HIWORD(wParam) == LBN_DBLCLK)
        {
            int sel = (int)SendMessage(hListBox, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && !showingThreadMessages)
            {
                // User clicked a thread ID
                const ThreadInfo& t = threadInfo[sel];
                PopulateListBoxWithMessages(t);
            }
        }
        else if ((HWND)lParam == hBackButton)
        {
            // Go back to thread list
            PopulateListBoxWithThreads();
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Populate listbox with thread IDs
void PopulateListBoxWithThreads()
{
    SendMessage(hListBox, LB_RESETCONTENT, 0, 0);
    for (const auto& t : threadInfo) {
        std::string msg = t.messages[0].from + " " + t.messages[0].subject;
        SendMessage(hListBox, LB_ADDSTRING, 0, (LPARAM)msg.c_str());
    }

    showingThreadMessages = false;
    ShowWindow(hBackButton, SW_HIDE);
}

// Populate listbox with message IDs for a thread
void PopulateListBoxWithMessages(const ThreadInfo& thread)
{
    SendMessage(hListBox, LB_RESETCONTENT, 0, 0);
    for (const auto& m : thread.messages)
    {
        if (!m.id.empty()) {
            std::string msg;
            for (auto c : m.bodyHtml) msg += c;
            SendMessage(hListBox, LB_ADDSTRING, 0, (LPARAM)msg.c_str());
        }

    }

    showingThreadMessages = true;
    ShowWindow(hBackButton, SW_SHOW);
}

// Main GUI
void ShowThreadListGUI(std::vector<ThreadInfo>& threadResults)
{
    threadInfo = threadResults;
    HINSTANCE hInstance = GetModuleHandle(NULL);
    const char CLASS_NAME[] = "ThreadListClass";

    WNDCLASS wc = {};
    wc.lpfnWndProc = ThreadListWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        "Gmail Threads",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 1200,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return;

    hListBox = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        "LISTBOX",
        "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
        10, 10, 780, 1120,  // fits within 800x1200 client area
        hwnd, NULL, hInstance, NULL
    );

    hBackButton = CreateWindowEx(
        0, "BUTTON", "Back",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        10, 1140, 100, 30, // placed below listbox
        hwnd, NULL, hInstance, NULL
    );
    ShowWindow(hBackButton, SW_HIDE);


    PopulateListBoxWithThreads();

    ShowWindow(hwnd, SW_SHOW);

    MSG msg{};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
