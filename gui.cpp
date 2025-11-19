#include <windows.h>
#include <string>

// event handler declaration
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);


// Global handles for back button
HWND hBackButton;

// Global handles for UI controls
HWND hButtonScreen1;
HWND hButtonScreen2;
HWND hButtonScreen3;

// Global handles for "screens"
HWND hScreen1Label;
HWND hScreen2Label;
HWND hScreen3Label;

// Current screen index
int currentScreen = 0; // 0 = main, 1 = screen1, 2 = screen2, 3 = screen3

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    // Register window class
    const char CLASS_NAME[] = "MyWin32Class";

    WNDCLASS wc = {};
    wc.lpfnWndProc   =  WindowProc;                         // the function that handles messages (callback for messages)
    wc.hInstance     =  hInstance;                          // this app instance 
    wc.lpszClassName =  CLASS_NAME;                         // the name of the window class
    wc.hCursor       =  LoadCursor(NULL, IDC_ARROW);        // normal arrow cursor
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);          // automatically updated background to update obsolete pixels (for dynamically changing size of window)

    RegisterClass(&wc);

    // Create window
    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, "Win32 Screen Switch Example",
        WS_OVERLAPPEDWINDOW,                               // this style ENABLES resizing automatically
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
        NULL, NULL, hInstance, NULL
    );

    // obviously show window
    ShowWindow(hwnd, nCmdShow);

    //everything above is init and this is the only thing that is ran until exe closed
    // Message loop (receives messages from windows os like: mouse clicks, key presses, button clicks, and move window events)
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg); // sends message to WindowProc
    }

    return 0;
}

// event handler definition
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        // case 1 when window is being created
        case WM_CREATE:
        {
            // Main screen buttons
            hButtonScreen1 = CreateWindow("BUTTON", "Go to Screen 1",
                                          WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                          20, 20, 120, 30, hwnd, (HMENU)1, NULL, NULL);

            hButtonScreen2 = CreateWindow("BUTTON", "Go to Screen 2",
                                          WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                          20, 60, 120, 30, hwnd, (HMENU)2, NULL, NULL);

            hButtonScreen3 = CreateWindow("BUTTON", "Go to Screen 3",
                                          WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                                          20, 100, 120, 30, hwnd, (HMENU)3, NULL, NULL);

            // Back button (hidden initially)
            hBackButton = CreateWindow("BUTTON", "Back",
                                    WS_CHILD | BS_DEFPUSHBUTTON,
                                    20, 150, 100, 30, hwnd, (HMENU)4, NULL, NULL);
            ShowWindow(hBackButton, SW_HIDE);


            // Placeholder labels for each screen
            hScreen1Label = CreateWindow("STATIC", "Screen 1",
                                         WS_CHILD, 200, 50, 200, 30, hwnd, NULL, NULL, NULL);

            hScreen2Label = CreateWindow("STATIC", "Screen 2",
                                         WS_CHILD, 200, 50, 200, 30, hwnd, NULL, NULL, NULL);

            hScreen3Label = CreateWindow("STATIC", "Screen 3",
                                         WS_CHILD, 200, 50, 200, 30, hwnd, NULL, NULL, NULL);

            // Hide all screen labels initially
            ShowWindow(hScreen1Label, SW_HIDE);
            ShowWindow(hScreen2Label, SW_HIDE);
            ShowWindow(hScreen3Label, SW_HIDE);

            return 0;
        }

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            HBRUSH hBrush = CreateSolidBrush(RGB(0, 120, 255));  // create brush and assign to variable
            FillRect(hdc, &ps.rcPaint, hBrush);                   // use brush
            DeleteObject(hBrush);                                 // delete brush immediately

            EndPaint(hwnd, &ps);
            return 0;
        }

        // ⬇⬇⬇ NEW: THIS HANDLES WINDOW RESIZING ⬇⬇⬇
        case WM_SIZE:
        {
            // lParam contains width in LOWORD and height in HIWORD
            int newWidth  = LOWORD(lParam);
            int newHeight = HIWORD(lParam);

            // -------------------------------
            // LAYOUT LOGIC:
            // MoveWindow() allows reposition + resize of ANY control.
            //
            // We'll:
            // - keep the main buttons on the left
            // - keep screen labels in center
            //
            // NOTE: You can design any layout rules you want here.
            // -------------------------------

            int margin = 20;

            // Position main buttons vertically on the left
            MoveWindow(hButtonScreen1, margin, margin, 120, 30, TRUE);
            MoveWindow(hButtonScreen2, margin, 60 + margin, 120, 30, TRUE);
            MoveWindow(hButtonScreen3, margin, 100 + margin, 120, 30, TRUE);

            // Center screen labels horizontally
            MoveWindow(hScreen1Label, newWidth / 2 - 100, newHeight / 2 - 15, 200, 30, TRUE);
            MoveWindow(hScreen2Label, newWidth / 2 - 100, newHeight / 2 - 15, 200, 30, TRUE);
            MoveWindow(hScreen3Label, newWidth / 2 - 100, newHeight / 2 - 15, 200, 30, TRUE);
            // Back button position (bottom left)
            MoveWindow(hBackButton, margin, newHeight - 60, 100, 30, TRUE);

            return 0; // indicate message handled
        }
        // ⬆⬆⬆ END RESIZE HANDLING ⬆⬆⬆

        // case when button is clicked
        case WM_COMMAND:
        {
            // wParam contains the control ID
            int id = LOWORD(wParam);

            switch (id)
            {
                case 1: // Go to Screen 1
                    ShowWindow(hButtonScreen1, SW_HIDE);
                    ShowWindow(hButtonScreen2, SW_HIDE);
                    ShowWindow(hButtonScreen3, SW_HIDE);
                    ShowWindow(hBackButton, SW_SHOW);  // <- add this line


                    ShowWindow(hScreen1Label, SW_SHOW);
                    currentScreen = 1;
                    break;

                case 2: // Go to Screen 2
                    ShowWindow(hButtonScreen1, SW_HIDE);
                    ShowWindow(hButtonScreen2, SW_HIDE);
                    ShowWindow(hButtonScreen3, SW_HIDE);
                    ShowWindow(hBackButton, SW_SHOW);  // <- add this line

                    ShowWindow(hScreen2Label, SW_SHOW);
                    currentScreen = 2;
                    break;

                case 3: // Go to Screen 3
                    ShowWindow(hButtonScreen1, SW_HIDE);
                    ShowWindow(hButtonScreen2, SW_HIDE);
                    ShowWindow(hButtonScreen3, SW_HIDE);
                    ShowWindow(hBackButton, SW_SHOW);  // <- add this line

                    ShowWindow(hScreen3Label, SW_SHOW);
                    currentScreen = 3;
                    break;


                case 4: // Back to home
                        ShowWindow(hScreen1Label, SW_HIDE);
                        ShowWindow(hScreen2Label, SW_HIDE);
                        ShowWindow(hScreen3Label, SW_HIDE);
                        ShowWindow(hBackButton, SW_HIDE);

                        ShowWindow(hButtonScreen1, SW_SHOW);
                        ShowWindow(hButtonScreen2, SW_SHOW);
                        ShowWindow(hButtonScreen3, SW_SHOW);

                        currentScreen = 0;
                        break;
                            }

                            return 0;
                        }

        // case when window is destroyed
        case WM_DESTROY:
            PostQuitMessage(0); // while loop in WinMain receives terminating message
            return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
