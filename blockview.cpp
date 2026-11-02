#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// ==================== 简单 SHA256 实现 ====================
class SHA256 {
public:
    void init() {
        m_h[0] = 0x6a09e667; m_h[1] = 0xbb67ae85; m_h[2] = 0x3c6ef372; m_h[3] = 0xa54ff53a;
        m_h[4] = 0x510e527f; m_h[5] = 0x9b05688c; m_h[6] = 0x1f83d9ab; m_h[7] = 0x5be0cd19;
        m_len = 0; m_tot = 0;
    }
    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            m_buf[m_len++] = data[i];
            if (m_len == 64) { transform(); m_tot += 512; m_len = 0; }
        }
    }
    void final(uint8_t hash[32]) {
        uint64_t bits = m_tot + m_len * 8;
        m_buf[m_len++] = 0x80;
        if (m_len > 56) { while (m_len < 64) m_buf[m_len++] = 0; transform(); m_len = 0; }
        while (m_len < 56) m_buf[m_len++] = 0;
        for (int i = 7; i >= 0; --i) m_buf[m_len++] = (bits >> (i * 8)) & 0xff;
        transform();
        for (int i = 0; i < 8; ++i) {
            hash[i * 4] = (m_h[i] >> 24) & 0xff;
            hash[i * 4 + 1] = (m_h[i] >> 16) & 0xff;
            hash[i * 4 + 2] = (m_h[i] >> 8) & 0xff;
            hash[i * 4 + 3] = m_h[i] & 0xff;
        }
    }
private:
    uint32_t m_h[8], m_w[64];
    uint8_t m_buf[64];
    size_t m_len; uint64_t m_tot;
    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    void transform() {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        for (int i = 0; i < 16; ++i)
            m_w[i] = (m_buf[i * 4] << 24) | (m_buf[i * 4 + 1] << 16) | (m_buf[i * 4 + 2] << 8) | m_buf[i * 4 + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(m_w[i - 15], 7) ^ rotr(m_w[i - 15], 18) ^ (m_w[i - 15] >> 3);
            uint32_t s1 = rotr(m_w[i - 2], 17) ^ rotr(m_w[i - 2], 19) ^ (m_w[i - 2] >> 10);
            m_w[i] = m_w[i - 16] + s0 + m_w[i - 7] + s1;
        }
        uint32_t a = m_h[0], b = m_h[1], c = m_h[2], d = m_h[3], e = m_h[4], f = m_h[5], g = m_h[6], h = m_h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + k[i] + m_w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        m_h[0] += a; m_h[1] += b; m_h[2] += c; m_h[3] += d; m_h[4] += e; m_h[5] += f; m_h[6] += g; m_h[7] += h;
    }
};

void DoubleSHA256(const uint8_t* data, size_t len, uint8_t out[32]) {
    SHA256 sha;
    uint8_t tmp[32];
    sha.init(); sha.update(data, len); sha.final(tmp);
    sha.init(); sha.update(tmp, 32); sha.final(out);
}

// ==================== 工具函数 ====================
std::string toHex(const uint8_t* data, size_t len, bool reverse = false) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    if (reverse)
        for (int i = (int)len - 1; i >= 0; --i) ss << std::setw(2) << (int)data[i];
    else
        for (size_t i = 0; i < len; ++i) ss << std::setw(2) << (int)data[i];
    return ss.str();
}

uint64_t ReadVarInt(const uint8_t*& p, const uint8_t* end) {
    if (p >= end) return 0;
    uint8_t prefix = *p++;
    if (prefix < 0xfd) return prefix;
    if (prefix == 0xfd && p + 2 <= end) { uint64_t v = p[0] | (p[1] << 8); p += 2; return v; }
    if (prefix == 0xfe && p + 4 <= end) { uint64_t v = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); p += 4; return v; }
    if (prefix == 0xff && p + 8 <= end) {
        uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i] << (i * 8)); p += 8; return v;
    }
    return 0;
}

std::wstring TimeToStr(uint32_t t) {
    time_t tt = t;
    struct tm tm;
    localtime_s(&tm, &tt);
    wchar_t buf[64];
    wcsftime(buf, 64, L"%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

// ==================== 区块结构 ====================
struct BlockInfo {
    uint32_t height;
    uint64_t offset;      // 在文件中的偏移（magic 位置）
    uint32_t size;        // 区块数据大小
    uint32_t version;
    uint8_t  prevHash[32];
    uint8_t  merkle[32];
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
    uint64_t txCount;
    uint8_t  hash[32];    // 计算出来的区块哈希
};

std::vector<BlockInfo> g_blocks;
HWND g_hTree = NULL;

// ==================== 解析 blk 文件 ====================
bool ParseBlkFile(const std::wstring& path) {
    g_blocks.clear();
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return false;

    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> data(fileSize);
    fread(data.data(), 1, fileSize, f);
    fclose(f);

    const uint8_t* p = data.data();
    const uint8_t* end = p + fileSize;
    uint32_t height = 0;

    while (p + 8 <= end) {
        uint32_t magic = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
        if (magic != 0xD9B4BEF9) { // f9beb4d9 小端
            // 尝试跳过寻找下一个 magic（容错）
            p++;
            continue;
        }
        uint32_t size = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
        p += 8;
        if (size < 80 || p + size > end) break;

        const uint8_t* blockStart = p;
        BlockInfo bi = {};
        bi.height = height++;
        bi.offset = (uint64_t)(blockStart - data.data() - 8);
        bi.size = size;

        // Header
        bi.version = blockStart[0] | (blockStart[1] << 8) | (blockStart[2] << 16) | (blockStart[3] << 24);
        memcpy(bi.prevHash, blockStart + 4, 32);
        memcpy(bi.merkle, blockStart + 36, 32);
        bi.time = blockStart[68] | (blockStart[69] << 8) | (blockStart[70] << 16) | (blockStart[71] << 24);
        bi.bits = blockStart[72] | (blockStart[73] << 8) | (blockStart[74] << 16) | (blockStart[75] << 24);
        bi.nonce = blockStart[76] | (blockStart[77] << 8) | (blockStart[78] << 16) | (blockStart[79] << 24);

        // 计算区块哈希
        DoubleSHA256(blockStart, 80, bi.hash);

        // Tx Count
        const uint8_t* txp = blockStart + 80;
        bi.txCount = ReadVarInt(txp, blockStart + size);

        g_blocks.push_back(bi);
        p += size;
    }
    return !g_blocks.empty();
}

// ==================== 填充树 ====================
void FillTree() {
    TreeView_DeleteAllItems(g_hTree);
    for (const auto& b : g_blocks) {
        std::wstringstream title;
        title << L"Block #" << b.height << L"  (offset 0x" << std::hex << b.offset << L")";

        TVINSERTSTRUCT tvi = {};
        tvi.hParent = TVI_ROOT;
        tvi.hInsertAfter = TVI_LAST;
        tvi.item.mask = TVIF_TEXT;
        std::wstring titleStr = title.str();
        tvi.item.pszText = (LPWSTR)titleStr.c_str();
        HTREEITEM hBlock = TreeView_InsertItem(g_hTree, &tvi);

        auto addChild = [&](const std::wstring& text) {
            TVINSERTSTRUCT c = {};
            c.hParent = hBlock;
            c.hInsertAfter = TVI_LAST;
            c.item.mask = TVIF_TEXT;
            c.item.pszText = (LPWSTR)text.c_str();
            TreeView_InsertItem(g_hTree, &c);
            };

        // 先转成 string，再转 wstring，避免临时对象问题
        auto toW = [](const std::string& s) {
            return std::wstring(s.begin(), s.end());
            };

        addChild(L"Hash: " + toW(toHex(b.hash, 32, true)));
        addChild(L"Time: " + TimeToStr(b.time) + L"  (" + std::to_wstring(b.time) + L")");
        addChild(L"Tx Count: " + std::to_wstring(b.txCount));
        addChild(L"Version: " + std::to_wstring(b.version));
        addChild(L"Prev Hash: " + toW(toHex(b.prevHash, 32, true)));
        addChild(L"Merkle Root: " + toW(toHex(b.merkle, 32, true)));
        addChild(L"Bits: 0x" + toW(toHex((uint8_t*)&b.bits, 4, true)));
        addChild(L"Nonce: " + std::to_wstring(b.nonce));
        addChild(L"Size: " + std::to_wstring(b.size) + L" bytes");
    }
}

// ==================== 窗口过程 ====================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_TREEVIEW_CLASSES };
        InitCommonControlsEx(&icex);

        g_hTree = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREEVIEW, L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_SHOWSELALWAYS,
            0, 0, 0, 0, hwnd, (HMENU)1001, GetModuleHandle(NULL), NULL);

        // 菜单
        HMENU hMenu = CreateMenu();
        HMENU hFile = CreatePopupMenu();
        AppendMenu(hFile, MF_STRING, 100, L"打开 blk 文件...");
        AppendMenu(hFile, MF_SEPARATOR, 0, NULL);
        AppendMenu(hFile, MF_STRING, 101, L"退出");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hFile, L"文件");
        SetMenu(hwnd, hMenu);
        break;
    }
    case WM_SIZE:
        if (g_hTree) MoveWindow(g_hTree, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == 100) { // 打开
            OPENFILENAME ofn = {};
            wchar_t file[MAX_PATH] = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = file;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"Bitcoin Block Files (*.dat)\0*.dat\0All Files\0*.*\0";
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileName(&ofn)) {
                if (ParseBlkFile(file)) {
                    FillTree();
                    std::wstring title = L"BTC Block Viewer - " + std::wstring(file);
                    SetWindowText(hwnd, title.c_str());
                }
                else {
                    MessageBox(hwnd, L"解析失败，请确认是有效的 blk*.dat 文件", L"错误", MB_ICONERROR);
                }
            }
        }
        else if (LOWORD(wParam) == 101) {
            PostQuitMessage(0);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"BtcBlockViewer";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    HWND hwnd = CreateWindow(L"BtcBlockViewer", L"BTC Block Viewer (0.1.0 style)",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 700,
        NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}