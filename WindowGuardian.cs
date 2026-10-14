// WindowGuardian - keeps window positions stable across display-topology switches.
//
// Only drift that happens while the display topology is changing is corrected.
// At every other moment the tool does nothing, so normal mouse dragging and
// resizing is never interfered with.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WindowGuardian
{
    // ---------------------------------------------------------------- interop

    [StructLayout(LayoutKind.Sequential)]
    internal struct RECT { public int L, T, R, B; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct POINT { public int X, Y; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct MONITORINFOEX
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct DEVMODE
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public ushort dmSpecVersion, dmDriverVersion, dmSize, dmDriverExtra;
        public uint dmFields;
        public int dmPositionX, dmPositionY;
        public uint dmDisplayOrientation, dmDisplayFixedOutput;
        public short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public ushort dmLogPixels;
        public uint dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFlags, dmDisplayFrequency,
                    dmICMMethod, dmICMIntent, dmMediaType, dmDitherType,
                    dmReserved1, dmReserved2, dmPanningWidth, dmPanningHeight;
    }

    internal static class Native
    {
        internal delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        internal delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdc, ref RECT rect, IntPtr data);

        [DllImport("user32.dll")] internal static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
        [DllImport("user32.dll")] internal static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MonitorEnumProc cb, IntPtr data);
        [DllImport("user32.dll")] internal static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll")] internal static extern bool IsWindow(IntPtr h);
        [DllImport("user32.dll")] internal static extern bool IsIconic(IntPtr h);
        [DllImport("user32.dll")] internal static extern bool IsZoomed(IntPtr h);
        [DllImport("user32.dll")] internal static extern bool GetWindowRect(IntPtr h, out RECT r);
        [DllImport("user32.dll")] internal static extern IntPtr MonitorFromWindow(IntPtr h, uint flags);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] internal static extern bool GetMonitorInfo(IntPtr hMon, ref MONITORINFOEX mi);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] internal static extern bool EnumDisplaySettings(string dev, int mode, ref DEVMODE dm);
        [DllImport("user32.dll")] internal static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] internal static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] internal static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
        [DllImport("user32.dll", SetLastError = true)] internal static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
        [DllImport("user32.dll")] internal static extern bool ShowWindow(IntPtr h, int cmd);
        [DllImport("user32.dll")] internal static extern short GetAsyncKeyState(int vk);
        [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] internal static extern IntPtr GetWindowLongPtr(IntPtr h, int idx);
        [DllImport("kernel32.dll")] internal static extern bool AttachConsole(int pid);

        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] internal static extern bool CloseHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
        [DllImport("advapi32.dll")] internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint idx);
        [DllImport("advapi32.dll")] internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        // Integrity level of THIS process.  Windows UIPI refuses SetWindowPos on a
        // window owned by a process of higher integrity, so a LOW/Untrusted instance
        // can never move normal (MEDIUM) windows - it would silently do nothing.
        internal static int IntegrityRid()
        {
            IntPtr tok;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out tok)) return -1;
            int len = 0;
            GetTokenInformation(tok, 25, IntPtr.Zero, 0, out len);
            if (len <= 0) { CloseHandle(tok); return -1; }
            IntPtr buf = Marshal.AllocHGlobal(len);
            int ret, rid = -1;
            if (GetTokenInformation(tok, 25, buf, len, out ret))
            {
                IntPtr sid = Marshal.ReadIntPtr(buf);
                IntPtr pcnt = GetSidSubAuthorityCount(sid);
                byte cnt = Marshal.ReadByte(pcnt);
                rid = Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(cnt - 1)));
            }
            Marshal.FreeHGlobal(buf);
            CloseHandle(tok);
            return rid;
        }

        internal static string IntegrityName(int rid)
        {
            switch (rid)
            {
                case 0x0000: return "Untrusted";
                case 0x1000: return "LOW";
                case 0x2000: return "MEDIUM";
                case 0x3000: return "HIGH";
                case 0x4000: return "SYSTEM";
                default: return rid < 0 ? "unknown" : ("0x" + rid.ToString("X"));
            }
        }

        internal const uint SWP_NOSIZE = 0x0001;
        internal const uint SWP_NOZORDER = 0x0004;
        internal const uint SWP_NOACTIVATE = 0x0010;
        internal const uint SWP_NOSENDCHANGING = 0x0400;

        // Used ONLY for windows that are currently maximized: position changes, size
        // untouched (the system owns a maximized window's size).
        internal const uint MoveFlags = SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING;

        // Used for ordinary windows: restores the exact baseline rectangle.
        //
        // Restoring WIDTH/HEIGHT is NOT optional.  When the desktop shrinks (4K ->
        // 1080p during a game's fullscreen switch) Windows clamps an over-wide window
        // and NEVER gives the size back, so a move-only tool lets every single switch
        // shave the window down a bit more - the app window lost half its width in a
        // single cycle on 2026-10-02.  What must never happen is the old code's
        // SW_RESTORE + SetWindowPos(W/2, H/2) + SW_MAXIMIZE dance, which is what
        // destroyed that window's GPU compositor.  That path is gone.
        internal const uint RestoreFlags = SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING;

        internal const int SW_RESTORE = 9;
        internal const int SW_MAXIMIZE = 3;
        internal const int GWL_STYLE = -16;
        internal const long WS_CHILD = 0x40000000L;
        internal const uint MONITOR_DEFAULTTONEAREST = 2;
    }

    // ------------------------------------------------------------------ model

    internal sealed class Mon
    {
        public string Dev;
        public int L, T, R, B;
        public int WL, WT, WR, WB;
        public int ModeW, ModeH, Hz;
        public bool Primary;
        public string Sig()
        {
            return string.Format("{0}|{1},{2},{3},{4}|{5},{6},{7},{8}|{9}x{10}@{11}|{12}",
                Dev, L, T, R, B, WL, WT, WR, WB, ModeW, ModeH, Hz, Primary);
        }
    }

    internal sealed class Target
    {
        public IntPtr Hwnd;
        public string MonDev;
        public int RelX, RelY;
        public int AbsX, AbsY;
        public int W, H;
        public bool Maximized;
        public string Desc;
    }

    internal sealed class Snapshot
    {
        public string Sig = "";
        public string Geom = "";
        public Dictionary<IntPtr, Target> Items = new Dictionary<IntPtr, Target>();
    }

    // ------------------------------------------------------------------- app

    internal sealed class Guardian : ApplicationContext
    {
        private readonly NotifyIcon _tray;
        private readonly System.Windows.Forms.Timer _timer;
        private readonly string _logPath;
        private readonly string _exeDir;
        private readonly bool _createUi;
        private readonly bool _startHidden;

        private readonly HashSet<string> _excludeProc = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _excludeClass = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private Snapshot _baseline = new Snapshot();
        private readonly Dictionary<IntPtr, RECT> _prevRect = new Dictionary<IntPtr, RECT>();
        private readonly Dictionary<uint, string> _procName = new Dictionary<uint, string>();

        private string _lastSig = "";
        private string _curSig = "";
        private bool _guarding;
        private bool _enabled = true;
        private bool _reallyExit;
        private DateTime _guardUntil = DateTime.MinValue;
        private DateTime _settleUntil = DateTime.MinValue;
        private DateTime _stableSince = DateTime.MinValue;
        private DateTime _lastRestore = DateTime.MinValue;
        private int _lastRestoreCount;
        private int _refusalLogged;
        private readonly HashSet<int> _errCodes = new HashSet<int>();
        private int _integrity = -2;
        private bool _accessDeniedWarned;
        private DateTime _lastGuardEnd = DateTime.MinValue;
        private double _graceSeconds = 8.0;

        // Per-window "cannot make it go where we want" counter.  A window that keeps
        // refusing to land on its target is abandoned for the rest of the session.
        private readonly Dictionary<IntPtr, int> _stuck = new Dictionary<IntPtr, int>();
        private readonly HashSet<IntPtr> _gaveUp = new HashSet<IntPtr>();
        private readonly HashSet<IntPtr> _badRectLogged = new HashSet<IntPtr>();
        private readonly Dictionary<IntPtr, string> _deferLogged = new Dictionary<IntPtr, string>();
        private int _maxStuck = 6;

        // Cumulative per guard session, per window.
        //
        // A *consecutive* failure counter can never stop a window whose state keeps
        // FLIPPING, because every successful restore resets it.  That is exactly the
        // shape of the 2026-10-13 QQ incident: the primary monitor thrashed between
        // 3840x2160 / 1600x1200 / 2560x1440, so the "is this window on its recorded
        // monitor?" test kept flipping and the un-maximise -> move -> re-maximise
        // cycle could repeat indefinitely with the consecutive counter pinned at 0.
        private readonly Dictionary<IntPtr, int> _sessionActions = new Dictionary<IntPtr, int>();
        private readonly Dictionary<IntPtr, int> _stateToggles = new Dictionary<IntPtr, int>();
        private readonly HashSet<IntPtr> _toggleStopped = new HashSet<IntPtr>();
        private int _maxSessionActions = 40;   // hard stop on total restores per window per session
        private int _maxStateToggles = 2;      // hard stop on SW_RESTORE/SW_MAXIMIZE cycles per window per session

        private int _guardSeconds = 20;
        private int _settleSeconds = 3;
        private double _stableSeconds = 1.0;
        private int _tickMs = 200;

        // ---- UI
        private Form _form;
        private Label _lblState, _lblBase, _lblTopo, _lblHint;
        private Button _btnToggle;
        private TextBox _txtLog;
        private CheckBox _chkAuto;
        private CheckBox _chkNoLog;
        private bool _noLogFiles;
        private readonly List<string> _uiLines = new List<string>();
        private bool _console;

        internal Guardian(string exeDir, string logPath, bool createUi, bool startHidden)
        {
            _exeDir = exeDir;
            _logPath = logPath;
            _createUi = createUi;
            _startHidden = startHidden;
            LoadExcludes();

            _tray = new NotifyIcon();
            _tray.Icon = SystemIcons.Shield;
            _tray.Text = "WindowGuardian";
            _tray.Visible = true;
            _tray.DoubleClick += delegate { ShowPanel(); };

            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add(new ToolStripMenuItem("打开控制面板", null, delegate { ShowPanel(); }));
            menu.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem miEnabled = new ToolStripMenuItem("启用监视", null, OnToggleEnabled);
            miEnabled.Checked = true;
            miEnabled.Name = "miEnabled";
            menu.Items.Add(miEnabled);
            menu.Items.Add(new ToolStripMenuItem("以当前布局为基准", null, OnRebaseline));
            menu.Items.Add(new ToolStripMenuItem("立即还原", null, OnRestoreNow));
            menu.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem miAuto = new ToolStripMenuItem("开机自启", null, OnToggleAutostart);
            miAuto.Checked = IsAutostartEnabled();
            miAuto.Name = "miAuto";
            menu.Items.Add(miAuto);
            menu.Items.Add(new ToolStripMenuItem("打开日志", null, OnOpenLog));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(new ToolStripMenuItem("退出", null, OnExit));
            _tray.ContextMenuStrip = menu;

            if (_createUi) BuildForm();

            _timer = new System.Windows.Forms.Timer();
            _timer.Interval = _tickMs;
            _timer.Tick += OnTick;

            _stableSince = DateTime.UtcNow.AddSeconds(-_stableSeconds - 1);

            _noLogFiles = LoadNoLog();
            _integrity = Native.IntegrityRid();
            Log("=== 启动 pid=" + Process.GetCurrentProcess().Id
                + "  完整性级别=" + Native.IntegrityName(_integrity));
            if (_integrity >= 0 && _integrity < 0x2000)
            {
                Log("!!! 严重警告：本进程完整性级别为 " + Native.IntegrityName(_integrity)
                    + "，低于普通程序的 MEDIUM。Windows 的 UIPI 会拒绝本程序移动任何普通窗口"
                    + "（SetWindowPos 返回 ERROR_ACCESS_DENIED=5），守护将完全无效！");
                Log("!!! 请关闭本程序，然后用资源管理器直接双击 WindowGuardian.exe 启动。"
                    + "不要从受限终端 / 沙箱 / 低权限脚本里启动它。");
            }
            Log("提示：图标可能在任务栏的“隐藏的图标(^)”里，双击图标可打开此面板。");
            _timer.Start();

            if (_createUi && !_startHidden) ShowPanel();
        }

        // ------------------------------------------------------------ excludes

        private void LoadExcludes()
        {
            // NOTE: WindowGuardian is deliberately NOT in this list any more.
            // The panel's own window is an ordinary top-level window: Windows clamps
            // and relocates it during a display switch exactly like everything else,
            // so it has to guard itself too.  Moving our own window is also the one
            // case that can never be blocked, because it is same-thread/same-process
            // and therefore never subject to UIPI.
            string[] defProc = { "wgc", "wgc360_api", "wgc_renderer_host",
                                 "WorldOfWarships", "WorldOfWarships64" };
            foreach (string s in defProc) _excludeProc.Add(s);

            string[] defCls = { "Progman", "WorkerW", "Shell_TrayWnd", "Shell_SecondaryTrayWnd",
                                "TaskListThumbnailWnd", "TaskListOverlayWnd", "SysShadow",
                                "tooltips_class32", "EdgeUiInputTopWndClass", "DummyDWMListenerWindow",
                                "Internet Explorer_Hidden", "MSCTFIME UI", "IME", "Default IME",
                                "Windows.UI.Core.CoreWindow" };
            foreach (string s in defCls) _excludeClass.Add(s);

            try
            {
                string f = Path.Combine(_exeDir, "exclude.txt");
                if (File.Exists(f))
                {
                    foreach (string raw in File.ReadAllLines(f))
                    {
                        string line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) continue;
                        if (line.StartsWith("p:", StringComparison.OrdinalIgnoreCase))
                            _excludeProc.Add(line.Substring(2).Trim());
                        else if (line.StartsWith("c:", StringComparison.OrdinalIgnoreCase))
                            _excludeClass.Add(line.Substring(2).Trim());
                    }
                }
            }
            catch { }
        }

        private string ProcNameOf(uint pid)
        {
            string n;
            if (_procName.TryGetValue(pid, out n)) return n;
            try { n = Process.GetProcessById((int)pid).ProcessName; }
            catch { n = "?"; }
            _procName[pid] = n;
            return n;
        }

        // ------------------------------------------------------------ topology

        private Dictionary<string, Mon> EnumerateMonitors()
        {
            Dictionary<string, Mon> res = new Dictionary<string, Mon>(StringComparer.OrdinalIgnoreCase);
            Native.EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, delegate(IntPtr hMon, IntPtr hdc, ref RECT r, IntPtr d)
            {
                MONITORINFOEX mi = new MONITORINFOEX();
                mi.cbSize = Marshal.SizeOf(typeof(MONITORINFOEX));
                if (!Native.GetMonitorInfo(hMon, ref mi)) return true;

                Mon m = new Mon();
                m.Dev = mi.szDevice;
                m.L = mi.rcMonitor.L; m.T = mi.rcMonitor.T; m.R = mi.rcMonitor.R; m.B = mi.rcMonitor.B;
                m.WL = mi.rcWork.L; m.WT = mi.rcWork.T; m.WR = mi.rcWork.R; m.WB = mi.rcWork.B;
                m.Primary = (mi.dwFlags & 1) == 1;

                DEVMODE dm = new DEVMODE();
                dm.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODE));
                if (Native.EnumDisplaySettings(mi.szDevice, -1, ref dm))
                {
                    m.ModeW = (int)dm.dmPelsWidth;
                    m.ModeH = (int)dm.dmPelsHeight;
                    m.Hz = (int)dm.dmDisplayFrequency;
                }
                res[mi.szDevice] = m;
                return true;
            }, IntPtr.Zero);
            return res;
        }

        private static string Signature(Dictionary<string, Mon> mons)
        {
            List<string> parts = new List<string>();
            foreach (Mon m in mons.Values) parts.Add(m.Sig());
            parts.Sort(StringComparer.Ordinal);
            return string.Join(" ;; ", parts.ToArray());
        }

        // Geometry-only signature: monitor rect + mode + primary flag, WITHOUT the
        // work area.  The taskbar flickers (hides for fullscreen apps, changes the
        // secondary tray width between 62 and 0 px) so comparing work areas made
        // "are we back at the baseline?" false while the monitors were in fact
        // already back -> the absolute restore never ran.
        private static string GeomSig(Dictionary<string, Mon> mons)
        {
            List<string> parts = new List<string>();
            foreach (Mon m in mons.Values)
                parts.Add(m.Dev + "|" + m.L + "," + m.T + "," + m.R + "," + m.B + "|"
                          + m.ModeW + "x" + m.ModeH + "@" + m.Hz + "|" + m.Primary);
            parts.Sort(StringComparer.Ordinal);
            return string.Join(" ;; ", parts.ToArray());
        }

        private static string Pretty(string sig)
        {
            if (sig.Length == 0) return "(无)";
            List<string> outp = new List<string>();
            string[] chunks = sig.Split(new string[] { " ;; " }, StringSplitOptions.None);
            foreach (string c in chunks)
            {
                // fields: 0=dev 1=monitor rect 2=work rect 3=mode 4=primary
                string[] f = c.Split('|');
                if (f.Length >= 5)
                {
                    string dev = f[0].Replace("\\\\.\\", "");
                    outp.Add(dev + " " + f[3] + (f[4] == "True" ? " [主]" : ""));
                }
                else outp.Add(c);
            }
            return string.Join("  |  ", outp.ToArray());
        }

        // ----------------------------------------------------------- snapshots

        private bool IsTrackable(IntPtr h, string cls, string proc, RECT r, Dictionary<string, Mon> mons)
        {
            if (_excludeClass.Contains(cls)) return false;
            if (_excludeProc.Contains(proc)) return false;
            if (!Native.IsWindowVisible(h)) return false;
            if (Native.IsIconic(h)) return false;

            int w = r.R - r.L, hh = r.B - r.T;
            if (w < 60 || hh < 60) return false;
            if (r.L <= -30000) return false;

            foreach (Mon m in mons.Values)
            {
                if (r.L <= m.L + 2 && r.T <= m.T + 2 && r.R >= m.R - 2 && r.B >= m.B - 2) return false;
            }

            IntPtr style = Native.GetWindowLongPtr(h, Native.GWL_STYLE);
            if ((style.ToInt64() & Native.WS_CHILD) != 0) return false;

            // WS_EX_TOOLWINDOW is intentionally kept: DeskBox desktop widgets
            // ("内容格子") are tool windows and are exactly what we must protect.
            return true;
        }

        private bool HasTitle(IntPtr h)
        {
            StringBuilder sb = new StringBuilder(8);
            return Native.GetWindowTextW(h, sb, 8) > 0;
        }

        private void RefreshBaseline(Dictionary<string, Mon> mons)
        {
            HashSet<IntPtr> seen = new HashSet<IntPtr>();

            int vL = int.MaxValue, vT = int.MaxValue, vR = int.MinValue, vB = int.MinValue;
            foreach (Mon m in mons.Values)
            {
                if (m.L < vL) vL = m.L;
                if (m.T < vT) vT = m.T;
                if (m.R > vR) vR = m.R;
                if (m.B > vB) vB = m.B;
            }
            if (mons.Count == 0) { vL = 0; vT = 0; vR = 1; vB = 1; }

            Native.EnumWindows(delegate(IntPtr h, IntPtr p)
            {
                RECT r;
                if (!Native.GetWindowRect(h, out r)) return true;
                if (!HasTitle(h)) return true;

                uint pid; Native.GetWindowThreadProcessId(h, out pid);
                string proc = ProcNameOf(pid);

                StringBuilder cb = new StringBuilder(128);
                Native.GetClassNameW(h, cb, 128);
                string cls = cb.ToString();

                if (!IsTrackable(h, cls, proc, r, mons)) return true;
                seen.Add(h);

                RECT prev;
                bool stable = _prevRect.TryGetValue(h, out prev)
                              && prev.L == r.L && prev.T == r.T && prev.R == r.R && prev.B == r.B;
                _prevRect[h] = r;

                if (stable)
                {
                    IntPtr hMon = Native.MonitorFromWindow(h, Native.MONITOR_DEFAULTTONEAREST);
                    MONITORINFOEX mi = new MONITORINFOEX();
                    mi.cbSize = Marshal.SizeOf(typeof(MONITORINFOEX));
                    if (Native.GetMonitorInfo(hMon, ref mi))
                    {
                        StringBuilder tb = new StringBuilder(160);
                        Native.GetWindowTextW(h, tb, 160);
                        string title = tb.ToString();

                        // Sanitise: a rectangle whose centre is outside every monitor
                        // must never become the baseline.  Once a bad rect has been
                        // adopted there is no way to roll it back, so refuse it and
                        // keep whatever good value we already had.
                        int ccx = (r.L + r.R) / 2, ccy = (r.T + r.B) / 2;
                        if (ccx < vL || ccx >= vR || ccy < vT || ccy >= vB)
                        {
                            if (_baseline.Items.ContainsKey(h) && _badRectLogged.Add(h))
                                Log("拒绝写入基准(窗口中心已在所有屏幕之外) [" + title + "] (" + r.L + "," + r.T + ") "
                                    + (r.R - r.L) + "x" + (r.B - r.T) + "，保留旧基准");
                            return true;
                        }

                        // A display switch often keeps damaging windows for several
                        // seconds AFTER the topology is back ("late clamping").  If we
                        // re-baselined immediately, the tool would quietly adopt the
                        // damaged position as the new truth and every later report
                        // would still say OK.  So: inside a grace period after a guard
                        // session, keep the old baseline and say so out loud.
                        Target old;
                        if (_baseline.Items.TryGetValue(h, out old))
                        {
                            int dx = Math.Abs(r.L - old.AbsX), dy = Math.Abs(r.T - old.AbsY);
                            int dw = Math.Abs((r.R - r.L) - old.W), dh = Math.Abs((r.B - r.T) - old.H);
                            bool big = dx > 8 || dy > 8 || dw > 8 || dh > 8;
                            if (big)
                            {
                                bool afterGuard = (_lastGuardEnd != DateTime.MinValue);
                                double since = afterGuard ? (DateTime.UtcNow - _lastGuardEnd).TotalSeconds : -1;
                                string sinceTxt = afterGuard ? string.Format("{0:F1}s", since) : "从未守护过";
                                if (afterGuard && since < _graceSeconds)
                                {
                                    // Log only when the observed rectangle actually
                                    // changes - otherwise the same refusal is repeated
                                    // every tick for 8 seconds and drowns the log.
                                    string cur = "(" + r.L + "," + r.T + ") " + (r.R - r.L) + "x" + (r.B - r.T);
                                    string prevLogged;
                                    if (!_deferLogged.TryGetValue(h, out prevLogged) || prevLogged != cur)
                                    {
                                        _deferLogged[h] = cur;
                                        Log(string.Format(
                                            "基准暂缓(距上次守护 {0} < {1}s) [{2}] ({3},{4}) {5}x{6} -> {7} 保留旧基准",
                                            sinceTxt, _graceSeconds, title,
                                            old.AbsX, old.AbsY, old.W, old.H, cur));
                                    }
                                    return true;   // do not adopt the damaged position
                                }
                                _deferLogged.Remove(h);
                                Log(string.Format(
                                    "基准更新(距上次守护 {0}) [{1}] ({2},{3}) {4}x{5} -> ({6},{7}) {8}x{9}",
                                    sinceTxt, title,
                                    old.AbsX, old.AbsY, old.W, old.H,
                                    r.L, r.T, r.R - r.L, r.B - r.T));
                            }
                        }

                        Target t = new Target();
                        t.Hwnd = h;
                        t.MonDev = mi.szDevice;
                        t.RelX = r.L - mi.rcMonitor.L;
                        t.RelY = r.T - mi.rcMonitor.T;
                        t.AbsX = r.L;
                        t.AbsY = r.T;
                        t.W = r.R - r.L;
                        t.H = r.B - r.T;
                        t.Maximized = Native.IsZoomed(h);
                        t.Desc = proc + " | " + title;
                        _baseline.Items[h] = t;
                    }
                }
                return true;
            }, IntPtr.Zero);

            List<IntPtr> dead = new List<IntPtr>();
            foreach (IntPtr h in _baseline.Items.Keys)
                if (!seen.Contains(h) || !Native.IsWindow(h)) dead.Add(h);
            foreach (IntPtr h in dead) _baseline.Items.Remove(h);

            _baseline.Sig = Signature(mons);
            _baseline.Geom = GeomSig(mons);
        }

        internal void Prime()
        {
            RefreshBaseline(EnumerateMonitors());
            Thread.Sleep(80);
            RefreshBaseline(EnumerateMonitors());
        }

        internal void RunHeadless(int seconds)
        {
            _tray.Visible = false;
            _timer.Stop();
            Prime();
            Log("headless run start seconds=" + seconds + " tracked=" + _baseline.Items.Count);
            DateTime end = DateTime.UtcNow.AddSeconds(seconds);
            while (DateTime.UtcNow < end)
            {
                try { Tick(); }
                catch (Exception ex) { Log("tick error: " + ex.Message); }
                Thread.Sleep(_tickMs);
            }
            Log("headless run finished");
        }

        // ------------------------------------------------------------ restore

        private void RestoreAll(Dictionary<string, Mon> mons, bool absolute)
        {
            // NOTE: there is deliberately NO "left mouse button down" check any more.
            // Warships players hold the left button to aim, so that guard switched the
            // whole protection off during play.  Guard mode only runs inside a
            // display-switch window anyway, where a user drag is not expected.
            if (mons.Count == 0) return;

            int vL = int.MaxValue, vT = int.MaxValue, vR = int.MinValue, vB = int.MinValue;
            foreach (Mon m in mons.Values)
            {
                if (m.L < vL) vL = m.L;
                if (m.T < vT) vT = m.T;
                if (m.R > vR) vR = m.R;
                if (m.B > vB) vB = m.B;
            }

            List<IntPtr> dead = new List<IntPtr>();
            int moved = 0, failed = 0;

            foreach (KeyValuePair<IntPtr, Target> kv in _baseline.Items)
            {
                IntPtr h = kv.Key;
                Target t = kv.Value;

                if (!Native.IsWindow(h)) { dead.Add(h); continue; }
                if (Native.IsIconic(h)) continue;

                int x, y;
                if (absolute)
                {
                    // Used verbatim.  The baseline rectangle is by definition where the
                    // window is supposed to be, and absolute restore only runs once the
                    // topology is back to the baseline, so there is nothing to protect
                    // against.  Clamping here was a real bug: windows that legitimately
                    // hang slightly past the bottom edge of the desktop (e.g. 811+1456
                    // = 2267 > the 2151 bottom edge) were shoved upwards by 50-100 px on
                    // every single switch, and each shove was then adopted as the new
                    // baseline.
                    x = t.AbsX; y = t.AbsY;
                }
                else
                {
                    Mon m;
                    if (!mons.TryGetValue(t.MonDev, out m)) continue;
                    x = m.L + t.RelX;
                    y = m.T + t.RelY;

                    // Transient topology only: never push a window into empty space
                    // outside every monitor, or it would become invisible.
                    if (x + t.W > vR) x = vR - t.W;
                    if (y + t.H > vB) y = vB - t.H;
                    if (x < vL) x = vL;
                    if (y < vT) y = vT;
                }

                int res = Apply(h, t, x, y, mons);
                if (res == 1) moved++;
                else if (res == 2) failed++;
            }

            foreach (IntPtr h in dead) _baseline.Items.Remove(h);

            _lastRestore = DateTime.UtcNow;
            _lastRestoreCount = moved;
            if (moved > 0 || failed > 0)
                Log("还原(" + (absolute ? "绝对" : "相对") + ") 拉动 " + moved + " 个窗口"
                    + (failed > 0 ? "，另有 " + failed + " 个移动被拒绝" : ""));

            if (!_accessDeniedWarned && moved == 0 && failed >= 3 && _errCodes.Contains(5))
            {
                _accessDeniedWarned = true;
                Log("!!! 所有窗口移动都被 Windows 拒绝 (ERROR_ACCESS_DENIED=5)。这几乎总是因为"
                    + "本进程完整性级别过低(当前=" + Native.IntegrityName(_integrity) + "，需要 MEDIUM)。"
                    + "守护无法生效，请关闭后用资源管理器直接双击 WindowGuardian.exe 重新启动。");
            }
        }

        // 0 = already correct, 1 = moved, 2 = refused.
        //
        // THE PROGRAM NEVER RESIZES A WINDOW.  Every SetWindowPos call below passes
        // cx=cy=0 together with SWP_NOSIZE, so only the position can change.  The
        // old code did ShowWindow(SW_RESTORE) + SetWindowPos(W/2, H/2) + SW_MAXIMIZE
        // for windows it believed were maximized, which resized them up to five times
        // a second and destroyed that window's compositor.  That path is gone.
        private int Apply(IntPtr h, Target t, int x, int y, Dictionary<string, Mon> mons)
        {
            int stuck;
            _stuck.TryGetValue(h, out stuck);
            if (stuck >= _maxStuck)
            {
                if (_gaveUp.Add(h))
                    Log("放弃该窗口(连续 " + stuck + " 次没能归位，本次守护不再尝试): " + t.Desc);
                return 0;
            }

            // Cumulative stop.  Unlike the consecutive counter above, this one is never
            // reset by a success, so it still bites when an application fights back and
            // the window keeps flipping between two states forever.
            int acted;
            _sessionActions.TryGetValue(h, out acted);
            if (acted >= _maxSessionActions)
            {
                if (_gaveUp.Add(h))
                    Log("放弃该窗口(本次守护已操作 " + acted + " 次，疑似与应用来回拉锯): " + t.Desc);
                return 0;
            }

            RECT r;
            if (!Native.GetWindowRect(h, out r)) { CountStuck(h, t, "取不到窗口矩形"); return 2; }

            bool wantMax = t.Maximized;
            bool isMax = Native.IsZoomed(h);

            if (wantMax != isMax)
            {
                // The window's maximized state does not match the baseline, so it is
                // NOT in the state we are supposed to maintain.  This was the bug that
                // made that window look "unguarded": it happened to be maximized
                // while its baseline was an ordinary rectangle, and the old code
                // treated any maximized window as "already correct" and skipped it.
                if (!AllowStateToggle(h, t)) return 0;
                Log(string.Format("恢复最大化状态 [{0}] {1} -> {2}  now=({3},{4}) {5}x{6}  目标=({7},{8}) {9}x{10}  (本次第 {11} 次状态切换)",
                    ShortDesc(t), isMax ? "最大化" : "普通", wantMax ? "最大化" : "普通",
                    r.L, r.T, r.R - r.L, r.B - r.T, x, y, t.W, t.H, _stateToggles[h]));
                NoteAction(h);
                if (isMax) Native.ShowWindow(h, Native.SW_RESTORE);
                if (!Native.SetWindowPos(h, IntPtr.Zero, x, y, t.W, t.H, Native.RestoreFlags))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (wantMax) Native.ShowWindow(h, Native.SW_MAXIMIZE);
                    NoteRefusal("state", h, t, x, y, r, err);
                    CountStuck(h, t, "状态还原被拒 err=" + err);
                    return 2;
                }
                if (wantMax) Native.ShowWindow(h, Native.SW_MAXIMIZE);
                _stuck[h] = 0;
                return 1;
            }

            if (isMax)
            {
                // Both sides agree it is maximized: only ensure it is maximized on the
                // recorded monitor.  A maximized window's size belongs to the system,
                // so this path moves only and never sets a size.
                Mon tm;
                if (!mons.TryGetValue(t.MonDev, out tm)) return 0;   // unknown target: leave it alone
                int cx = (r.L + r.R) / 2;
                if (cx >= tm.L && cx < tm.R) { _stuck[h] = 0; return 0; }

                if (!AllowStateToggle(h, t)) return 0;
                Log(string.Format("换屏回置 [{0}] 目标屏={1} now=({2},{3}) {4}x{5}  目标=({6},{7})  (本次第 {8} 次状态切换)",
                    ShortDesc(t), t.MonDev, r.L, r.T, r.R - r.L, r.B - r.T, x, y, _stateToggles[h]));
                NoteAction(h);
                Native.ShowWindow(h, Native.SW_RESTORE);
                if (!Native.SetWindowPos(h, IntPtr.Zero, x, y, 0, 0, Native.MoveFlags))
                {
                    int err = Marshal.GetLastWin32Error();
                    Native.ShowWindow(h, Native.SW_MAXIMIZE);
                    NoteRefusal("rehome", h, t, x, y, r, err);
                    CountStuck(h, t, "换屏移动被拒 err=" + err);
                    return 2;
                }
                Native.ShowWindow(h, Native.SW_MAXIMIZE);
                _stuck[h] = 0;
                return 1;
            }

            // both sides say "ordinary window": restore the exact baseline rectangle.
            // The size half of this is essential - see the RestoreFlags comment.
            if (r.L == x && r.T == y && (r.R - r.L) == t.W && (r.B - r.T) == t.H) { _stuck[h] = 0; return 0; }

            NoteAction(h);
            if (!Native.SetWindowPos(h, IntPtr.Zero, x, y, t.W, t.H, Native.RestoreFlags))
            {
                int err = Marshal.GetLastWin32Error();
                NoteRefusal("restore", h, t, x, y, r, err);
                CountStuck(h, t, "还原被拒 err=" + err);
                return 2;
            }

            RECT after;
            if (Native.GetWindowRect(h, out after) && after.L == x && after.T == y)
            {
                _stuck[h] = 0;
                return 1;
            }
            CountStuck(h, t, "移动后没有停在目标位置");
            return 1;
        }

        private static string ShortDesc(Target t)
        {
            string d = t.Desc;
            int i = d.IndexOf(" | ");
            return i > 0 ? d.Substring(i + 3) : d;
        }

        private void CountStuck(IntPtr h, Target t, string why)
        {
            int n;
            _stuck.TryGetValue(h, out n);
            _stuck[h] = n + 1;
            if (n + 1 == _maxStuck)
                Log("窗口连续 " + (n + 1) + " 次无法归位 (" + why + ")，下次起放弃: " + t.Desc);
        }

        private void NoteAction(IntPtr h)
        {
            int n;
            _sessionActions.TryGetValue(h, out n);
            _sessionActions[h] = n + 1;
        }

        // Hard stop for SW_RESTORE / SW_MAXIMIZE cycles.
        //
        // This is the action that destroyed that window's GPU compositor on
        // 2026-10-02, so it gets a far tighter budget than a plain move, and every
        // single occurrence is logged with the window's identity.  The 2026-10-13 QQ
        // incident could not be localised precisely because this path used to be
        // completely invisible in the log.
        private bool AllowStateToggle(IntPtr h, Target t)
        {
            int n;
            _stateToggles.TryGetValue(h, out n);
            if (n >= _maxStateToggles)
            {
                if (_toggleStopped.Add(h))
                    Log("停止对 [" + ShortDesc(t) + "] 做 还原/最大化 切换（本次守护已达 " + n
                        + " 次上限，避免打坏该应用的渲染状态）");
                return false;
            }
            _stateToggles[h] = n + 1;
            return true;
        }

        private void NoteRefusal(string kind, IntPtr h, Target t, int x, int y, RECT cur, int err)
        {
            _errCodes.Add(err);
            if (_refusalLogged < 8)
            {
                _refusalLogged++;
                Log(string.Format("  移动被拒[{0}] err={1} hwnd=0x{2:X} now=({3},{4}) {5}x{6} target=({7},{8}) {9}x{10}  {11}",
                    kind, err, h.ToInt64(),
                    cur.L, cur.T, cur.R - cur.L, cur.B - cur.T,
                    x, y, t.W, t.H, t.Desc));
            }
        }

        // Written every time guard mode ends: exactly which windows did NOT make it
        // back to their baseline rectangle, and by how much.
        private void WriteGuardReport(Dictionary<string, Mon> mons, string reason)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                int bad = 0;
                sb.AppendLine("time   : " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "   reason=" + reason);
                sb.AppendLine("baseline geometry : " + Pretty(_baseline.Geom));
                sb.AppendLine("current  geometry : " + Pretty(GeomSig(mons)));
                sb.AppendLine("baseline workarea : " + _baseline.Sig);
                sb.AppendLine("current  workarea : " + Signature(mons));
                sb.AppendLine();
                foreach (KeyValuePair<IntPtr, Target> kv in _baseline.Items)
                {
                    IntPtr h = kv.Key;
                    Target t = kv.Value;
                    if (!Native.IsWindow(h)) { sb.AppendLine("  GONE      " + t.Desc); continue; }

                    RECT r;
                    if (!Native.GetWindowRect(h, out r)) { sb.AppendLine("  NO-RECT   " + t.Desc); continue; }

                    bool ok;
                    string detail;
                    bool nowMax = Native.IsZoomed(h);
                    if (t.Maximized != nowMax)
                    {
                        ok = false;
                        detail = "最大化状态不符: 基准=" + (t.Maximized ? "最大化" : "普通")
                               + " 现在=" + (nowMax ? "最大化" : "普通");
                    }
                    else if (nowMax)
                    {
                        Mon tm;
                        bool onTarget = mons.TryGetValue(t.MonDev, out tm)
                                        && ((r.L + r.R) / 2) >= tm.L && ((r.L + r.R) / 2) < tm.R;
                        ok = onTarget;
                        detail = "最大化, 在目标屏=" + onTarget;
                    }
                    else
                    {
                        int dx = r.L - t.AbsX, dy = r.T - t.AbsY;
                        int dw = (r.R - r.L) - t.W, dh = (r.B - r.T) - t.H;
                        ok = Math.Abs(dx) <= 2 && Math.Abs(dy) <= 2 && Math.Abs(dw) <= 2 && Math.Abs(dh) <= 2;
                        detail = string.Format("d=({0},{1},{2},{3})", dx, dy, dw, dh);
                    }
                    if (!ok) bad++;
                    sb.AppendLine(string.Format("  {0} base=({1},{2}) {3}x{4} max={5} mon={6}  now=({7},{8}) {9}x{10}  {11}  {12}",
                        ok ? "OK      " : "MISMATCH", t.AbsX, t.AbsY, t.W, t.H, t.Maximized, t.MonDev,
                        r.L, r.T, r.R - r.L, r.B - r.T, detail, t.Desc));
                }
                sb.AppendLine();
                sb.AppendLine("MISMATCH = " + bad + " / " + _baseline.Items.Count);
                if (_noLogFiles)
                {
                    Log("守护结束报告：" + bad + " / " + _baseline.Items.Count + " 个窗口未回到基准（日志已关闭，未写文件）");
                    return;
                }
                string p = Path.Combine(_exeDir, "guardoff-" + DateTime.Now.ToString("HHmmss") + ".txt");
                File.WriteAllText(p, sb.ToString(), Encoding.UTF8);
                Log("守护结束报告：" + bad + " / " + _baseline.Items.Count + " 个窗口未回到基准  -> " + Path.GetFileName(p));
            }
            catch (Exception ex) { Log("写报告失败: " + ex.Message); }
        }

        // --------------------------------------------------------------- tick

        private void OnTick(object sender, EventArgs e)
        {
            try { Tick(); }
            catch (Exception ex) { Log("tick error: " + ex.Message); }
            UpdateUi();
        }

        private void Tick()
        {
            Dictionary<string, Mon> mons = EnumerateMonitors();
            string sig = Signature(mons);
            string geom = GeomSig(mons);
            _curSig = sig;

            bool topoChanged = (_lastSig.Length != 0) && (sig != _lastSig);
            if (_lastSig.Length == 0) _lastSig = sig;
            bool atBaseline = (geom == _baseline.Geom) && _baseline.Geom.Length > 0;

            if (topoChanged)
            {
                Log("检测到显示器拓扑变化 -> " + Pretty(sig));
                _lastSig = sig;
                _stableSince = DateTime.UtcNow;
                if (!_guarding)
                {
                    if (_baseline.Geom.Length == 0) { RefreshBaseline(mons); return; }
                    _guarding = true;
                    _refusalLogged = 0;
                    _errCodes.Clear();
                    _stuck.Clear();
                    _gaveUp.Clear();
                    _sessionActions.Clear();
                    _stateToggles.Clear();
                    _toggleStopped.Clear();
                    Log("进入守护模式 (基准=" + Pretty(_baseline.Sig) + ")");
                }
                _guardUntil = DateTime.UtcNow.AddSeconds(_guardSeconds);
                if (atBaseline) _settleUntil = DateTime.UtcNow.AddSeconds(_settleSeconds);
            }

            if (!_enabled)
            {
                if (!_guarding && DateTime.UtcNow - _stableSince > TimeSpan.FromSeconds(_stableSeconds))
                    RefreshBaseline(mons);
                return;
            }

            if (_guarding)
            {
                if (atBaseline)
                {
                    RestoreAll(mons, true);
                    if (DateTime.UtcNow >= _settleUntil)
                    {
                        _guarding = false;
                        _lastGuardEnd = DateTime.UtcNow;
                        if (_errCodes.Count > 0)
                        {
                            List<string> cs = new List<string>();
                            foreach (int e in _errCodes) cs.Add(e.ToString());
                            Log("本次守护出现的拒绝错误码: " + string.Join(",", cs.ToArray()));
                        }
                        WriteGuardReport(mons, "back-at-baseline");
                        RefreshBaseline(mons);
                        Log("退出守护模式 (已回到基准布局)");
                    }
                }
                else if (DateTime.UtcNow < _guardUntil)
                {
                    RestoreAll(mons, false);
                }
                return;
            }

            if (DateTime.UtcNow - _stableSince > TimeSpan.FromSeconds(_stableSeconds))
                RefreshBaseline(mons);
        }

        // ------------------------------------------------------------ UI panel

        private void BuildForm()
        {
            _form = new Form();
            _form.Text = "WindowGuardian - 显示切换窗口守护";
            _form.ClientSize = new Size(560, 462);
            _form.FormBorderStyle = FormBorderStyle.FixedSingle;
            _form.MaximizeBox = false;
            _form.StartPosition = FormStartPosition.CenterScreen;
            _form.Icon = SystemIcons.Shield;
            _form.ShowInTaskbar = true;

            Label t = new Label();
            t.Text = "在显示器拓扑切换（游戏进出独占全屏）期间维持窗口位置；其余时间不干预。";
            t.SetBounds(12, 10, 536, 34);
            _form.Controls.Add(t);

            _lblState = new Label();
            _lblState.SetBounds(12, 50, 536, 22);
            _form.Controls.Add(_lblState);

            _lblBase = new Label();
            _lblBase.SetBounds(12, 74, 536, 22);
            _form.Controls.Add(_lblBase);

            _lblTopo = new Label();
            _lblTopo.SetBounds(12, 98, 536, 22);
            _form.Controls.Add(_lblTopo);

            _btnToggle = new Button();
            _btnToggle.SetBounds(12, 128, 128, 30);
            _btnToggle.Click += OnToggleEnabled;
            _form.Controls.Add(_btnToggle);

            Button b2 = new Button();
            b2.Text = "以当前布局为基准";
            b2.SetBounds(148, 128, 150, 30);
            b2.Click += OnRebaseline;
            _form.Controls.Add(b2);

            Button b3 = new Button();
            b3.Text = "立即还原";
            b3.SetBounds(306, 128, 110, 30);
            b3.Click += OnRestoreNow;
            _form.Controls.Add(b3);

            Button b4 = new Button();
            b4.Text = "打开日志";
            b4.SetBounds(424, 128, 110, 30);
            b4.Click += OnOpenLog;
            _form.Controls.Add(b4);

            _chkAuto = new CheckBox();
            _chkAuto.Text = "开机自启";
            _chkAuto.SetBounds(12, 166, 120, 24);
            _chkAuto.Checked = IsAutostartEnabled();
            _chkAuto.Click += OnToggleAutostart;
            _form.Controls.Add(_chkAuto);

            _lblHint = new Label();
            _lblHint.SetBounds(140, 166, 400, 24);
            _lblHint.ForeColor = Color.DimGray;
            _lblHint.Text = "关闭本窗口 = 收进托盘，程序继续运行";
            _form.Controls.Add(_lblHint);

            _chkNoLog = new CheckBox();
            _chkNoLog.Text = "关闭日志生成（不写 guardian.log 与 guardoff-*.txt，面板内的记录照常）";
            _chkNoLog.SetBounds(12, 196, 536, 24);
            _chkNoLog.Checked = _noLogFiles;
            _chkNoLog.Click += OnToggleNoLog;
            _form.Controls.Add(_chkNoLog);

            Label lt = new Label();
            lt.Text = "最近事件：";
            lt.SetBounds(12, 226, 200, 20);
            _form.Controls.Add(lt);

            _txtLog = new TextBox();
            _txtLog.Multiline = true;
            _txtLog.ReadOnly = true;
            _txtLog.ScrollBars = ScrollBars.Vertical;
            _txtLog.WordWrap = false;
            _txtLog.BackColor = Color.White;
            _txtLog.Font = new Font("Consolas", 8.5f);
            _txtLog.SetBounds(12, 248, 536, 204);
            _form.Controls.Add(_txtLog);

            _form.FormClosing += delegate(object s, FormClosingEventArgs e)
            {
                if (!_reallyExit)
                {
                    e.Cancel = true;
                    _form.Hide();
                    _tray.ShowBalloonTip(2500, "WindowGuardian", "仍在后台运行，双击托盘图标可重新打开。", ToolTipIcon.Info);
                }
            };
            UpdateUi();
        }

        private void ShowPanel()
        {
            if (_form == null) return;
            _form.Show();
            if (_form.WindowState == FormWindowState.Minimized) _form.WindowState = FormWindowState.Normal;
            _form.Activate();
            _form.BringToFront();
        }

        private void UpdateUi()
        {
            if (_form == null) return;
            _lblState.Text = "状态： " + (_enabled ? "● 监视中" : "○ 已暂停")
                           + (_guarding ? "    【正在守护切换：拓扑已变化】" : "");
            _lblState.ForeColor = _enabled ? (_guarding ? Color.DarkOrange : Color.SeaGreen) : Color.Gray;

            if (_integrity >= 0 && _integrity < 0x2000)
            {
                _lblState.Text = "状态： ⚠ 完整性级别 " + Native.IntegrityName(_integrity)
                               + " 过低，守护无法生效！请用资源管理器双击本程序重启";
                _lblState.ForeColor = Color.Red;
            }
            _lblBase.Text = "基准： " + _baseline.Items.Count + " 个窗口 / " + Pretty(_baseline.Geom);
            _lblTopo.Text = "当前： " + Pretty(_curSig);
            _btnToggle.Text = _enabled ? "暂停监视" : "启用监视";
        }

        // -------------------------------------------------------------- menu

        private void OnToggleEnabled(object sender, EventArgs e)
        {
            _enabled = !_enabled;
            ToolStripItem mi = FindTrayItem("miEnabled");
            if (mi != null) mi.Text = _enabled ? "启用监视" : "已暂停监视";
            if (mi is ToolStripMenuItem) ((ToolStripMenuItem)mi).Checked = _enabled;
            Log("监视开关 = " + _enabled);
            UpdateUi();
        }

        private ToolStripItem FindTrayItem(string name)
        {
            foreach (ToolStripItem it in _tray.ContextMenuStrip.Items)
                if (it.Name == name) return it;
            return null;
        }

        private void OnRebaseline(object sender, EventArgs e)
        {
            Dictionary<string, Mon> mons = EnumerateMonitors();
            _baseline.Items.Clear();
            _prevRect.Clear();
            RefreshBaseline(mons);
            Thread.Sleep(60);
            RefreshBaseline(mons);
            _guarding = false;
            _lastSig = Signature(mons);
            Log("手动重设基准，共 " + _baseline.Items.Count + " 个窗口");
            UpdateUi();
        }

        private void OnRestoreNow(object sender, EventArgs e)
        {
            RestoreAll(EnumerateMonitors(), true);
            Log("手动还原一次");
            UpdateUi();
        }

        private void OnOpenLog(object sender, EventArgs e)
        {
            try { Process.Start("notepad.exe", "\"" + _logPath + "\""); } catch { }
        }

        private void OnToggleNoLog(object sender, EventArgs e)
        {
            bool want = _chkNoLog.Checked;
            // Log the intent BEFORE flipping the flag so the file records the switch.
            Log("日志文件写入 -> " + (want ? "关闭（不再写 guardian.log / guardoff-*.txt）" : "开启"));
            _noLogFiles = want;
            SaveNoLog(want);
        }

        private static bool LoadNoLog()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\WindowGuardian", false))
                    return k != null && Convert.ToInt32(k.GetValue("NoLog", 0)) != 0;
            }
            catch { return false; }
        }

        private static void SaveNoLog(bool v)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.CreateSubKey(@"Software\WindowGuardian"))
                    k.SetValue("NoLog", v ? 1 : 0, RegistryValueKind.DWord);
            }
            catch { }
        }

        private void OnToggleAutostart(object sender, EventArgs e)
        {
            bool enable = !IsAutostartEnabled();
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (enable)
                        k.SetValue("WindowGuardian", "\"" + Path.Combine(_exeDir, "WindowGuardian.exe") + "\" --tray");
                    else
                        k.DeleteValue("WindowGuardian", false);
                }
                if (_chkAuto != null) _chkAuto.Checked = enable;
                ToolStripItem mi = FindTrayItem("miAuto");
                if (mi is ToolStripMenuItem) ((ToolStripMenuItem)mi).Checked = enable;
                Log("开机自启 = " + enable);
            }
            catch (Exception ex) { Log("设置自启失败: " + ex.Message); }
        }

        private static bool IsAutostartEnabled()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", false))
                {
                    return k != null && k.GetValue("WindowGuardian") != null;
                }
            }
            catch { return false; }
        }

        private void OnExit(object sender, EventArgs e)
        {
            Log("=== 退出");
            _reallyExit = true;
            _timer.Stop();
            _tray.Visible = false;
            Application.Exit();
        }

        internal void DumpTo(string path)
        {
            Dictionary<string, Mon> mons = EnumerateMonitors();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("time: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"));
            sb.AppendLine("topology: " + Signature(mons));
            sb.AppendLine("baseline: " + _baseline.Sig);
            sb.AppendLine("guarding: " + _guarding + "  enabled: " + _enabled);
            sb.AppendLine("tracked windows: " + _baseline.Items.Count);
            List<IntPtr> keys = new List<IntPtr>(_baseline.Items.Keys);
            foreach (IntPtr h in keys)
            {
                Target t = _baseline.Items[h];
                RECT r; bool ok = Native.GetWindowRect(h, out r);
                sb.AppendLine(string.Format("  baseline {0,-16} ({1},{2}) {3}x{4} max={5} mon={6}  now=({7},{8})  {9}",
                    "0x" + h.ToInt64().ToString("X"), t.AbsX, t.AbsY, t.W, t.H, t.Maximized, t.MonDev,
                    ok ? r.L.ToString() : "?", ok ? r.T.ToString() : "?", t.Desc));
            }
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        // --------------------------------------------------------------- log

        internal void EnableConsole() { _console = true; }

        internal void Log(string msg)
        {
            string line = DateTime.Now.ToString("HH:mm:ss.fff") + "  " + msg;
            // The panel's event box below ALWAYS keeps working; this switch only stops
            // the files (guardian.log and guardoff-*.txt) from being written.
            if (!_noLogFiles)
            {
                try { File.AppendAllText(_logPath, line + Environment.NewLine, Encoding.UTF8); } catch { }
            }
            if (_console) Console.WriteLine(line);

            _uiLines.Add(line);
            while (_uiLines.Count > 400) _uiLines.RemoveAt(0);
            if (_form != null && _txtLog != null && !_form.IsDisposed)
            {
                try
                {
                    _txtLog.Text = string.Join(Environment.NewLine, _uiLines.ToArray());
                    _txtLog.SelectionStart = _txtLog.TextLength;
                    _txtLog.ScrollToCaret();
                }
                catch { }
            }
        }
    }

    // -------------------------------------------------------------- entry

    internal static class Program
    {
        [STAThread]
        internal static int Main(string[] args)
        {
            bool dumpOnly = false, startHidden = false;
            int testSeconds = 0;
            string exeDir = Path.GetDirectoryName(Application.ExecutablePath);
            string logPath = Path.Combine(exeDir, "guardian.log");
            string dumpPath = null;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if (a == "--dump")
                {
                    dumpOnly = true;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--")) dumpPath = args[i + 1];
                }
                else if (a == "--test")
                {
                    if (i + 1 < args.Length) int.TryParse(args[i + 1], out testSeconds);
                }
                else if (a == "--tray" || a == "--silent") { startHidden = true; }
            }

            if (dumpOnly || testSeconds > 0)
            {
                Native.AttachConsole(-1);
                Guardian gh = new Guardian(exeDir, logPath, false, true);
                gh.EnableConsole();
                if (testSeconds > 0) { gh.RunHeadless(testSeconds); return 0; }
                string outp = dumpPath ?? Path.Combine(exeDir, "guardian-dump.txt");
                gh.Prime();
                gh.DumpTo(outp);
                Console.WriteLine(File.ReadAllText(outp, Encoding.UTF8));
                return 0;
            }

            bool created;
            using (Mutex mtx = new Mutex(true, "Global\\WindowGuardian_SingleInstance", out created))
            {
                if (!created)
                {
                    MessageBox.Show("WindowGuardian 已经在运行了，请查看任务栏托盘（可能在 ^ 隐藏区里）。",
                        "WindowGuardian", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 1;
                }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new Guardian(exeDir, logPath, true, startHidden));
            }
            return 0;
        }
    }
}
