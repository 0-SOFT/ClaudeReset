// ClaudeReset setup: installs the portable bundle for the current user only, without administrator rights.
// Layout: %LOCALAPPDATA%\Programs\ClaudeReset\{ClaudeReset.exe, ClaudeReset.ico, current.txt, app-<version>\}.
// Built by tools/build_bundle.py (.NET Framework compiler, C# 5) with the bundle ZIP, icon, mark and fonts as resources.
// Test options: /target=DIR /registry-key=NAME /shortcuts=DIR /no-desktop /quiet
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

static class L
{
    // Russian by default; the ENGLISH button (or /lang=en) switches to English.
    public static bool Ru = true;

    public static string T(string ru, string en) { return Ru ? ru : en; }
}

class InstallError : Exception
{
    public InstallError(string message) : base(message) { }
}

class Options
{
    public string Home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", Product.Name);
    public string RegistryKey = Product.Name;
    public string Shortcuts = null;
    public bool Desktop = true;
    public bool Quiet = false;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        foreach (string arg in args)
        {
            if (arg.StartsWith("/target=")) o.Home = Path.GetFullPath(arg.Substring(8));
            else if (arg.StartsWith("/registry-key=")) o.RegistryKey = arg.Substring(14);
            else if (arg.StartsWith("/shortcuts=")) o.Shortcuts = Path.GetFullPath(arg.Substring(11));
            else if (arg == "/no-desktop") o.Desktop = false;
            else if (arg == "/quiet") o.Quiet = true;
            else if (arg == "/lang=en") L.Ru = false;
            else if (arg == "/lang=ru") L.Ru = true;
        }
        if (!Regex.IsMatch(o.RegistryKey, "^" + Regex.Escape(Product.Name) + "[A-Za-z0-9-]*$")) throw new ArgumentException("registry-key");
        return o;
    }
}

static class Installer
{
    const string UninstallRoot = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\";

    public static Stream Resource(string name)
    {
        return Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
    }

    public static string Run(Options o, Action<int> progress)
    {
        using (Stream payload = Resource("payload.zip"))
        using (var zip = new ZipArchive(payload, ZipArchiveMode.Read))
        {
            string top = zip.Entries[0].FullName.Split('/')[0];
            if (!Regex.IsMatch(top, "^" + Regex.Escape(Product.Name) + @"-[0-9A-Za-z.\-]+$")) throw new InstallError(L.T("Установочный пакет повреждён.", "The installation package is damaged."));
            string version = top.Substring(Product.Name.Length + 1);
            string appName = "app-" + version;
            Directory.CreateDirectory(o.Home);
            string target = Path.Combine(o.Home, appName);
            string partial = target + ".partial";
            if (Directory.Exists(partial)) Directory.Delete(partial, true);
            if (Directory.Exists(target))
            {
                try { Directory.Delete(target, true); }
                catch (IOException) { throw new InstallError(L.T("Эта версия уже установлена и сейчас работает. Закройте " + Product.Name + " и повторите.", "This version is already installed and running. Close " + Product.Name + " and try again.")); }
                catch (UnauthorizedAccessException) { throw new InstallError(L.T("Эта версия уже установлена и сейчас работает. Закройте " + Product.Name + " и повторите.", "This version is already installed and running. Close " + Product.Name + " and try again.")); }
            }
            string root = Path.GetFullPath(partial) + "\\";
            int done = 0, total = zip.Entries.Count;
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                done++;
                if (!entry.FullName.StartsWith(top + "/")) throw new InstallError(L.T("Установочный пакет повреждён.", "The installation package is damaged."));
                string relative = entry.FullName.Substring(top.Length + 1);
                if (relative.Length == 0) continue;
                string destination = Path.GetFullPath(Path.Combine(partial, relative.Replace('/', '\\')));
                if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InstallError(L.T("Установочный пакет повреждён.", "The installation package is damaged."));
                if (entry.FullName.EndsWith("/")) { Directory.CreateDirectory(destination); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(destination));
                entry.ExtractToFile(destination, true);
                if (progress != null && done % 40 == 0) progress(done * 100 / total);
            }
            Directory.Move(partial, target);
            string launcher = Path.Combine(o.Home, Product.Name + ".exe");
            string icon = Path.Combine(o.Home, Product.Name + ".ico");
            File.Copy(Path.Combine(target, Product.Name + ".exe"), launcher, true);
            File.Copy(Path.Combine(target, Product.Name + ".ico"), icon, true);
            File.WriteAllText(Path.Combine(o.Home, "current.txt"), appName);

            string menu = Path.Combine(o.Shortcuts ?? Environment.GetFolderPath(Environment.SpecialFolder.Programs), Product.Name + ".lnk");
            Directory.CreateDirectory(Path.GetDirectoryName(menu));
            Shortcut(menu, launcher, icon, o.Home);
            string desktop = "";
            if (o.Desktop)
            {
                string folder = o.Shortcuts != null ? Path.Combine(o.Shortcuts, "Desktop") : Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                Directory.CreateDirectory(folder);
                desktop = Path.Combine(folder, Product.Name + ".lnk");
                Shortcut(desktop, launcher, icon, o.Home);
            }
            long size = 0;
            foreach (string file in Directory.GetFiles(target, "*", SearchOption.AllDirectories)) size += new FileInfo(file).Length;
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(UninstallRoot + o.RegistryKey))
            {
                key.SetValue("DisplayName", Product.Name);
                key.SetValue("DisplayVersion", version);
                key.SetValue("Publisher", Product.Publisher);
                key.SetValue("DisplayIcon", icon);
                key.SetValue("InstallLocation", o.Home);
                key.SetValue("UninstallString", "\"" + launcher + "\" --uninstall");
                key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                key.SetValue("EstimatedSize", (int)(size / 1024), RegistryValueKind.DWord);
                key.SetValue("ShortcutStartMenu", menu);
                key.SetValue("ShortcutDesktop", desktop);
            }
            if (progress != null) progress(100);
            return launcher;
        }
    }

    static void Shortcut(string path, string target, string icon, string folder)
    {
        Type type = Type.GetTypeFromProgID("WScript.Shell");
        object shell = Activator.CreateInstance(type);
        object link = type.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { path });
        Type linkType = link.GetType();
        linkType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, link, new object[] { target });
        linkType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, link, new object[] { folder });
        linkType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, link, new object[] { icon + ",0" });
        linkType.InvokeMember("Description", BindingFlags.SetProperty, null, link, new object[] { L.T(Product.Name + ": сброс Claude и прокси", Product.Name + ": reset Claude and use a proxy") });
        linkType.InvokeMember("Save", BindingFlags.InvokeMethod, null, link, null);
        Marshal.FinalReleaseComObject(link);
        Marshal.FinalReleaseComObject(shell);
    }
}

static class Brand
{
    public static readonly Color Paper = Color.FromArgb(0xf2, 0xf1, 0xec), Marble = Color.FromArgb(0xf8, 0xf7, 0xf4),
        Mist = Color.FromArgb(0xec, 0xef, 0xf1), Stone = Color.FromArgb(0xb9, 0xc0, 0xc8), Graphite = Color.FromArgb(0x2e, 0x31, 0x35),
        Graphite2 = Color.FromArgb(0x4a, 0x4f, 0x56), Ink = Color.FromArgb(0x0e, 0x0e, 0x0e), Accent = Color.FromArgb(0x92, 0xd0, 0xe3),
        Bad = Color.FromArgb(0xb3, 0x26, 0x1e);
    static readonly PrivateFontCollection Fonts = new PrivateFontCollection();
    static readonly List<IntPtr> Memory = new List<IntPtr>();

    // Fonts for this process only. Text is drawn with GDI+ (compatible text rendering), which uses this collection.
    // GDI+ may append the style to the family name ("Onest Medium Medium"), so a prefix also matches.
    static FontFamily Load(string resource, string name, string fallback)
    {
        try
        {
            using (Stream stream = Installer.Resource(resource))
            {
                var data = new byte[stream.Length];
                stream.Read(data, 0, data.Length);
                IntPtr memory = Marshal.AllocCoTaskMem(data.Length);
                Marshal.Copy(data, 0, memory, data.Length);
                Memory.Add(memory);
                Fonts.AddMemoryFont(memory, data.Length);
            }
            foreach (FontFamily family in Fonts.Families)
                if (family.Name == name) return family;
            foreach (FontFamily family in Fonts.Families)
                if (family.Name.StartsWith(name + " ")) return family;
        }
        catch (Exception) { }
        return new FontFamily(fallback);
    }

    public static readonly FontFamily Display = Load("display.ttf", "Cormorant Garamond Medium", "Georgia");
    public static readonly FontFamily Body = Load("body.ttf", "Onest", "Segoe UI");
    public static readonly FontFamily Medium = Load("medium.ttf", "Onest Medium", "Segoe UI Semibold");
}

class Pill : Control
{
    public bool Primary = true;
    bool hover, pressed;

    public Pill()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint |
                 ControlStyles.SupportsTransparentBackColor, true);
        Cursor = Cursors.Hand;
        Font = new Font(Brand.Medium, 11f);
    }

    protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { hover = false; pressed = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { pressed = true; Invalidate(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
    protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
    protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
    protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }
    // Keyboard: Enter or Space presses the button.
    protected override bool IsInputKey(Keys key) { return key == Keys.Enter || base.IsInputKey(key); }
    protected override void OnKeyDown(KeyEventArgs e) { if ((e.KeyCode == Keys.Enter || e.KeyCode == Keys.Space) && Enabled) OnClick(EventArgs.Empty); base.OnKeyDown(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        g.Clear(Parent != null ? Parent.BackColor : Brand.Paper);
        var box = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        float d = box.Height;
        using (var path = new GraphicsPath())
        {
            path.AddArc(box.X, box.Y, d, d, 90, 180);
            path.AddArc(box.Right - d, box.Y, d, d, 270, 180);
            path.CloseFigure();
            Color fill, text;
            if (!Enabled) { fill = Brand.Stone; text = Brand.Marble; }
            else if (Primary) { fill = hover || pressed ? Brand.Accent : Brand.Ink; text = hover || pressed ? Brand.Ink : Brand.Paper; }
            else { fill = pressed ? Brand.Accent : Brand.Paper; text = Brand.Ink; }
            using (var brush = new SolidBrush(fill)) g.FillPath(brush, path);
            if (!Primary && Enabled)
                using (var pen = new Pen(hover ? Brand.Accent : Brand.Graphite, 1.2f)) g.DrawPath(pen, path);
            g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
            using (var brush = new SolidBrush(text))
            using (var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                g.DrawString(Text, Font, brush, new RectangleF(0, 0, Width, Height), format);
        }
        if (Focused && Enabled)
            using (var pen = new Pen(Brand.Graphite, 1.5f) { DashStyle = DashStyle.Dot }) g.DrawRectangle(pen, 2, 2, Width - 5, Height - 5);
    }
}

class Check : Control
{
    bool on = true;
    public bool Checked { get { return on; } set { on = value; Invalidate(); } }

    public Check()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint |
                 ControlStyles.Selectable, true);
        Cursor = Cursors.Hand;
        TabStop = true;
    }

    protected override void OnClick(EventArgs e) { if (Enabled) Checked = !Checked; base.OnClick(e); }
    protected override void OnKeyDown(KeyEventArgs e) { if (e.KeyCode == Keys.Space && Enabled) Checked = !Checked; base.OnKeyDown(e); }
    protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
    protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }
    protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        Graphics g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        g.Clear(Brand.Paper);
        float size = Height - 6, top = 3, radius = size * 0.28f;
        using (var path = new GraphicsPath())
        {
            path.AddArc(1, top, radius * 2, radius * 2, 180, 90);
            path.AddArc(1 + size - radius * 2, top, radius * 2, radius * 2, 270, 90);
            path.AddArc(1 + size - radius * 2, top + size - radius * 2, radius * 2, radius * 2, 0, 90);
            path.AddArc(1, top + size - radius * 2, radius * 2, radius * 2, 90, 90);
            path.CloseFigure();
            using (var fill = new SolidBrush(on ? Brand.Accent : Brand.Marble)) g.FillPath(fill, path);
            if (!on) using (var pen = new Pen(Brand.Stone, 1.5f)) g.DrawPath(pen, path);
            if (Focused) using (var pen = new Pen(Brand.Graphite, 2f)) g.DrawPath(pen, path);
        }
        if (on)
            using (var pen = new Pen(Brand.Ink, Math.Max(1.6f, size * 0.11f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                g.DrawLines(pen, new[] { new PointF(1 + size * .27f, top + size * .52f), new PointF(1 + size * .43f, top + size * .68f),
                                         new PointF(1 + size * .74f, top + size * .34f) });
        using (var brush = new SolidBrush(Enabled ? Brand.Graphite : Brand.Stone))
        using (var format = new StringFormat { LineAlignment = StringAlignment.Center })
            g.DrawString(Text, Font, brush, new RectangleF(size + 14, 0, Width - size - 14, Height), format);
    }
}

class Bar : Control
{
    int value;
    public int Value { get { return value; } set { this.value = Math.Max(0, Math.Min(100, value)); Invalidate(); } }
    public Bar() { SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint, true); }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(Brand.Mist);
        using (var brush = new SolidBrush(Brand.Accent)) e.Graphics.FillRectangle(brush, 0, 0, Width * value / 100, Height);
    }
}

class SetupForm : Form
{
    readonly Options options;
    readonly Label tag, title, body, folder, error;
    readonly Check desktop;
    readonly Pill primary, secondary, language;
    readonly Bar bar;
    string launcher;

    public SetupForm(Options options)
    {
        this.options = options;
        BackColor = Brand.Paper;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96f, 96f);
        ClientSize = new Size(600, 440);
        try { using (Stream s = Installer.Resource("icon.ico")) Icon = new Icon(s); } catch (Exception) { }

        var mark = new PictureBox { Location = new Point(40, 36), Size = new Size(48, 34), SizeMode = PictureBoxSizeMode.Zoom };
        try { mark.Image = Image.FromStream(Installer.Resource("mark.png")); } catch (Exception) { }
        Controls.Add(mark);
        tag = MakeLabel("", new Font(Brand.Medium, 7.5f), Brand.Graphite2, 98, 48, 300);
        // The other language, in capitals so it is found at once.
        language = new Pill { Primary = false, Location = new Point(440, 36), Size = new Size(120, 34), Font = new Font(Brand.Medium, 9f) };
        language.Click += delegate { L.Ru = !L.Ru; Texts(); };
        Controls.Add(language);
        title = MakeLabel("", new Font(Brand.Display, 24f), Brand.Ink, 40, 92, 520);
        title.Height = 52;
        body = MakeLabel("", new Font(Brand.Body, 11f), Brand.Graphite, 40, 152, 520);
        body.Height = 72;
        folder = MakeLabel("", new Font(Brand.Body, 9f), Brand.Graphite2, 40, 232, 520);
        folder.Height = 36;
        desktop = new Check { Checked = options.Desktop, Location = new Point(40, 270),
                              Size = new Size(320, 30), Font = new Font(Brand.Body, 10.5f) };
        Controls.Add(desktop);
        error = MakeLabel("", new Font(Brand.Body, 10f), Brand.Bad, 40, 306, 520);
        error.Height = 40;
        bar = new Bar { Location = new Point(40, 316), Size = new Size(520, 4), Visible = false };
        Controls.Add(bar);
        primary = new Pill { Location = new Point(40, 360), Size = new Size(180, 48) };
        primary.Click += delegate { if (launcher == null) Install(); else Open(); };
        Controls.Add(primary);
        secondary = new Pill { Primary = false, Location = new Point(232, 360), Size = new Size(140, 48) };
        secondary.Click += delegate { Close(); };
        Controls.Add(secondary);
        AcceptButton = null;
        ActiveControl = primary;  // Enter installs; the language button is reached with Tab
        Texts();
    }

    void Texts()
    {
        Text = L.T("Установка " + Product.Name, "Install " + Product.Name);
        tag.Text = L.T("0-SOFT · НАЧНЁМ С НУЛЯ", "0-SOFT · START FROM ZERO");
        language.Text = L.Ru ? "ENGLISH" : "РУССКИЙ";
        title.Text = L.T("Установка " + Product.Name, "Install " + Product.Name);
        body.Text = L.T("Программа поставится в вашу папку пользователя, права администратора не нужны. " +
                        "Установка ничего не меняет в Claude: сброс и защиту вы запустите сами из окна программы.",
                        "The program goes into your user folder; no administrator rights are needed. " +
                        "Installing changes nothing in Claude: you start the reset and the protection yourself from the program window.");
        folder.Text = L.T("Папка: ", "Folder: ") + options.Home;
        desktop.Text = L.T("Ярлык на рабочем столе", "Desktop shortcut");
        desktop.Invalidate();
        primary.Text = launcher == null ? L.T("Установить", "Install") : L.T("Открыть " + Product.Name, "Open " + Product.Name);
        secondary.Text = launcher == null ? L.T("Отмена", "Cancel") : L.T("Закрыть", "Close");
        primary.Invalidate();
        secondary.Invalidate();
        language.Invalidate();
    }

    Label MakeLabel(string text, Font font, Color color, int x, int y, int width)
    {
        var label = new Label { Text = text, Font = font, ForeColor = color, BackColor = Brand.Paper, Location = new Point(x, y),
                                Size = new Size(width, 24), UseMnemonic = false };
        Controls.Add(label);
        return label;
    }

    void Install()
    {
        options.Desktop = desktop.Checked;
        error.Text = "";
        primary.Enabled = secondary.Enabled = desktop.Enabled = false;
        language.Visible = false;
        bar.Visible = true;
        bar.Value = 0;
        body.Text = L.T("Устанавливаем… Это займёт меньше минуты.", "Installing… This takes less than a minute.");
        var worker = new Thread(delegate ()
        {
            try
            {
                string result = Installer.Run(options, delegate (int percent) { BeginInvoke((Action)delegate { bar.Value = percent; }); });
                BeginInvoke((Action)delegate { Done(result); });
            }
            catch (Exception e)
            {
                string text = e is InstallError ? e.Message : L.T("Не получилось установить: ", "Installation failed: ") + e.Message;
                BeginInvoke((Action)delegate { Failed(text); });
            }
        });
        worker.IsBackground = true;
        worker.Start();
    }

    void Done(string result)
    {
        launcher = result;
        bar.Visible = false;
        desktop.Visible = false;
        title.Text = L.T("Готово", "Done");
        body.Text = L.Ru
            ? Product.Name + " установлен. Ярлык — в меню «Пуск»" + (options.Desktop ? " и на рабочем столе." : ".") +
              " Дальше всё в окне программы: шаг 1 — сброс, шаг 2 — прокси."
            : Product.Name + " is installed. The shortcut is in the Start menu" + (options.Desktop ? " and on the desktop." : ".") +
              " Everything else happens in the program window: step 1 — reset, step 2 — proxy.";
        primary.Text = L.T("Открыть " + Product.Name, "Open " + Product.Name);
        primary.Size = new Size(220, 48);
        secondary.Location = new Point(272, 360);
        secondary.Text = L.T("Закрыть", "Close");
        primary.Enabled = secondary.Enabled = true;
    }

    void Failed(string text)
    {
        bar.Visible = false;
        error.Text = text;
        primary.Text = L.T("Повторить", "Try again");
        primary.Enabled = secondary.Enabled = desktop.Enabled = true;
    }

    void Open()
    {
        try { Process.Start(new ProcessStartInfo(launcher) { WorkingDirectory = options.Home, UseShellExecute = true }); }
        catch (Exception) { }
        Close();
    }
}

static class ClaudeResetSetup
{
    [STAThread]
    static int Main(string[] args)
    {
        Options options;
        try { options = Options.Parse(args); }
        catch (Exception) { return 2; }
        if (options.Quiet)
        {
            try { Console.WriteLine(Installer.Run(options, null)); return 0; }
            catch (Exception e) { Console.Error.WriteLine(e.Message); return 1; }
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(true);
        Application.Run(new SetupForm(options));
        return 0;
    }
}
