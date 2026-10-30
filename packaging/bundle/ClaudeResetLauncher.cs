// ClaudeReset.exe in an installed copy: starts the window with the bundled Python, no console.
// Built by tools/build_bundle.py with the .NET Framework compiler; arguments are passed through (e.g. --expert).
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Forms;

static class L
{
    // The launcher cannot know the window's language yet: its rare error messages are in both.
    public static string T(string ru, string en) { return ru + "\n\n" + en; }
}

static class ClaudeResetLauncher
{
    [STAThread]
    static int Main(string[] args)
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        // An installed copy keeps each version in app-<version>; current.txt names the one to start.
        string pointer = Path.Combine(root, "current.txt");
        if (File.Exists(pointer))
        {
            string version = File.ReadAllText(pointer).Trim();
            if (!System.Text.RegularExpressions.Regex.IsMatch(version, @"^app-[0-9A-Za-z.\-]+$"))
            {
                MessageBox.Show(L.T("Файл версии повреждён. Установите " + Product.Name + " заново.", "The version file is damaged. Install " + Product.Name + " again."), Product.Name,
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
            root = Path.Combine(root, version);
        }
        string python = Path.Combine(root, "python", "pythonw.exe");
        string launcher = Path.Combine(root, "src", "launcher.py");
        if (!File.Exists(python) || !File.Exists(launcher))
        {
            MessageBox.Show(L.T("Файлы программы не найдены. Установите " + Product.Name + " заново.", "The program files were not found. Install " + Product.Name + " again."), Product.Name,
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        // -E -s: no PYTHON* variables and no per-user packages from outside the program.
        var line = new StringBuilder("-E -s ").Append(Quote(launcher));
        foreach (string arg in args)
            line.Append(' ').Append(Quote(arg));
        var start = new ProcessStartInfo(python, line.ToString());
        start.WorkingDirectory = root;
        start.UseShellExecute = false;
        try
        {
            Process.Start(start);
            return 0;
        }
        catch (Exception)
        {
            MessageBox.Show(L.T("Не удалось запустить " + Product.Name + ". Установите программу заново.", Product.Name + " could not start. Install the program again."), Product.Name,
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    static string Quote(string value)
    {
        // Windows command-line quoting: backslashes before a quote are doubled.
        var result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { result.Append('\\', slashes * 2 + 1).Append('"'); slashes = 0; continue; }
            result.Append('\\', slashes).Append(c);
            slashes = 0;
        }
        result.Append('\\', slashes * 2).Append('"');
        return result.ToString();
    }
}
