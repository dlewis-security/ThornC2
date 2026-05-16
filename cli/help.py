"""HelpMixin — help command and command group definitions."""

from .ui import bold, cyan, grey, orange, err, pad


class HelpMixin:

    # Shown only when a rat is active
    _RAT_CMDS = ("Active Rat", [
        ("shell [relay_host:port]",         "Reverse shell via station TCP relay"),
        ('command "<cmd>" [-w] [-t <s>]',  "Dispatch a single command"),
        ("mode <ps|cmd>",                  "Set rat execution mode (powershell_clr or os_shell)"),
        ("run <#|id> [key=value ...]",     "Dispatch any module by # or ID"),
        ("sysinfo",                        "Dump process/user/OS info from rat"),
        ("sleep <ms>",                     "Update beacon sleep interval"),
        ("shellcode <local_path>",         "Encrypt and deliver shellcode inline"),
        ("inject <pid> <path> [method]",   "Inject shellcode into remote process"),
        ("bof <local_path.o> [args...]",   "Execute BOF (Beacon Object File) inline"),
        ("upload <local> <remote>",        "Push a file to the rat"),
        ("download <remote> <local>",      "Pull a file from the rat"),
        ("die",                            "Kill the implant"),
        ("tasks",                          "Task history"),
        ("output <task_id>",               "Show full task output"),
        (None, "Post-Exploitation (in-memory PS — requires mode ps)"),
        ("mimikatz",                       "Invoke-Mimikatz -DumpCreds in-memory"),
        ("kerberoast [-d domain] [-u user]","Invoke-Kerberoast (Hashcat format)"),
        ("lsass_dump [local_path]",        "Out-MiniDump lsass → auto-download .dmp"),
        ("sharphound [CollectionMethod]",  "BloodHound collector → auto-download zip"),
        ("snaffler [remote_path]",         "Upload+run Snaffler.exe → download output"),
        ("portscan <hosts> <ports>",       "Invoke-Portscan hosts/ports"),
        ("powerupsql",                     "PowerUpSQL domain SQL discovery"),
        (None, "Tunnelling"),
        ("socks5 start [port]",            "Start SOCKS5 proxy through implant (default :1080)"),
        ("socks5 stop",                    "Stop active SOCKS5 proxy"),
        ("socks5 status",                  "Check SOCKS5 proxy state"),
    ])

    # All command groups — used by do_help
    _HELP_GROUPS = [
        ("rat", "Rats", [
            ("rats",                           "List all rats"),
            ("use <# | rat_id>",               "Set active rat context"),
            ("back",                           "Clear active rat context"),
            ("info",                           "Show active rat details"),
            ("kill [# | rat_id | all]",        "Send die to implant and delete rat record"),
        ]),
        ("resources", "Resources", [
            ("modules [search]",               "List available modules  (sets # index)"),
            ("implants [search]",              "List generated implants"),
            ("stagers [search]",               "List generated stagers"),
            ("stations [search]",              "List generated stations"),
            ("shellcode",                      "List shellcode files"),
        ]),
        ("build", "Build", [
            (None, "Config"),
            ("build show",                     "Show build config + status"),
            ("build config",                   "Edit payload config (key/IV/URLs/filenames/imp_id)"),
            ("build local [on|off|status]",    "Toggle local (in-process cargo) vs server build"),
            (None, "Implant"),
            ("build implant <language>",       "Build implant"),
            (None, "Stager"),
            ("build stager <language>",        "Build stager"),
            ("build zip",                      "Queue full pipeline + ZIP packaging on server"),
            ("build jscript",                  "Generate obfuscated JScript stager"),
            ("build lnk",                      "Generate LNK shortcut"),
            (None, "Station"),
            ("build station",                  "Assemble station from component snippets"),
            (None, "Utilities"),
            ("build thornldr",                 "Recompile ThornLDR stub (clears cache)"),
            ("build encrypt <file> [out]",     "AES-encrypt a shellcode file for shellcode_load"),
            ("build bof <file.o>",             "Pack + encrypt a BOF for inline dispatch to rat"),
            ("build thornbof",                 "Recompile COFF loader stub (clears cache)"),
            ("build deliver",                  "Push stager to active rat via PowerShell download-exec"),
        ]),
        ("post", "Post-Exploitation (operator-side impacket)", [
            (None, "All commands auto-fill target from active rat context"),
            ("post secretsdump [DOMAIN/user:pass@target]", "Dump secrets via impacket"),
            ("post kerberoast  [DOMAIN/user:pass@target]", "Kerberoast with GetUserSPNs"),
            ("post asreproast  [DOMAIN/user@target]",      "AS-REP roast with GetNPUsers"),
            ("post psexec      [DOMAIN/user:pass@target]", "Remote exec via psexec"),
            ("post wmiexec     [DOMAIN/user:pass@target]", "Remote exec via WMI"),
            ("post smbexec     [DOMAIN/user:pass@target]", "Remote exec via SMB service"),
            ("post ntlmrelay   -t <target> [args]",        "ntlmrelayx relay attack"),
            ("post dacledit    [DOMAIN/user:pass@target]", "Read/write DACL entries"),
            ("post rbcd        [DOMAIN/user:pass@target]", "Resource-based constrained delegation"),
            ("post certipy     <find|req|auth|...> [args]","AD CS abuse via certipy"),
        ]),
        ("logs", "Logs", [
            ("log [--imp <id>] [--rat <id>] [--limit <n>]", "Show activity log (newest first)"),
            ("report [--imp <id>] [filename]", "Export engagement report as markdown"),
        ]),
        ("user", "Users", [
            ("users",                          "List operators and their implant access"),
            ("useradd <username>",             "Create operator account and print API key"),
            ("userdel <username>",             "Delete an operator account"),
            ("grant <username> <imp_id>",      "Give a user access to an implant ID"),
            ("revoke <username> <imp_id>",     "Remove a user's access to an implant ID"),
        ]),
        ("system", "System", [
            (None, "Config"),
            ("config <url> <api_key>",         "Save/update the default connection profile"),
            ("config <name> <url> <api_key>",  "Save a named profile for multiple C2 servers"),
            ("config list",                    "List all profiles  (* = active)"),
            ("config use <name>",              "Switch active profile"),
            ("config del <name>",              "Delete a profile"),
            (None, "Telegram"),
            ("telegram <bot_token> <chat_id>", "Enable Telegram notifications"),
            ("telegram test",                  "Send a test message with saved credentials"),
            ("telegram off",                   "Disable Telegram notifications"),
            (None, "System"),
            ("reload",                         "Reload modules from disk"),
            ("theme [name]",                   "Switch color theme"),
            ("help all",                       "Full command reference"),
            ("exit / quit",                    "Exit the console"),
        ]),
    ]

    def _print_group(self, title, cmds):
        print(f"  {bold(orange(title))}")
        for name, desc in cmds:
            if name is None:
                print(f"\n    {orange(desc)}")
            else:
                print(f"    {pad(cyan(name), 38)}  {grey(desc)}")
        print()

    def do_help(self, arg):
        """help [section|all]  —  Show help (section: rats resources build logs users system)"""
        arg = arg.strip().lower()

        # 'help all' → full reference
        if arg == "all":
            print()
            if self.active_rat:
                self._print_group(*self._RAT_CMDS)
            for _, title, cmds in self._HELP_GROUPS:
                self._print_group(title, cmds)
            return

        # 'help <section>' → just that section
        if arg:
            match = next(((t, c) for k, t, c in self._HELP_GROUPS if k.startswith(arg)), None)
            if match:
                print()
                self._print_group(*match)
            else:
                err(f"Unknown section '{arg}'  —  sections: " +
                    "  ".join(k for k, _, _ in self._HELP_GROUPS))
            return

        # bare 'help' → show active rat commands first if in rat context, then sections
        print()
        if self.active_rat:
            self._print_group(*self._RAT_CMDS)
        sections = "  ·  ".join(cyan(k) for k, _, _ in self._HELP_GROUPS)
        print(f"  {bold(orange('Sections:'))}  {sections}")
        print()
        print(f"    {pad(cyan('help <section>'), 38)}  {grey('show commands for a section')}")
        print(f"    {pad(cyan('help all'), 38)}  {grey('full command reference')}")
        print()

    # Section shortcuts — typing the section name shows its help
    def do_rat(self, arg):       self.do_help("rat")
    def do_user(self, arg):      self.do_help("user")
    def do_resources(self, arg): self.do_help("resources")
    def do_logs(self, arg):      self.do_help("logs")
    def do_system(self, arg):    self.do_help("system")
