# Copyright (C) 10se1ucgo 2015-2016
#
# This file is part of DisableWinTracking.
#
# DisableWinTracking is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# DisableWinTracking is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with DisableWinTracking.  If not, see <http://www.gnu.org/licenses/>.
import io
import logging
import platform
import sys
import traceback
import webbrowser
from ctypes import windll

import wx
from wx.lib.itemspicker import ItemsPicker, IP_SORT_SELECTED, IP_SORT_CHOICES, IP_REMOVE_FROM_CHOICES

import dwt_about
import dwt_util


class RedirectText(io.StringIO):
    def __init__(self, console, old_stdout):
        super(RedirectText, self).__init__()

        self.out = console
        self.old_out = old_stdout

        reload(sys)  # Reload does the trick!
        sys.setdefaultencoding('UTF8')

    def write(self, string):
        # Oh my god this is the DUMBEST THING I've ever done. (Keeping a reference to the old stdout)
        self.old_out.write(string)
        self.out.WriteText(string)


class ConsoleDialog(wx.Dialog):
    def __init__(self, old_stdout):
        wx.Dialog.__init__(self, parent=wx.GetApp().TopWindow, title="Console Output", size=(500, 200),
                           style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)

        console_box = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sys.stdout = RedirectText(console_box, old_stdout)

        top_sizer = wx.BoxSizer(wx.VERTICAL)
        console_sizer = wx.BoxSizer(wx.VERTICAL)
        button_sizer = self.CreateButtonSizer(wx.OK | wx.CANCEL)

        report_button = wx.FindWindowById(wx.ID_CANCEL, self)
        report_button.SetLabel("Report an issue")

        console_sizer.Add(console_box, 1, wx.LEFT | wx.RIGHT | wx.EXPAND | wx.ALIGN_TOP, 5)

        top_sizer.Add(console_sizer, 1, wx.ALL | wx.EXPAND, 5)
        top_sizer.Add(button_sizer, 0, wx.ALL | wx.ALIGN_LEFT, 5)

        self.Bind(wx.EVT_CLOSE, handler=lambda x: sys.exit(0))
        self.Bind(wx.EVT_BUTTON, handler=lambda x: sys.exit(0), id=wx.ID_OK)
        self.Bind(wx.EVT_BUTTON, source=report_button, handler=self.submit_issue)
        self.SetSizer(top_sizer)

    def submit_issue(self, event):
        webbrowser.open_new_tab("https://github.com/10se1ucgo/DisableWinTracking/issues/new")


class MainFrame(wx.Frame):
    def __init__(self):
        super(MainFrame, self).__init__(parent=wx.GetApp().GetTopWindow(), title="Disable Windows 10 Tracking",
                                        size=(415, 245))
        self.SetMinSize(self.GetSize())
        panel = MainPanel(self)

        file_menu = wx.Menu()
        settings = file_menu.Append(wx.ID_SETUP, "&Settings", "DWT settings")

        help_menu = wx.Menu()
        about = help_menu.Append(wx.ID_ABOUT, "&About", "About DWT")
        licenses = help_menu.Append(wx.ID_ANY, "&Licenses", "Open-source licenses")

        menu_bar = wx.MenuBar()
        menu_bar.Append(file_menu, "&File")
        menu_bar.Append(help_menu, "&Help")
        self.SetMenuBar(menu_bar)

        check_elevated()

        self.SetIcon(wx.Icon(sys.executable, wx.BITMAP_TYPE_ICO))
        self.Bind(wx.EVT_MENU, lambda x: dwt_about.about_dialog(self), about)
        self.Bind(wx.EVT_MENU, panel.settings, settings)
        self.Bind(wx.EVT_MENU, lambda x: dwt_about.Licenses(self), licenses)
        self.Layout()


class MainPanel(wx.Panel):
    def __init__(self, parent):
        super(MainPanel, self).__init__(parent)

        self.parent = parent
        self.unpicked_ads = []
        self.picked_normal = []
        self.picked_extra = []
        self.picked_ips = []

        self.service_check = wx.CheckBox(self, label="Services")
        self.service_check.SetToolTip("Disables or deletes tracking services. Choose option in 'Services Method'")
        self.service_check.SetValue(1)

        self.diagtrack_check = wx.CheckBox(self, label="Clear DiagTrack log")
        self.diagtrack_check.SetToolTip("Clears Dianostic Tracking log and prevents modification to it.")
        self.diagtrack_check.SetValue(1)

        # Telemetry checkbox
        self.telemetry_check = wx.CheckBox(self, label="Telemetry")
        self.telemetry_check.SetToolTip("Sets 'AllowTelemetry' to 0. "
                                        "On non-Enterprise OS editions, requires HOSTS file modification.")
        self.telemetry_check.SetValue(1)

        # Ad HOSTS file checkbox
        self.ads_check = wx.CheckBox(self, label="Block ad domains")
        self.ads_check.SetToolTip("Adds known ad domains to HOSTS file.")
        self.ads_check.SetValue(1)

        # HOSTS file checkbox
        self.host_check = wx.CheckBox(self, label="Block tracking domains")
        self.host_check.SetToolTip("Adds known tracking domains to HOSTS file. Required to disable Telemetry")
        self.host_check.SetValue(1)

        # Extra HOSTS checkbox
        self.extra_host_check = wx.CheckBox(self, label="Block even more tracking domains")
        self.extra_host_check.SetToolTip("For the paranoid. Adds extra domains to the HOSTS file.\n"
                                         "May cause issues with Skype, Dr. Watson, Hotmail and/or Error Reporting.")

        # Flush DNS Service
        self.flush_dns_check = wx.CheckBox(self, label="Flush DNS Service")
        self.flush_dns_check.SetToolTip("")
        self.flush_dns_check.SetValue(1)

        # IP block checkbox
        self.ip_check = wx.CheckBox(self, label="Block tracking IP addresses")
        self.ip_check.SetToolTip("Blocks known tracking IP addresses with Windows Firewall.")

        # WifiSense checkbox
        self.wifisense_check = wx.CheckBox(self, label="WifiSense")

        # OneDrive uninstall checkbox
        self.onedrive_check = wx.CheckBox(self, label="Uninstall OneDrive")
        self.onedrive_check.SetToolTip("Uninstalls OneDrive from your computer and removes it from Explorer.")

        self.service_rad = wx.RadioBox(self, label="Service Method", choices=("Disable", "Delete"))
        self.service_rad.SetItemToolTip(item=0, text="Simply disables the services. This can be undone.")
        self.service_rad.SetItemToolTip(item=1, text="Deletes the services completely. This can't be undone.")

        self.mode_rad = wx.RadioBox(self, label="Mode", choices=("Privacy", "Revert"))
        self.mode_rad.SetItemToolTip(item=0, text="Applies the selected settings.")
        self.mode_rad.SetItemToolTip(item=1, text="Reverts the selected settings.")

        go_button = wx.Button(self, label="Go!")

        top_sizer = wx.BoxSizer(wx.VERTICAL)
        top_row_sizer = wx.BoxSizer(wx.HORIZONTAL)
        check_sizer = wx.BoxSizer(wx.VERTICAL)
        rad_sizer = wx.BoxSizer(wx.VERTICAL)

        top_sizer.Add(top_row_sizer, 0, wx.ALL, 5)
        # top_sizer.Add(self.app_box, 0, wx.ALL, 5)
        top_row_sizer.Add(check_sizer, 0, wx.ALL)
        top_row_sizer.Add(rad_sizer, 0, wx.ALL)
        rad_sizer.Add(self.service_rad, 0, wx.ALL, 10)
        rad_sizer.Add(go_button, 0, wx.ALL ^ wx.BOTTOM | wx.ALIGN_CENTER, 10)
        rad_sizer.Add(self.mode_rad, 0, wx.ALL, 10)
        check_sizer.Add(self.service_check, 0, wx.ALL, 1)
        check_sizer.Add(self.diagtrack_check, 0, wx.ALL, 1)
        check_sizer.Add(self.telemetry_check, 0, wx.ALL, 1)
        check_sizer.Add(self.ads_check, 0, wx.ALL, 1)
        check_sizer.Add(self.host_check, 0, wx.ALL, 1)
        check_sizer.Add(self.extra_host_check, 0, wx.ALL, 1)
        check_sizer.Add(self.flush_dns_check, 0, wx.ALL, 1)
        check_sizer.Add(self.ip_check, 0, wx.ALL, 1)
        check_sizer.Add(self.wifisense_check, 0, wx.ALL, 1)
        check_sizer.Add(self.onedrive_check, 0, wx.ALL, 1)

        # self.Bind(wx.EVT_CHECKBOX, handler=self.select_all_apps, source=select_all_check)
        self.Bind(wx.EVT_CHECKBOX, handler=self.ip_warn, source=self.ip_check)
        self.Bind(wx.EVT_CHECKBOX, handler=self.hosts_warn, source=self.extra_host_check)
        self.Bind(wx.EVT_BUTTON, handler=self.go, source=go_button)

        self.SetSizer(top_sizer)

    def select_all_apps(self, event):
        # Iters through all children of the wxStaticBox of the wxStaticBoxSizer and checks/un checks all wxCheckBoxes.
        for child in self.app_box.GetStaticBox().GetChildren():
            if isinstance(child, wx.CheckBox):
                child.SetValue(event.IsChecked())

    def ip_warn(self, event):
        # Warn users about the potential side effects of the IP blocking firewall rules
        if event.IsChecked():
            warn = wx.MessageDialog(parent=self,
                                    message="This option could potentially disable Microsoft Licensing traffic and thus "
                                            "certain games and apps may cease to work, such as, Forza, or Gears of War.",
                                    caption="Attention!", style=wx.YES_NO | wx.ICON_EXCLAMATION)

            if warn.ShowModal() == wx.ID_NO:
                event.GetEventObject().SetValue(False)

            warn.Destroy()

    def hosts_warn(self, event):
        # Warn users about the potential side effects of the extra hosts mod.
        if event.IsChecked():
            warn = wx.MessageDialog(parent=self,
                                    message="This option could potentially disable one or more of the following "
                                            "services:\n\nSkype, Hotmail, Dr. Watson and/or Error Reporting. Continue?",
                                    caption="Attention!", style=wx.YES_NO | wx.ICON_EXCLAMATION)

            if warn.ShowModal() == wx.ID_NO:
                event.GetEventObject().SetValue(False)

            warn.Destroy()

    def go(self, event):
        if not all((self.unpicked_ads, self.picked_ips, self.picked_extra, self.picked_normal)):
            self.settings(event=None)

        undo = bool(self.mode_rad.GetSelection())

        if self.ip_check.IsChecked():
            dwt_util.ip_block(self.picked_ips, undo=undo)
        if self.diagtrack_check.IsChecked():
            dwt_util.clear_diagtrack()
        if self.service_check.IsChecked():
            if self.service_rad.GetSize():
                dwt_util.delete_service("dmwappushsvc")
                dwt_util.delete_service("DiagTrack")
            else:
                dwt_util.disable_service("dmwappushsvc")
                dwt_util.disable_service("DiagTrack")
            dwt_util.services(undo=undo)
        if self.telemetry_check.IsChecked():
            dwt_util.telemetry(undo=undo)
        if self.ads_check.IsChecked():
            dwt_util.hosts_ad_removal(self.unpicked_ads, undo=undo)
        if self.host_check.IsChecked():
            dwt_util.host_file(self.picked_normal, undo=undo)
        if self.extra_host_check.IsChecked():
            dwt_util.host_file(self.picked_extra, undo=undo)
        if self.defender_check.IsChecked():
            dwt_util.defender(undo=undo)
        if self.flush_dns_check.IsChecked():
            dwt_util.flush_dns()
        if self.wifisense_check.IsChecked():
            dwt_util.wifisense(undo=undo)
        if self.onedrive_check.IsChecked():
            dwt_util.onedrive(undo=undo)
        logger.info("Done. It's recommended that you reboot as soon as possible for the full effect.")
        logger.info(("If you feel something didn't work properly, please press the 'Report an issue'"
                     " button and follow the directions"))
        console.Center()
        console.Show()

    def settings(self, event, silent=False):
        if silent == False:
            dialog = wx.Dialog(parent=self, title="Settings", style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
            sizer = wx.BoxSizer(wx.VERTICAL)

        normal_domains = (
            'a-0001.a-msedge.net', 'a-0002.a-msedge.net', 'a-0003.a-msedge.net', 'a-0004.a-msedge.net',
            'a-0005.a-msedge.net', 'a-0006.a-msedge.net', 'a-0007.a-msedge.net', 'a-0008.a-msedge.net',
            'a-0009.a-msedge.net', 'a-msedge.net', 'a.ads1.msn.com', 'a.ads2.msads.net', 'a.ads2.msn.com',
            'a.rad.msn.com', 'ac3.msn.com', 'ad.doubleclick.net', 'adnexus.net', 'adnxs.com', 'ads.msn.com',
            'ads1.msads.net', 'ads1.msn.com', 'aidps.atdmt.com', 'aka-cdn-ns.adtech.de',
            'az361816.vo.msecnd.net', 'az512334.vo.msecnd.net', 'b.ads1.msn.com', 'b.ads2.msads.net',
            'b.rad.msn.com', 'bs.serving-sys.com', 'c.atdmt.com', 'c.msn.com', 'cdn.atdmt.com',
            'cds26.ams9.msecn.net', 'choice.microsoft.com', 'choice.microsoft.com.nsatc.net',
            'compatexchange.cloudapp.net', 'corp.sts.microsoft.com', 'corpext.msitadfs.glbdns2.microsoft.com',
            'cs1.wpc.v0cdn.net', 'db3aqu.atdmt.com', 'df.telemetry.microsoft.com',
            'diagnostics.support.microsoft.com', 'ec.atdmt.com', 'feedback.microsoft-hohm.com',
            'feedback.search.microsoft.com', 'feedback.windows.com', 'flex.msn.com', 'g.msn.com', 'h1.msn.com',
            'i1.services.social.microsoft.com', 'i1.services.social.microsoft.com.nsatc.net',
            'lb1.www.ms.akadns.net', 'live.rads.msn.com', 'm.adnxs.com', 'msedge.net', 'msftncsi.com',
            'msnbot-65-55-108-23.search.msn.com', 'msntest.serving-sys.com', 'oca.telemetry.microsoft.com',
            'oca.telemetry.microsoft.com.nsatc.net', 'pre.footprintpredict.com', 'preview.msn.com',
            'rad.live.com', 'rad.msn.com', 'redir.metaservices.microsoft.com', 'schemas.microsoft.akadns.net',
            'secure.adnxs.com', 'secure.flashtalking.com', 'settings-sandbox.data.microsoft.com',
            'settings-win.data.microsoft.com', 'sls.update.microsoft.com.akadns.net', 'sqm.df.telemetry.microsoft.com',
            'sqm.telemetry.microsoft.com', 'sqm.telemetry.microsoft.com.nsatc.net', 'ssw.live.com',
            'static.2mdn.net', 'statsfe1.ws.microsoft.com', 'statsfe2.ws.microsoft.com',
            'telecommand.telemetry.microsoft.com', 'telecommand.telemetry.microsoft.com.nsatc.net',
            'telemetry.appex.bing.net', 'telemetry.microsoft.com', 'telemetry.urs.microsoft.com',
            'v10.vortex-win.data.microsoft.com', 'vortex-bn2.metron.live.com.nsatc.net',
            'vortex-cy2.metron.live.com.nsatc.net', 'vortex-sandbox.data.microsoft.com',
            'vortex-win.data.metron.live.com.nsatc.net', 'vortex-win.data.microsoft.com',
            'vortex.data.glbdns2.microsoft.com', 'vortex.data.microsoft.com', 'watson.live.com',
            'web.vortex.data.microsoft.com', 'www.msftncsi.com',

            'fe2.update.microsoft.com.akadns.net', 'view.atdmt.com', 'watson.telemetry.microsoft.com',
            'watson.telemetry.microsoft.com.nsatc.net', 'reports.wes.df.telemetry.microsoft.com',
            'services.wes.df.telemetry.microsoft.com', 'wes.df.telemetry.microsoft.com'
        )

        extra_domains = (
            's0.2mdn.net', 'statsfe2.update.microsoft.com.akadns.net', 'survey.watson.microsoft.com',
            'watson.microsoft.com', 'watson.ppe.telemetry.microsoft.com', 'ui.skype.com',
            'pricelist.skype.com', 'apps.skype.com', 'm.hotmail.com', 's.gateway.messenger.live.com'
        )

        ip_addresses = (
            '2.22.61.43', '2.22.61.66', '65.39.117.230', '65.55.108.23', '23.218.212.69', '134.170.30.202',
            '137.116.81.24', '157.56.106.189', '204.79.197.200', '65.52.108.33', '64.4.54.254'
        )

        adblock_whitelist = (
            'clickserve.dartsearch.net', 'tc.tradetracker.net', 'www.googleadservices.com', 'googleadservices.com',
            'ad.doubleclick.net'
        )

        normal_domain_picker = ItemsPicker(dialog, choices=[], selectedLabel="Domains to be blocked",
                                           ipStyle=IP_SORT_SELECTED | IP_SORT_CHOICES | IP_REMOVE_FROM_CHOICES)
        if self.picked_normal:
            normal_domain_picker.SetSelections(self.picked_normal)
            normal_domain_picker.SetItems([domain for domain in normal_domains if domain not in self.picked_normal])
        else:
            normal_domain_picker.SetSelections(normal_domains)

        extra_domain_picker = ItemsPicker(dialog, choices=[], selectedLabel="Extra domains to be blocked",
                                          ipStyle=IP_SORT_SELECTED | IP_SORT_CHOICES | IP_REMOVE_FROM_CHOICES)
        if self.picked_extra:
            extra_domain_picker.SetSelections(self.picked_extra)
            extra_domain_picker.SetItems([domain for domain in extra_domains if domain not in self.picked_extra])
        else:
            extra_domain_picker.SetSelections(extra_domains)

        ip_picker = ItemsPicker(dialog, choices=[], selectedLabel="IP addresses to be blocked",
                                ipStyle=IP_SORT_SELECTED | IP_SORT_CHOICES | IP_REMOVE_FROM_CHOICES)
        if self.picked_ips:
            ip_picker.SetSelections(self.picked_ips)
            ip_picker.SetItems([ip for ip in ip_addresses if ip not in self.picked_ips])
        else:
            ip_picker.SetSelections(ip_addresses)

        whitelist_picker = ItemsPicker(dialog, choices=[], selectedLabel="Domains to be whitelisted",
                                       ipStyle=IP_SORT_SELECTED | IP_SORT_CHOICES | IP_REMOVE_FROM_CHOICES)
        if self.unpicked_ads:
            whitelist_picker.SetSelections(self.unpicked_ads)
            whitelist_picker.SetItems([domain for domain in adblock_whitelist if domain not in self.unpicked_ads])
        else:
            whitelist_picker.SetSelections(adblock_whitelist)

        if silent == False:
            sizer.Add(normal_domain_picker, 0, wx.EXPAND)
            sizer.Add(whitelist_picker, 0, wx.EXPAND)
            sizer.Add(extra_domain_picker, 0, wx.EXPAND)
            sizer.Add(ip_picker, 0, wx.EXPAND)
            if event is not None:
                dialog.SetSizerAndFit(sizer)
                dialog.Center()
                dialog.ShowModal()
            dialog.Destroy()

        self.unpicked_ads = whitelist_picker.GetSelections()
        self.picked_normal = normal_domain_picker.GetSelections()
        self.picked_extra = extra_domain_picker.GetSelections()
        self.picked_ips = ip_picker.GetSelections()


def setup_logging():
    global logger
    logger = logging.getLogger('dwt')
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S')

    stdout_log = logging.StreamHandler(sys.stdout)
    stdout_log.setLevel(logging.DEBUG)
    stdout_log.setFormatter(formatter)
    logger.addHandler(stdout_log)

    try:
        file_log = logging.FileHandler(filename='dwt.log')
        file_log.setLevel(logging.DEBUG)
        file_log.setFormatter(formatter)
        logger.addHandler(file_log)
    except (OSError, IOError):
        error_dialog = wx.MessageDialog(parent=wx.GetApp().GetTopWindow(),
                                        message="Could not create log file, errors will not be recorded!",
                                        caption="ERROR!", style=wx.OK | wx.ICON_ERROR)
        error_dialog.ShowModal()
        error_dialog.Destroy()
        logger.exception("Could not create log file.")

    logger.info("Python {version} on {platform}".format(version=sys.version, platform=sys.platform))
    logger.info(platform.uname())
    logger.info("DisableWinTracking version {v}".format(v=dwt_about.__version__))


def exception_hook(error, value, trace):
    error_message = ''.join(traceback.format_exception(error, value, trace))
    logger.critical(error_message)
    error_dialog = wx.MessageDialog(parent=wx.GetApp().GetTopWindow(),
                                    message="An error has occured!\n\n" + error_message,
                                    caption="ERROR!", style=wx.OK | wx.CANCEL | wx.ICON_ERROR)
    error_dialog.SetOKCancelLabels("Ignore", "Quit")
    if error_dialog.ShowModal() == wx.ID_OK:
        error_dialog.Destroy()
    else:
        error_dialog.Destroy()
        sys.exit(1)


def check_elevated(silent=False):
    if not bool(windll.advpack.IsNTAdmin(0, None)):
        if silent:
            windll.shell32.ShellExecuteW(None, u"runas", unicode(sys.executable),
                                         u"{0} -silent".format(unicode(__file__)), None, 1)
            sys.exit(1)
        else:
            windll.shell32.ShellExecuteW(None, u"runas", unicode(sys.executable), unicode(__file__), None, 1)
        sys.exit(1)


def silent():
    setup_logging()
    check_elevated(True)

    dwt_util.clear_diagtrack()
    dwt_util.disable_service("dmwappushsvc")
    dwt_util.disable_service("DiagTrack")
    dwt_util.services(0)
    dwt_util.telemetry(0)
    dwt_util.wifisense(0)
    dwt_util.onedrive(0)

    logger.info("COMPLETE")


if __name__ == '__main__':
    if '-silent' in sys.argv:
        silent()
        sys.exit(0)

    wx_app = wx.App()
    frame = MainFrame()
    console = ConsoleDialog(sys.stdout)
    setup_logging()
    sys.excepthook = exception_hook
    dwt_about.update_check(None)
    frame.Show()
    wx_app.MainLoop()
