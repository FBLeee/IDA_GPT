import functools
import json
import os
import re
import textwrap
import threading
import gettext

import requests
import sys
import urllib3
import time

import idaapi
import ida_hexrays
import ida_kernwin
import idc

#代理
import winreg


# Bard
import bardapi.core
import requests
from bardapi import Bard, SESSION_HEADERS
import json
# =============================================================================
# EDIT VARIABLES IN THIS SECTION
# =============================================================================





# Specify the program language. It can be "fr_FR", "zh_CN", or any folder in Fbl-locales.
# Defaults to English.
language = "zh_CN"

# =============================================================================
# END
# =============================================================================

# Set up translations
translate = gettext.translation('gepetto',
                                os.path.join(os.path.abspath(
                                    os.path.dirname(__file__)), "gepetto-locales"),
                                fallback=True,
                                languages=[language])
_ = translate.gettext

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================


class Fbleee_16k_SrcPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "Fbleee_16k:explain_function"
    explain_menu_path = "Edit/Fbleee_16k/" + _("Explain function")
    rename_action_name = "Fbleee_16k:rename_function"
    rename_menu_path = "Edit/Fbleee_16k/" + _("Rename variables")
    wanted_name = 'Fbleee_16k'
    wanted_hotkey = ''
    comment = _("Uses Fbleee_16k to enrich the decompiler's output")
    help = _("See usage instructions on GitHub")
    menu = None

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              _('Explain function'),
                                              ExplainHandler(),
                                              "Ctrl+Alt+9",
                                              _('Use Fbleee_16k to explain the currently selected function'),
                                              199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(
            self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)

        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             _('Rename variables'),
                                             RenameHandler(),
                                             "Ctrl+Alt+0",
                                             _("Use Fbleee_16k to rename this function's variables"),
                                             199)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(
            self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(
            self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(
            self.rename_menu_path, self.rename_action_name)
        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

# 右键菜单，需保证explain_action_name唯一，否则会造成混乱


class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(
                form, popup, Fbleee_16k_SrcPlugin.explain_action_name, "Fbleee_16k/")     #此处不能和以前的重名，也不能包含，比如以前是FBLEEE，现在不能叫FBL\FBLE\FBLEE\F\FB
            idaapi.attach_action_to_popup(
                form, popup, Fbleee_16k_SrcPlugin.rename_action_name, "Fbleee_16k/")       

# -----------------------------------------------------------------------------


def comment_callback(address, view, response):
    """
    在给定地址设置评论的回调。
     :param address: 要注释的函数地址
     :param view: 反编译器窗口的句柄
     :param response: 要添加的评论
    """
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA, but preserve any existing non-Fbleee_16k comment
    comment = idc.get_func_cmt(address, 0)
    comment = re.sub(r'----- ' + _("Comment generated by Fbleee_16k") + ' -----.*?----------------------------------------',
                     r"",
                     comment,
                     flags=re.DOTALL)

    idc.set_func_cmt(address, '----- ' + _("Comment generated by GPT_3.5_turbo_16k") +
                     f" -----\n\n"
                     f"{response.strip()}\n\n"
                     f"----------------------------------------\n\n"
                     f"{comment.strip()}", 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print(_("Fbleee_16k query finished!"))


# -----------------------------------------------------------------------------

class ExplainHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying bard-3.5-turbo for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(_("分析以下C函数的功能：\n"
                            "{decompiler_output}").format(decompiler_output=str(decompiler_output)),
                          functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------


def rename_lvar(ea, src, dst):
    def make_unique_name(name, taken):
        if name not in taken:
            return name
        fmt = "%s_%%i" % name
        for i in range(3, 1024):
            tmpName = fmt % i
            if tmpName not in taken:
                return tmpName
        return "i_give_up"

    #  if you want to use an existing view:
    #      widget = ida_kernwin.find_widget('Pseudocode-Y')
    #      vu = ida_hexrays.get_widget_vdui(widget)
    func = idaapi.get_func(ea)
    if func:
        ea = func.start_ea
        vu = idaapi.open_pseudocode(ea, 0)
        names = [n.name for n in vu.cfunc.lvars]
        if dst in names:
            dst = make_unique_name(dst, names)
        lvars = [n for n in vu.cfunc.lvars if n.name == src]
        if len(lvars) == 1:
            print("renaming {} to {}".format(lvars[0].name, dst))
            vu.rename_lvar(lvars[0], dst, 1)
            # how to close the view without a widget object?
            #     idautils.close_pseudocode (nope)
            #     ida_kerwin.close_widget   (nope)
        else:
            print("couldn't find var {}".format(src))


def rename_callback(address, view, response, retries=0):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from bard-3.5-turbo
    :param retries: The number of times that we received invalid JSON
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:  # Give up obtaining the JSON after 3 times.
            print(_("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
            print(response)
            return
        print(
            _("Cannot extract valid JSON from the response. Asking the model to fix it..."))
        query_model_async(_("The JSON document provided in this response is invalid. Can you fix it?\n"
                            "{response}").format(response=response),
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1))
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:  # Give up fixing the JSON after 3 times.
            print(_("Could not obtain valid data from the model, giving up. Dumping the response for manual import:"))
            print(response)
            return
        print(_("The JSON document returned is invalid. Asking the model to fix it..."))
        query_model_async(_("Please fix the following JSON document:\n{json}").format(json=j.group(0)),
                          functools.partial(rename_callback,
                                            address=address,
                                            view=view,
                                            retries=retries + 1))
        return

    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea

    replaced = []
    for n in names:
        if rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print(
        _("Fbleee_16k query finished! {replaced} variable(s) renamed.").format(replaced=len(replaced)))

# -----------------------------------------------------------------------------


class RenameHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from bard-3.5-turbo and updates the
    decompiler's output.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(_("As a senior retrograde engineer, please analyze the following C function in detail:\n{decompiler_output}"
                            "\nSuggest better variable names, reply with a JSON array where keys are the original names "
                            "and values are the proposed names. Do not explain anything, only print the JSON "
                            "dictionary.").format(decompiler_output=str(decompiler_output)),
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS




#获取系统代理信息
class ProxyServer:
 
    def __init__(self):
        self.__path = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        self.__INTERNET_SETTINGS = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER,
                                                    self.__path, 0, winreg.KEY_ALL_ACCESS)
 
    def get_server_form_Win(self):
        """获取代理配置的ip和端口号"""
        ip, port = "", ""
        if self.is_open_proxy_form_Win():
            try:
                ip, port = winreg.QueryValueEx(self.__INTERNET_SETTINGS, "ProxyServer")[0].split(":")
                #print("获取到代理信息：{}:{}".format(ip, port))
            except FileNotFoundError as err:
                print("没有找到代理信息：" + str(err))
            except Exception as err:
                print("有其他报错：" + str(err))
        else:
            print("系统没有开启代理")
        return ip, port
 
    def is_open_proxy_form_Win(self):
        """判断是否开启了代理"""
        try:
            if winreg.QueryValueEx(self.__INTERNET_SETTINGS, "ProxyEnable")[0] == 1:
                return True
        except FileNotFoundError as err:
            print("没有找到代理信息：" + str(err))
        except Exception as err:
            print("有其他报错：" + str(err))
        return False
 



def updateImage(query):
    url = "https://api.gptgod.online/v1/chat/completions"
    headers = {
        "Authorization": "sk-OsMMq65tXdfOIlTUYtocSL7NCsmA7CerN77OkEv29dODg1EA",
        "Content-Type": "application/json"
    }
    data = {
        "model": "gpt-3.5-turbo-16k",
        "messages": [{"role": "system", "content": "You are a helpful assistant."}, 
                     {"role": "user", "content": query}]
    }
    
    
    ps = ProxyServer()
    ip, port = ps.get_server_form_Win()
    proxy_url = "{}:{}".format(ip, port)
    proxies = {'http': proxy_url, 'https': proxy_url}

    response = requests.post(url, headers=headers, proxies=proxies, json=data)
    #print("response:",response)
    return_str = response.text
    return_str_json = json.loads(return_str)
    content = return_str_json["choices"][0]["message"]["content"]
    response.close()	# 注意关闭response
    return content




def query_model(query, cb, max_tokens=2500):
    """
    Function which sends a query to bard-3.5-turbo and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to bard-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        response = updateImage(query)

        ida_kernwin.execute_sync(functools.partial(cb, response=response),
                                 ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(_("General exception encountered while running the query: {error}").format(
            error=str(e)))

# -----------------------------------------------------------------------------


def query_model_async(query, cb):
    """
    Function which sends a query to bard-3.5-turbo and calls a callback when the response is available.
    :param query: The request to send to bard-3.5-turbo
    :param cb: Tu function to which the response will be passed to.
    """
    print(_("Request to Fbleee_16k sent..."))
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()

# =============================================================================
# Main
# =============================================================================


def PLUGIN_ENTRY():
    # if not openai.api_key:
    #     openai.api_key = os.getenv("OPENAI_API_KEY")
    #     if not openai.api_key:
    #         print(_("Please edit this script to insert your OpenAI API key!"))
    #         raise ValueError("No valid OpenAI API key found")

    return Fbleee_16k_SrcPlugin()
