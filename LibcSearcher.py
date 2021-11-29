#!/usr/bin/env python

from __future__ import print_function
import os
import re
import sys

import requests
import json

FIND_API_URL = 'https://libc.rip/api/find'
LIBC_API_URL = 'https://libc.rip/api/libc/'
HEADER = {'Content-Type': 'application/json'}


class LibcSearcher(object):
    def __init__(self, func=None, address=None, online=False):
        self.condition = {}
        self.libcs = []
        self.libc = None
        self.online = online
        if func is not None and address is not None:
            self.add_condition(func, address)
        self.libc_database_path = os.path.join(
            os.path.realpath(os.path.dirname(__file__)), "libc-database/db/")
        self.db = ""

    def add_condition(self, func, address):
        if not isinstance(func, str):
            print("The function should be a string")
            sys.exit()
        if not isinstance(address, int):
            print("The address should be an int number")
            sys.exit()
        self.condition[func] = address

    def query_libc_online(self):
        if len(self.condition) == 0:
            print("No leaked info provided.")
            print(
                "Please supply more info using add_condition(leaked_func, leaked_address)."
            )
            sys.exit(0)

        payload = {
            "symbols":
            {s_name: hex(s_addr)
             for s_name, s_addr in self.condition.items()}
        }
        res = requests.post(FIND_API_URL,
                            data=json.dumps(payload),
                            headers=HEADER)
        self.libcs = json.loads(res.text)
        self.decide_online()

    def decide_online(self):
        if not self.libcs:
            print("No matched libc, please add more libc or try others")
            exit(0)
        elif len(self.libcs) == 1:
            self.libc = self.libcs[0]['id']
        else:
            print("Multi Results:")
            for x in range(len(self.libcs)):
                print("%2d: %s" % (x, self.libcs[x]['id']))
            print(
                "Please supply more info using \n\tadd_condition(leaked_func, leaked_address)."
            )
            while True:
                in_id = input(
                    "You can choose it by hand\nOr type 'exit' to quit:")
                if in_id == "exit" or in_id == "quit":
                    sys.exit(0)
                try:
                    in_id = int(in_id)
                    self.libc = self.libcs[in_id]
                    break
                except:
                    continue
        # print(self.libc)
        print("[+] %s be choosed." % self.libc['id'])

    def query_symbol_online(self, id: str, func: str):
        payload = {"symbols": [func]}
        result = requests.post(LIBC_API_URL + id,
                               data=json.dumps(payload),
                               headers=HEADER)
        if func:
            return int(json.loads(result.text)['symbols'][func], 16)
        else:
            if not func:
                data = json.loads(result.text)['symbols']

                for k, v in data.items():
                    print(k, v)
                return data

    # Wrapper for libc-database's find shell script.
    def decide_local(self):
        if len(self.condition) == 0:
            print("No leaked info provided.")
            print(
                "Please supply more info using add_condition(leaked_func, leaked_address)."
            )
            sys.exit(0)

        # if self.online:
        #     self.query_libc_online()
        #     return

        res = []
        for name, address in self.condition.items():
            addr_last12 = address & 0xfff
            res.append(re.compile("^%s .*%x" % (name, addr_last12)))

        db = self.libc_database_path
        files = []
        # only read "*.symbols" file to find
        for _, _, f in os.walk(db):
            for i in f:
                files += re.findall('^.*symbols$', i)

        result = []
        for ff in files:
            fd = open(db + ff, "rb")
            data = fd.read().decode(errors='ignore').split("\n")
            for x in res:
                if any(map(lambda line: x.match(line), data)):
                    result.append(ff)
            fd.close()

        if len(result) == 0:
            print("No matched libc, please add more libc or try others")
            sys.exit(0)

        if len(result) > 1:
            print("Multi Results:")
            for x in range(len(result)):
                print("%2d: %s" % (x, self.pmore(result[x])))
            print(
                "Please supply more info using \n\tadd_condition(leaked_func, leaked_address)."
            )
            while True:
                in_id = input(
                    "You can choose it by hand\nOr type 'exit' to quit:")
                if in_id == "exit" or in_id == "quit":
                    sys.exit(0)
                try:
                    in_id = int(in_id)
                    self.db = result[in_id]
                    break
                except:
                    continue
        else:
            self.db = result[0]
        print("[+] %s be choosed." % self.pmore(self.db))

    def pmore(self, result):
        result = result[:-8]  # .strip(".symbols")
        fd = open(self.libc_database_path + result + ".info")
        info = fd.read().strip()
        return "%s (id %s)" % (info, result)

    # Wrapper for libc-database's dump shell script.
    def dump(self, func=""):
        if not self.online:
            if not self.db:
                self.decide_local()
            db = self.libc_database_path + self.db
            fd = open(db, "rb")
            data = fd.read().decode(errors='ignore').strip("\n").split("\n")
            if not func:
                result = {}
                func = [
                    "__libc_start_main_ret", "system", "dup2", "read", "write",
                    "str_bin_sh"
                ]
                for ff in func:
                    for d in data:
                        f = d.split(" ")[0]
                        addr = d.split(" ")[1]
                        if ff == f:
                            result[ff] = int(addr, 16)
                for k, v in result.items():
                    print(k, hex(v))
                return result

            for d in data:
                f = d.split(" ")[0]
                addr = d.split(" ")[1]
                if func == f:
                    return int(addr, 16)

            print(
                "No matched, Make sure you supply a valid function name or just add more libc."
            )
            return 0
        else:
            if not self.libc:
                self.query_libc_online()
            if self.libc['symbols'].get(func):
                return int(self.libc['symbols'][func], 16)
            else:
                return self.query_symbol_online(id=self.libc['id'], func=func)


if __name__ == "__main__":
    # obj = LibcSearcher("fgets", 0x7ff39014bd90)
    # print("[+]system  offset: ", hex(obj.dump("system")))
    # print("[+]/bin/sh offset: ", hex(obj.dump("str_bin_sh")))

    obj = LibcSearcher("fgets", 0x7ff39014bd90, True)
    print("[+]system  offset: ", hex(obj.dump("system")))
    print("[+]writev offset: ", hex(obj.dump("writev")))
    # print(obj.dump())
