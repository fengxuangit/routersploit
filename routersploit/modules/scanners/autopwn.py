import sys
from os import path

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_info,
    utils,
    threads,
)


class Exploit(exploits.Exploit):
    """
    Scanner implementation for all vulnerabilities.
    """
    __info__ = {
        'name': 'AutoPwn',
        'description': 'Scanner module for all vulnerabilities.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Multi',
        ),
    }
    modules = ['routers', 'cameras', 'misc']

    target = exploits.Option('', 'Target IP address e.g. 192.168.1.1 or json str' +
                            ' [{"http://192.168.1.1":80}, {"http://192.168.1.2":90}]')  # target address
    target_file = exploits.Option(None, "Target IP File, e.g. test.txt http://192.168.1.1:80" +
                                "\\nhttp://192.168.1.2:80")

    output_file = exploits.Option('result.txt', "if you use target_file option, set output_file to save successful "
                                                "target")
    port = exploits.Option(80, 'Target port')  # default port
    threads = exploits.Option(1, "Number of threads")

    def __init__(self):
        self.vulnerabilities = []
        self.not_verified = []
        self.target_file = None
        self.output_file = "result.txt"
        self._exploits_directories = [path.join(utils.EXPLOITS_DIR, module) for module in self.modules]

    def run(self):
        self.vulnerabilities = []
        self.not_verified = []
        target = utils.safe_json_loads(self.target)
        if target:
            self.target = target

        with threads.ThreadPoolExecutor(self.threads) as executor:
            for directory in self._exploits_directories:
                for exploit in utils.iter_modules(directory):
                    executor.submit(self.target_function, exploit)

        print_info()
        if self.not_verified:
            print_status("Could not verify exploitability:")
            for v in self.not_verified:
                print_info(" - {}".format(v))

        print_info()
        if self.vulnerabilities:
            print_success("Device is vulnerable:")
            for v in self.vulnerabilities:
                print_info(" - {}".format(v))
            print_info()
        else:
            print_error("Could not confirm any vulnerablity\n")

    def check(self):
        raise NotImplementedError("Check method is not available")

    def target_function(self, exploit):
        if self.target_file:
            self.filecheck(exploit)

        if isinstance(self.target, list):
            self.multicheck(exploit)
        elif isinstance(self.target, str):
            self.siglecheck(exploit)
        else:
            pass


    def filecheck(self, exploit):
        self.target = []

        if not utils.check_file(self.target_file):
            print_error("{} is not exists or readdle".format(self.target_file))
            sys.exit()

        with open(self.target_file) as f:
            for line in f.readlines():
                line = line.replace('\n', '')
                ip = line[:line.rfind(':')]
                port = line[line.rfind(':')+1:]
                self.target.append({ip: port})

        self.multicheck(exploit)


    def siglecheck(self, exploit):
        exploit = exploit()
        exploit.port = self.port
        exploit.target = self.target

        response = exploit.check()
        self.getresponse(response, exploit)

    def multicheck(self, exploit):
        for target in self.target:
            exp = exploit()
            for line in target.keys():
                exp.port = target[line]
                exp.target = line

            response = exp.check()
            self.getresponse(response, exp)


    def savefile(self, exploit):
        with open(self.output_file, 'ab') as f:
            data = "{0} {1}\n".format(exploit.target, exploit.port)
            f.write(data)
        print_success("target {} save file ok!".format(exploit.target))

    def getresponse(self, response, exploit):
        if response is True:
            print_success("ip {0} port {1} {2} is vulnerable".format(exploit.target, exploit.port, exploit))
            self.savefile(exploit)
            self.vulnerabilities.append(exploit)
        elif response is False:
            print_error("ip {0} port {1} {2} is not a  vulnerable".format(exploit.target, exploit.port, exploit))
        else:
            print_status("ip {0} port {1} {2} is can't verified".format(exploit.target, exploit.port, exploit))
            self.not_verified.append(exploit)
