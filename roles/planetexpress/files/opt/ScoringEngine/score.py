#!/usr/bin/python3

import datetime
import glob
import hashlib
import os
import pwd
import re
import shlex
import shutil
import subprocess
import pickle
from jinja2 import Template
from pathlib import Path
from collections import namedtuple


def run(command, is_shell=False):
    """Runs a shell command and returns the stdout response"""
    result = subprocess.run(shlex.split(command),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=is_shell,
                            )
    result.stdout = result.stdout.decode('utf-8')
    result.stderr = result.stderr.decode('utf-8')
    return result.stdout.strip()

def password_status(user):
    PasswordStatus = namedtuple('PasswordStatus', 
                    ['user', 'is_locked', 'last_change', 'min_age', 
                    'max_age', 'warning', 'inactivity'])
    output = run(f"passwd -S {user}")
    output = output.split()
    d = output[2].split('/')
    output[2] = datetime.date(int(d[2]), int(d[0]), int(d[1]))
    output[3] = int(output[3])
    output[4] = int(output[4])
    output[5] = int(output[5])
    output[6] = int(output[6])
    ps = PasswordStatus(*output)    
    return ps

def get_apt_repositories():
    AptSource = namedtuple('AptSource', [type, uri, suite, component])
    sources_files = glob.glob("/etc/apt/sources.list.d/*.list", recursive=True)
    sources_files.append("/etc/apt/sources.list")
    sources = []
    for source_file in source_files:
        with open(source_file) as f:
            line = f.readline().strip()
            if re.match(r'^\s*#', line):
                continue
            type, uri, suite, components = line.split(' ', 3)
            components = components.split(' ')
            for component in components:
                sources.append(AptSource(type, uri, suite, component))
    return sources


def get_file_md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def is_file_md5_equal(filename, hash):
    return get_file_md5(filename) == hash

def is_user_in_passwd(user):
    pass_line = run(f"grep {user} /etc/passwd")
    return user in pass_line

def is_user_home_removed(user):
    try:
        return not os.path.isdir(f"/home/{user}")
    except:
        return True

def is_user_removed(user):
    return is_user_home_removed(user) and not is_user_in_passwd(user)

def is_root_login_disabled():
    ps = password_status('root')
    return ps.is_locked == 'L'

def is_root_ssh_login_disabled():
    permit_root_login = run("grep ^PermitRootLogin /etc/ssh/sshd_config")
    is_yes = "yes" in permit_root_login
    return not is_yes

def is_user_in_admin(user):
    return 'sudo' in run(f"groups {user}")

def is_media_files_deleted(directory, filetype):
    files = glob.glob(f"{directory}/*.{filetype}")
    return len(files) == 0

def is_program_installed(program):
    return shutil.which(program) is not None

def which(command):
    split_command = shlex.split(command)
    cmd = split_command[0]
    resolved_cmd = shutil.which(cmd)
    if resolved_cmd is None:
        return None
    args = " ".join(split_command[1:])
    return f"{resolved_cmd} {args}".strip()

def is_one_of_program_installed(*programs):
    return any(map(is_program_installed, programs))

def is_guest_session_disabled():
    config_line = run("grep allow-guest /etc/lightdm/lightdm.conf.d/*")
    is_guest_allowed = config_line.split('=')[1]
    is_yes = re.match("true", is_guest_allowed, re.IGNORECASE)
    return is_yes == None

def is_service_running(service):
    active_line = run(f"systemctl is-active {service}")
    is_active = "inactive" not in active_line
    return is_active

def is_service_enabled(service):
    enabled_line = run(f"systemctl is-enabled {service}")
    is_enabled = "disabled" not in enabled_line
    return is_enabled

def is_service(service):
    return is_service_running(service) and is_service_enabled(service)

def is_ufw_enabled():
    enabled_line = run("ufw status")
    is_enabled = "inactive" not in enabled_line
    return is_enabled

def is_removed_service(service):
    return not is_service_running(service) and not is_service_enabled(service)

def is_daily_update_checked():
    update_package_list = run("grep 'APT::Periodic::Update-Package-Lists' /etc/apt/apt.conf.d/*")
    return '1' in update_package_list

def is_auto_upgrade():
    unattended_upgrade = run("grep 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/*")
    return '1' in unattended_upgrade

def is_hypnotoad_not_sudo():
    hypnotoad_line = run("grep hypnotoad /etc/sudoers")
    return "hypnotoad" not in hypnotoad_line

def is_user_sudoer(user):
    return "not allowed" not in run(f"sudo -l -U {user}")

def is_user_password_expired(user):
    password_info = password_status(user)


def is_forensic_question_answered(forensic_file, answer):
    if not os.path.exists(forensic_file):
        print(f"Forensics file {forensic_file} not found. This is an error of the scoring engine.")
        return False

    divider_pattern = r'^=.*$'
    answer_pattern = r'^ANSWER: (.*)$'
    answer_line = ''

    with open(forensic_file) as file:
        in_example = True
        for line in file:
            line = line.rstrip('\n')
            if re.match(divider_pattern, line):
                in_example = False
            if in_example:
                continue
            match = re.match(answer_pattern, line)
            if match:
                answer_line = match.groups()[0].strip()


    # In the command below, the \K of the regex will lookup the previous pattern, but not include it in the
    # matching result. The -Po options to grep cause it to return only the matching pattern
    # command = r"grep -Po '^Answer: *\K.*' " + f'"{forensic_file}"'
    # answer_line = run(command).strip()
    return answer == answer_line

class Task:
    def __init__(self, function, arguments, success, description, points = 5):
        self.points = points
        self.function = function
        if not type(arguments) is list and not type(arguments) is tuple:
            self.args = [arguments]
        else:
            self.args = arguments
        self.success = success
        self.description = description
        self.passed = None
        
    def check(self):
        global score
        global found_items
        if len(self.args)==1 and self.args[0]==None:
            value = (self.function() == self.success)
        else:
            value = (self.function(*self.args) == self.success)
        if value:
            self.passed = True
            # score += self.points
            # found_items += 1
            # print(f"{s.bold}{self.points} points{s.reset} {self.description}")
        else:
            self.passed = False

class TestSuite:
    def __init__(self, tasks):
        self.tasks = tasks 
        self.score = 0
        self.completion = 0
        self.total_possible = sum(t.points for t in self.tasks)


    def check_all(self):
        for task in self.tasks:
            task.check()
        self.score = 0
        for task in self.tasks:
            if task.passed is None:
                task.check()
            if task.passed:
                self.score += task.points
        return self.score

    @property
    def solved(self):
        return len(task for task in self.tasks if task.passed == True)
    

    def __iter__(self):
        if self.tasks is None:
            raise StopIteration
        return (task for task in self.tasks)
    

    def __len__(self):
        if self.tasks is None:
            return 0
        return len(self.tasks)


    def __getitem__(self, index):
        return self.tasks[index]

    
    def __str__(self):
        return f"You have found {self.solved} out of {len(self)} for a score of {self.score}."

# Do first-time tasks
os.makedirs('/var/score/', mode=0o755, exist_ok=True)
first_time_file = Path("/var/score/first-time")
first_time_data = {}
if first_time_file.exists():
    first_time_data = pickle.load(first_time_file.open('rb'))
else:
    first_time_data['firefox_md5'] = get_file_md5(which("firefox"))
    pickle.dump(first_time_file.open('wb'))


tasks = [
    #Points, function, arguments, truth, description
    Task(is_root_login_disabled, None, True, "Disabled root user login."),
    Task(is_root_ssh_login_disabled, None, True, "Disallowed root from login in through ssh."),
    Task(is_user_removed, "donbot", True, "Removed unauthorized user donbot."),
    Task(is_user_removed, "mom", True, "Removed unauthorized user mom."),
    Task(is_user_removed, "wernstrom", True, "Removed unauthorized user wernstrom."),
    Task(is_user_removed, "hypnotoad", True, "Removed unauthorized user hypnotoad."),
    Task(is_user_in_admin, "cubert", False, "Removed cubert from Administrators."),
    Task(is_user_in_admin, "donbot", False, "Removed donbot from Administrators."),
    Task(is_user_in_admin, "wernstrom", False, "Removed wernstrom from Administrators."),
    Task(is_user_in_admin, "leela", True, "Added leela to Administrators."),
    Task(is_media_files_deleted, ["/home/scruffy/Pictures", "*"], True, "Removed unauthorized media files from user scruffy."),
    Task(is_service, "auditd", True, "Installed and enabled auditd service."),
    Task(is_file_md5_equal, [which("firefox"), first_time_data['firefox_md5']], False, "Updated Firefox"),
    Task(is_removed_service, "xrdp", True, "Stopped and disabled Remote Desktop Protocol service."),
    Task(is_program_installed, "aircrack-ng", False, "Removed hacking tool aircrack-ng."),
    Task(is_program_installed, "nmap", False, "Removed hacking tool nmap."),
    Task(is_user_sudoer, "hypnotoad", False, "Removed hypnotoad's sudo access."),
    Task(is_ufw_enabled, None, True, "Firewall enabled."),
    Task(is_daily_update_checked, None, True, "Set to check for updates daily."),
    Task(is_auto_upgrade, None, True, "Set to upgrade automatically."),
    Task(is_forensic_question_answered, ["/home/bender/Desktop/Forensics Question 1.txt", "scruffy"], True, "Answered forensic question 1"),
    Task(is_program_installed, "clamav", True, "Installed anti-malware tools."),
    ]
    

points = TestSuite(tasks)

if __name__ == "__main__":
    # Check if pickled points file exists. If it does, un-pickle it and save it as an old value.
    pickle_file = Path('/var/score/points')
    if pickle_file.exists():
        old_points = pickle.load(open(pickle_file, 'rb'))
    points.check_all()
    # if points.score > old_points.score:
    #     ... # Notify points gained
    # Now save for the next time
    pickle.dump(points, open(pickle_file, 'wb'))

    # Generate scoring report
    template = Template(open("/opt/ScoringEngine/ScoringReport.html.j2").read())
    page = template.render(points=points, now=datetime.datetime.now())
    with open("/opt/ScoringEngine/ScoringReport.html", "w") as f:
        f.write(page)
    
    
    # if pwd.getpwuid( os.getuid() ).pw_name != 'root':
    #     print("""Since the scoring software needs to access system configurations,
    #             it must be run with elevated privileges. Try again with 'sudo'.
    #         """)
    #     exit()
    
    # print("")
    # total_possible_points = 0
    # score = 0
    # found_items = 0
    # for point in points:
    #     total_possible_points += point.points
    #     point.check()
        
    # print(f"\nYou have found {bold(found_items)} out of {bold(len(points))}, \nearning {bold(f'{score} points out of {total_possible_points} points')}.")
    

