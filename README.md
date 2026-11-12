# vanishd - Linux Rootkit for Process Hiding

A rootkit that uses DKOM for process hiding through:

- **tasks unlinking** - unlinks the target `task_struct` from the global `tasks` list, hides from `for_each_process()` in the kernel 
- **pid hash table unlinking** - unlinks from the pid hash table so `find_task_by_vpid()` no longer works. Removes entries under `/proc` as the kernel views the task as 'dead'. 

Warnings: 
- This is purely academic project as part of a larger project on uncovering hidden processes. 
- **To be used in a VM ONLY** and with **ALL PROPER PERMISSIONS**. 
- You can only hide 1 process at a time. Future work could include building out an array of hidden process pointers but for my purposes 1 is sufficient. Do not try to hide a 2nd process while the 1st is still hidden as the pointers will be overwritten. 
- **Could lead to system instability**, use at your own risk in your own testing environment. 

Future work:
- Support hiding multiple processes at a time 
- Automatically hide children of hidden processes 

## Compilation

Install the kernel headers:
```sh
sudo apt install linux-headers-$(uname -r)
```
Clone and compile the tool:
```sh
$ git clone https://github.com/lnchamberlain/vanishd
$ cd vanishd/
$ make
```

## Usage 

Install the kernel module:
```sh
sudo insmod vanishd.ko
```

Interacting with the rootkit happens through `/proc` entries.

To unhide the module (starts hidden by default):
```sh
sudo echo "show" > /proc/module
```
To hide the module:
```sh
sudo echo "hide" > /proc/module
```

To hide a process:
```sh
sudo echo "hide [pid]" > /proc/process
```

To unhide a process:
```sh
sudo echo "show [pid]" > /proc/process
```

## Credits
- `ftrace_helper.h`: https://github.com/ilammy/ftrace-hook and https://github.com/ait-aecid/caraxes who took the original and edited to fit as a library instead of a standalone rootkit.
