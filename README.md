# CanaryWatch #

Written in Python, CanaryWatch is a deception-based approach to detecting ransomware. By utilising [Fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html), CanaryWatch will detect filesystem events and kill the process attempting to interact with the trap file.

There are currently two scripts:

- [trap_file_deployment.py](https://github.com/Tr1sH-G/CanaryWatch/blob/main/trap_file_deployment.py)
- [canarywatch.py](https://github.com/Tr1sH-G/CanaryWatch/blob/main/canarywatch.py)

**trap_file_deployment.py** deploys a hidden file, `.aa.pdf`, to a pre-defined list of directories. This list can be adjusted according to the deployment requirements. The trap files are 4096 bytes in size.

**canarywatch.py** does the heavy lifting by monitoring for any activity on the deployed trap files then killing the offending process.


**NOTE:** *If you update the directories and/or the trap file name in `trap_file_deployment.py`, you must make sure that this detail is reflected in `canarywatch.py`*

In most cases, a response action should be triggered by the presence of events utilising Open-Permissions, however if the ransomware does not open the files to encrypt initially, CanaryWatch will attempt to retroactively identify process data where there has been a rename event against the trap file. This does mean there will be at least one sacrificial file in this instance.

CanaryWatch and it's implementation principles are based around the idea that any interaction with a hidden trap file should be considered malicious. technical inspiration/ideas taken from [RansomwareLocker](https://github.com/Aayushjn/RansomwareLocker
) & [R-Locker](https://github.com/raulsf6/R-Locker).

Further insight into the my research in this space can be found here: [Resilience without AI: Assessing the Viability of Deception-Based Ransomware Detection](https://www.sciencedirect.com/science/article/pii/S1877050925028777)
RansomwareLocker & R-Locker are also cited works in this paper.


## Installation ##

To install CanaryWatch, clone the repo, then either create a virtual environment with the CanaryWatch Directory or run `python -m pip install requirements.txt` to install the packages at a global level.

`canarywatch.py` requires sudo elevation to run correctly.
