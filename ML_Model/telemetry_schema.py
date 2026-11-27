"""Ordered model inputs and TON_IoT Windows labels shared by training and inference."""

FEATURE_KEYS = [
    "Network_I_ActiveNIC_TCP_APS",
    "Process_Pool_Paged Bytes",
    "Process_Handle Count",
    "Memory Free System Page Table Entries",
    "Process_Virtual_Bytes",
    "Memory System Cache Resident Bytes",
    "Process_Virtual_Bytes Peak",
    "Process_Thread Count",
    "Process_Working Set",
    "Process_Working_Set_Peak",
    "Network_I_ActiveNIC_ TCP Active RSC Connections",
    "Process_Page_File Bytes",
    "Process_Working_Set_ Private",
    "Memory Standby Cache Normal Priority Bytes",
    "Network_I_ActiveNIC_ Bytes Sent sec"
]

CLASS_NAMES = ['ddos', 'dos', 'injection', 'mitm', 'normal', 'password', 'scanning', 'xss']
NORMAL_CLASS = CLASS_NAMES.index("normal")
