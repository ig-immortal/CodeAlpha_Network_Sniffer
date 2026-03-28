import time
ascii_art = r"""
                 _________-----_____
       _____------           __      ----_
___----             ___------              \
   ----________        ----                 \
               -----__    |             _____)
                    __-                /     \
        _______-----    ___--          \    /)\
  ------_______      ---____            \__/  /
               -----__    \ --    _          /\
                      --__--__     \_____/   \_/\
                              ----|   /          |
                                  |  |___________|
                                  |  | ((_(_)| )_)
                                  |  \_((_(_)|/(_)
                                  \             (
                                   \_____________)
"""

# Print in green
print("\033[92m" + ascii_art + "\033[0m")
print("                          \033[1;32mAuth: ig-immortal\033[0m")
from scapy.all import sniff, hexdump

def slow_print(text, delay=0.02):
    """Print text slowly, character by character."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()  # move to next line

def packet_callback(packet):
    # Capture detailed packet info
    packet_info = packet.show(dump=True)  # dump=True returns as string instead of printing
    hex_info = hexdump(packet, dump=True) # same for hex dump

    slow_print(packet_info, delay=0.01)   # slower animation for readability
    slow_print(hex_info, delay=0.005)     # hex dump can scroll faster

print("Sniffer running...")
sniff(prn=packet_callback, store=False)
