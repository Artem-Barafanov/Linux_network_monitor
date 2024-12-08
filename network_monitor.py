import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, ICMP, TCP, UDP, send
from threading import Thread
import time
import subprocess

# Правила для обнаружения подозрительного трафика
suspicious_rules = {
    "large_packet": lambda pkt: len(pkt) > 1500,  # Большой пакет
    "port_scan": lambda pkt: pkt.haslayer(TCP) and pkt[IP].dst == "192.168.1.1" and pkt[TCP].dport == 135,  # Сканирование порта 135
    "repeated_requests": lambda pkt: pkt.haslayer(TCP) and pkt[IP].src == "192.168.1.2" and pkt[TCP].dport == 80,  # Повторяющиеся запросы на порт 80
    "unusual_port": lambda pkt: pkt.haslayer(TCP) and pkt[TCP].dport > 1024,  # Необычный порт
    "icmp_flood": lambda pkt: pkt.haslayer(ICMP) and pkt[ICMP].type == 8,  # ICMP flood
    "syn_flood": lambda pkt: pkt.haslayer(TCP) and pkt[TCP].flags == "S",  # SYN flood
    "udp_flood": lambda pkt: pkt.haslayer(UDP) and pkt[UDP].dport == 53,  # UDP flood на порт DNS
}

# Счетчики для обнаружения повторяющихся пакетов
packet_counters = {}

# Глобальная переменная для управления блокировкой трафика
block_traffic_enabled = False

def detect_suspicious_traffic(pkt):
    global packet_counters, block_traffic_enabled

    for rule_name, rule_func in suspicious_rules.items():
        if rule_func(pkt):
            log_message = f"Подозрительный трафик обнаружен по правилу: {rule_name}\n"
            if pkt.haslayer(TCP):
                log_message += f"Пакет от {pkt[IP].src} к {pkt[IP].dst} на порту {pkt[TCP].dport}\n"
            elif pkt.haslayer(UDP):
                log_message += f"Пакет от {pkt[IP].src} к {pkt[IP].dst} на порту {pkt[UDP].dport}\n"
            else:
                log_message += f"Пакет от {pkt[IP].src} к {pkt[IP].dst}\n"
            log_to_gui(log_message)

            # Увеличиваем счетчик для источника пакета
            src_ip = pkt[IP].src
            if src_ip not in packet_counters:
                packet_counters[src_ip] = 0
            packet_counters[src_ip] += 1

            # Если счетчик превышает порог и блокировка разрешена, блокируем трафик
            if packet_counters[src_ip] > 5 and block_traffic_enabled:
                block_traffic(pkt)
                packet_counters[src_ip] = 0
                break

def block_traffic(pkt):
    src_ip = pkt[IP].src
    try:
        # Добавляем правило в iptables для блокировки трафика с этого IP
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"], check=True)
        log_to_gui(f"Трафик от {src_ip} заблокирован.\n")
    except subprocess.CalledProcessError as e:
        log_to_gui(f"Ошибка при блокировке трафика от {src_ip}: {e}\n")

def log_to_gui(message):
    log_text.insert(tk.END, message)
    log_text.see(tk.END)

def start_monitoring():
    print("Начинаю мониторинг сетевого трафика...")
    sniff(prn=detect_suspicious_traffic, filter="ip", store=0)

def start_monitoring_thread():
    monitoring_thread = Thread(target=start_monitoring)
    monitoring_thread.daemon = True
    monitoring_thread.start()

def clear_log():
    log_text.delete(1.0, tk.END)

def toggle_block_traffic():
    global block_traffic_enabled
    block_traffic_enabled = not block_traffic_enabled
    block_button.config(text="Блокировать трафик: ВКЛ" if block_traffic_enabled else "Блокировать трафик: ВЫКЛ")

# Создание графического интерфейса
root = tk.Tk()
root.title("Network Traffic Monitor")

log_frame = tk.Frame(root)
log_frame.pack(padx=10, pady=10)

log_label = tk.Label(log_frame, text="Лог обнаружения и блокировки трафика:")
log_label.pack()

log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=60, height=20)
log_text.pack()

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Начать мониторинг", command=start_monitoring_thread)
start_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(button_frame, text="Очистить лог", command=clear_log)
clear_button.pack(side=tk.LEFT, padx=5)

block_button = tk.Button(button_frame, text="Блокировать трафик: ВЫКЛ", command=toggle_block_traffic)
block_button.pack(side=tk.LEFT, padx=5)

root.mainloop()