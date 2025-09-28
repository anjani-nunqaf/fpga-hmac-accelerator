# test_hmac_fpga_sha1.py
# Skrip Python untuk menguji akselerator HMAC-SHA1 pada FPGA.

import time
import os
import hmac
import hashlib
from smbus2 import SMBus, i2c_msg

# --- KONFIGURASI ---
I2C_BUS = 1
I2C_SLAVE_ADDR = 0x50

# --- PETA REGISTER (Sesuai dengan Verilog HMAC-SHA1) ---
ADDR_CTRL   = 0x0000
ADDR_STATUS = 0x0004
ADDR_KEY    = 0x0010
ADDR_MSG    = 0x0050
ADDR_DIGEST = 0x0090

# Parameter Spesifik SHA-1
KEY_SIZE_BYTES    = 64   # 512 bits
MSG_SIZE_BYTES    = 64   # 512 bits
DIGEST_SIZE_BYTES = 20   # 160 bits
HASHLIB_ALGO      = hashlib.sha1


# --- FUNGSI BANTU I2C YANG ROBUST ---

def write_register(bus, addr, value):
    """Menulis 4 byte (32-bit) ke sebuah register AXI-Lite via I2C."""
    addr_bytes = addr.to_bytes(2, byteorder='big')
    data_bytes = value.to_bytes(4, byteorder='little')
    payload = list(addr_bytes + data_bytes)
    write_msg = i2c_msg.write(I2C_SLAVE_ADDR, payload)
    bus.i2c_rdwr(write_msg)

def read_register(bus, addr):
    """Membaca 4 byte (32-bit) dari sebuah register AXI-Lite via I2C."""
    addr_bytes = addr.to_bytes(2, byteorder='big')
    write_msg = i2c_msg.write(I2C_SLAVE_ADDR, list(addr_bytes))
    read_msg = i2c_msg.read(I2C_SLAVE_ADDR, 4)
    bus.i2c_rdwr(write_msg, read_msg)
    return int.from_bytes(bytes(list(read_msg)), byteorder='little')

def write_buffer(bus, base_addr, data):
    """Menulis buffer data (key/message) ke FPGA, 4 byte per transaksi."""
    for i in range(0, len(data), 4):
        word_bytes = data[i:i+4]
        word_int = int.from_bytes(word_bytes, byteorder='little')
        write_register(bus, base_addr + i, word_int)

def read_buffer(bus, base_addr, length):
    """Membaca buffer data (digest) dari FPGA, 4 byte per transaksi."""
    read_data = bytearray()
    for i in range(0, length, 4):
        word_int = read_register(bus, base_addr + i)
        read_data.extend(word_int.to_bytes(4, byteorder='little'))
    # Potong data sesuai panjang digest yang sebenarnya
    return bytes(read_data[:length])


# --- FUNGSI UTAMA ---

def main():
    """Menjalankan siklus tes HMAC lengkap."""
    print("--- MEMULAI PENGUJIAN HMAC-SHA1 ---")

    try:
        bus = SMBus(I2C_BUS)
    except FileNotFoundError:
        print(f"Error: I2C Bus {I2C_BUS} tidak ditemukan.")
        return

    key = os.urandom(KEY_SIZE_BYTES)
    message = os.urandom(MSG_SIZE_BYTES)
    
    print("\n--- TAHAP 1: Mengirim Data ---")
    print("Mengirim kunci...")
    write_buffer(bus, ADDR_KEY, key)
    print("Mengirim pesan...")
    write_buffer(bus, ADDR_MSG, message)
    print("✅ Data berhasil dikirim.")

    print("\n--- TAHAP 2: Menjalankan HMAC ---")
    print("Memulai kalkulasi HMAC...")
    write_register(bus, ADDR_CTRL, 1)
    
    start_time = time.time()
    timeout = 5
    
    print("Menunggu hasil akhir...")
    while True:
        status = read_register(bus, ADDR_STATUS)
        is_done = status & 0x1
        is_idle = (status >> 1) & 0x1
        if is_done and is_idle:
            break
        if time.time() - start_time > timeout:
            print("❌ GAGAL! Timeout.")
            bus.close()
            return
        time.sleep(0.01)
        
    end_time = time.time()
    print(f"✅ Perhitungan Selesai! (setelah {end_time - start_time:.4f} detik)")

    print("\n--- TAHAP 3: Verifikasi Hasil Akhir ---")
    fpga_digest = read_buffer(bus, ADDR_DIGEST, DIGEST_SIZE_BYTES)
    python_digest = hmac.new(key, message, HASHLIB_ALGO).digest()

    print(f" -> Digest Python (hex): {python_digest.hex()}")
    print(f" -> Digest FPGA (hex):   {fpga_digest.hex()}")
    
    if fpga_digest == python_digest:
        print("SELAMAT! Hasil HMAC COCOK!")
    else:
        print(" GAGAL! Hasil HMAC TIDAK COCOK.")

    bus.close()


if __name__ == "__main__":
    main()