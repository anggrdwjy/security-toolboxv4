#!/bin/bash

# Pastikan skrip dijalankan sebagai root / sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "\e[31mError: Skrip ini harus dijalankan dengan hak akses root / sudo!\e[0m"
  exit 1
fi

LOG_FILE="security_toolbox_$(date +%Y%m%d_%H%M%S).log"
exec &> >(tee -a ./audit_log/"$LOG_FILE")

# Fungsi Dekorasi Warna
cetak_judul() { echo -e "\n\e[1;34m=== $1 ===\e[0m"; echo "------------------------------------------------------------------"; }
cetak_sukses() { echo -e "[\e[32mAMAN/SUKSES\e[0m] $1"; }
cetak_peringatan() { echo -e "[\e[33mPERINGATAN\e[0m] $1"; }
cetak_bahaya() { echo -e "[\e[31mBAHAYA\e[0m] $1"; }
cetak_info() { echo -e "[\e[36mINFO\e[0m] $1"; }

while true; do
    clear
    echo " "
    echo " #/(*/#%%//.#/&#&/###*%#(*,.,...*/#&#(&%.%%&, .,,...*#(..,,.. "
    echo " %###((#(/(&%%##&&#/#/*/ ...,. ..*(&%&@@&&(, ,.,.,,,*,((.  ., "
    echo " #%&#####%%%#(%/##%/*(/. .  ... ...#@@@@%(/     .../,/*#(//.. "
    echo " #%#%(/#((%%(#%/#/*,   (.     ,  ..(@@@&    ..     ..*/&(((., "
    echo " .//#%#(((#(%&#.*,,     .#     . . *&@/  ./ ,       .**##%//* "
    echo "  ..(%(##/#(&//,,.*,           *.,.(&& ,    .&      ,..(##(/. "
    echo "   ..*/((#%%#/*. ....  .    .   ..,#%&*.           ,(..*///,. "
    echo " .  ...*(*/##(*,.,. ....    (*/./*#&%#.          . ....,,#*.. "
    echo " .........*/**/,,/..          ,/#&&@@&,,,*,#. .,* . ..,*/.... "
    echo " ,...... .  ..,,,,,#..*.,**((%&&&&&@&%&(**.*...., . .,,,..... "
    echo " ,,......       . ... ..///*(#&(%#%##%#//*,,,*.,**(/**,...... "
    echo " ............,....    ../(##*/*,,(//.**/** ......,........... "
    echo " ............,,*,,.....,##((*. ...,.../%/*.,.,............... "
    echo " .....,,,,,,,,**,,,,...... (*/.     .(/**,.,,................ "
    echo " ...**/*,,,/((/,.**,,,......   ,*(#(*,...  .,,,,,,,,,,,,,,,,, "
    echo " ,.,/////****,,,,,,.............(,,.        ...,**,,,,,****** "
    echo " ,*/////*.........,,,,...........,#..           ..***,...**// "
    echo " //****,,,,,.,,....,,,,,,.....  .......          ..  ..,,**## "
    echo " //(/***,,,.,****,,,,,........  .,,,,,.... ....  ...,/(**/#(( "
    echo " "
    echo "      LINUX SECURITY ASSESSMENT & MANAGEMENT TOOLBOX V4       "
    echo "           Provide By  : aw0x0410 a.k.a anggrdwjy		    "
    echo " 		       Source Code : github.com/anggrdwjy		    "
    echo " "
    echo "  ------------------------------------------------------------"
    echo "   Waktu Sistem : $(date)"
    echo "   Hostname     : $(hostname)"
    echo "   Log Berkas   : $LOG_FILE"
    echo "  ------------------------------------------------------------"
    echo " "
    echo " [1] RUN SECURITY ASSESSMENT (Audit Port, SSH, UFW, Auto-Update)"
    echo " [2] AUDIT USERNAME & GROUP (Cek Session Aktif & Hak Sudo)"
    echo " [3] AUDIT ACTIVE DIRECTORY / CURRENT WORKDIR (Izin File & Owners)"
    echo " [4] KELOLA / UBAH KONFIGURASI SISTEM, FIREWALL & IP"
    echo " [5] KELUAR"
    echo "  ------------------------------------------------------------"
    read -p " Pilih menu (1-5): " MENU_UTAMA

    case $MENU_UTAMA in
        1)
            # ==========================================
            # MODUL 1: SECURITY ASSESSMENT
            # ==========================================
            clear
            cetak_judul "MENJALANKAN AUDIT KEAMANAN JARINGAN & LAYANAN"
            
            # Cek UFW Firewall & Kebijakan Default
            UFW_ST=$(ufw status | head -n 1 | awk '{print $2}')
            if [ "$UFW_ST" == "active" ]; then 
                cetak_sukses "Firewall UFW Aktif."
                echo -e "\n[Aturan Firewall Aktif Saat Ini]:"
                ufw status numbered
            else 
                cetak_bahaya "Firewall UFW MATI! Server Anda sepenuhnya terekspos tanpa filter."
            fi
            
            # Cek Port Publik Terbuka
            echo ""
            cetak_info "Daftar Port Terbuka Lokal (Listening):"
            ss -tulpn | grep LISTEN | awk '{print $1, $5, $7}' | sed 's/users:(//' | column -t
            
            # Analisis Risiko Port Publik & Deteksi Port SSH Aktif
            echo ""
            CURRENT_SSH_PORT=22
            ss -tulpn | grep LISTEN | awk '{print $5}' | while read -r addr; do
                PORT=$(echo "$addr" | awk -F: '{print $NF}')
                if [[ "$addr" =~ ^(0\.0\.0\.0|\[::\]|\*): ]]; then
                    case $PORT in
                        22) cetak_peringatan "Port 22 (SSH Default) Terbuka Publik. Disarankan ganti ke Custom Port." ;;
                        3306) cetak_bahaya "Port 3306 (MySQL) Terbuka Publik! Sangat Berisiko dieksploitasi." ;;
                        21|23) cetak_bahaya "Port $PORT (FTP/Telnet - Insecure) Terbuka Publik!" ;;
                    esac
                fi
            done
            
            # Cek Kebijakan SSH
            echo ""
            if [ -f /etc/ssh/sshd_config ]; then
                R_LOGIN=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
                P_AUTH=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
                SSH_PORT_CONF=$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $2}')
                [ -z "$SSH_PORT_CONF" ] && SSH_PORT_CONF="22 (default)"
                
                cetak_info "Port SSH dikonfigurasi pada: $SSH_PORT_CONF"
                if [[ "$R_LOGIN" =~ ^(no|prohibit-password)$ ]]; then cetak_sukses "SSH Root Login Terproteksi ($R_LOGIN)."; else cetak_peringatan "SSH Root Login Aktif ($R_LOGIN)."; fi
                if [ "$P_AUTH" == "no" ]; then cetak_sukses "Autentikasi Password SSH Mati (Bagus, Pakai SSH Key)."; else cetak_peringatan "Autentikasi Password SSH Aktif."; fi
            fi
            echo ""
            read -p "Tekan Enter untuk kembali..."
            ;;

        2)
            # ==========================================
            # MODUL 2: AUDIT USERNAME & GROUP
            # ==========================================
            clear
            cetak_judul "AUDIT PENGGUNA (USERNAME) & GRUP AKSES"
            who | awk '{print " - User: "$1" via "$2" sejak "$3" "$4" ("$5")"}'
            echo ""
            awk -F: '($3 >= 1000 && $1 != "nobody") {print " -> " $1 " (UID: "$3", Shell: "$7")"}' /etc/passwd
            echo ""
            SUDO_USERS=$(getent group sudo wheel | cut -d: -f4 | tr ',' ' ' | xargs)
            for u in $SUDO_USERS; do echo " -> $u"; done
            echo ""
            UID_Z=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
            if [ -z "$UID_Z" ]; then cetak_sukses "Tidak ada user gelap ber-UID 0 selain root."; else cetak_bahaya "BACKDOOR DETECTED: User ini memiliki hak root (UID 0): $UID_Z"; fi
            echo ""
            read -p "Tekan Enter untuk kembali..."
            ;;

        3)
            # ==========================================
            # MODUL 3: AUDIT DIREKTORI AKTIF
            # ==========================================
            clear
            cetak_judul "AUDIT FILE & DIREKTORI AKTIF CURRENT WORKDIR"
            CURRENT_DIR=$(pwd)
            WW_FILES=$(find "$CURRENT_DIR" -maxdepth 2 -type f -perm -0002 2>/dev/null)
            if [ -z "$WW_FILES" ]; then cetak_sukses "Aman. Tidak ada file world-writable."; else cetak_bahaya "Ditemukan file World-Writable:\n$WW_FILES"; fi
            echo ""
            read -p "Tekan Enter untuk kembali..."
            ;;

        4)
            # ==========================================
            # MODUL 4: MANAGEMENT / MEKANISME PERUBAHAN
            # ==========================================
            while true; do
                clear
                echo "=================================================================="
                echo "                 SUB-MENU MEKANISME PERUBAHAN SISTEM              "
                echo "=================================================================="
                echo " "
                echo " -- MANAJEMEN USER, SSH HARDENING & CUSTOM PORT --"
                echo " [1] Tambah USER BARU (Otomatis & Set Hak Sudo)"
                echo " [2] Hapus USER SISTEM (Otomatis Bersihkan Home Dir)"
                echo " [3] Amankan Layanan SSH (Matikan Root Login & Password Auth)"
                echo " [4] UBAH PORT SSH KE CUSTOM PORT + OTOMATIS ALLOW FIREWALL"
                echo " [5] Set Ulang Permission Direktori Aktif ke Standar (644/755)"
                echo " [6] Ubah Hostname Server"
                echo " "
                echo " -- MANAJEMEN FIREWALL (UFW) --"
                echo " [7] AKTIFKAN Firewall (Default Deny Inbound)"
                echo " [8] MATIKAN Firewall"
                echo " [9] Buka Port Standar Web (Allow Port 80 & 443)"
                echo " [10] Kunci & Batasi Akses SSH (Hanya IP Tertentu)"
                echo " "
                echo " -- MANAJEMEN IP ADDRESS & NETWORKING --"
                echo " [11] Cek Interface & IP Address Saat Ini"
                echo " [12] Ubah IP Address SEMENTARA (Runtime)"
                echo " [13] Ubah IP Address PERMANEN (Netplan Ubuntu)"
                echo " -- KEMBALI --"
                echo " [14] Kembali ke Menu Utama"
                echo " "
                echo "=================================================================="
                read -p "Pilih tindakan (1-14): " PIL_RUBAH

                case $PIL_RUBAH in
                    1)
                        cetak_judul "Tindakan: Membuat User Baru"
                        read -p "Masukkan Username baru: " NEW_UNAME
                        if id "$NEW_UNAME" &>/dev/null; then cetak_peringatan "User sudah ada!"; sleep 2; continue; fi
                        read -s -p "Masukkan Password : " NEW_PASS; echo ""
                        useradd -m -s /bin/bash "$NEW_UNAME"
                        echo "$NEW_UNAME:$NEW_PASS" | chpasswd
                        cetak_sukses "User '$NEW_UNAME' berhasil didaftarkan."
                        read -p "Berikan hak akses admin/sudo? (y/n): " MAU_SUDO
                        if [[ "$MAU_SUDO" =~ ^[Yy]$ ]]; then usermod -aG sudo "$NEW_UNAME" 2>/dev/null || usermod -aG wheel "$NEW_UNAME"; fi
                        sleep 2
                        ;;
                    2)
                        cetak_judul "Tindakan: Menghapus User"
                        read -p "Masukkan nama user yang mau DIHAPUS BERSIH: " DEL_UNAME
                        if ! id "$DEL_UNAME" &>/dev/null; then cetak_peringatan "User tidak ditemukan."; sleep 2; continue; fi
                        killall -u "$DEL_UNAME" -9 2>/dev/null
                        userdel -r -f "$DEL_UNAME"
                        cetak_sukses "User '$DEL_UNAME' berhasil dihapus."
                        sleep 2
                        ;;
                    3)
                        cetak_judul "Tindakan: Hardening SSH Daemon"
                        if [ -f /etc/ssh/sshd_config ]; then
                            cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_"$(date +%F)"
                            sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config
                            sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config
                            systemctl restart sshd || systemctl restart ssh
                            cetak_sukses "SSH Hardening diperbarui (Root & Password login dinonaktifkan)."
                        fi
                        sleep 2
                        ;;
                    4)
                        cetak_judul "Tindakan: Mengubah Port SSH & Integrasi Firewall"
                        if [ ! -f /etc/ssh/sshd_config ]; then
                            cetak_bahaya "Konfigurasi SSH (/etc/ssh/sshd_config) tidak ditemukan!"
                            sleep 2
                            continue
                        fi

                        # Mendapatkan informasi port saat ini
                        CURRENT_PORT=$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $2}')
                        [ -z "$CURRENT_PORT" ] && CURRENT_PORT=22
                        cetak_info "Port SSH yang aktif saat ini: $CURRENT_PORT"
                        
                        read -p "Masukkan nomor Custom Port SSH baru (Rekomendasi: 1024 - 65535): " NEW_SSH_PORT
                        
                        # Validasi input angka port
                        if [[ ! "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_SSH_PORT" -lt 1 ] || [ "$NEW_SSH_PORT" -gt 65535 ]; then
                            cetak_peringatan "Nomor port tidak valid! Harus berupa angka antara 1 - 65535."
                            sleep 3
                            continue
                        fi

                        cetak_info "[Langkah 1/3] Mendaftarkan port baru $NEW_SSH_PORT ke Firewall UFW..."
                        ufw allow "$NEW_SSH_PORT"/tcp comment "Custom SSH Port"
                        
                        cetak_info "[Langkah 2/3] Memperbarui berkas konfigurasi /etc/ssh/sshd_config..."
                        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_port_"$(date +%s)"
                        
                        # Cek apakah parameter 'Port' sudah ada atau masih dikomen (#)
                        if grep -q -i "^#\?Port " /etc/ssh/sshd_config; then
                            sed -i "s/^#\?Port.*/Port $NEW_SSH_PORT/g" /etc/ssh/sshd_config
                        else
                            echo "Port $NEW_SSH_PORT" >> /etc/ssh/sshd_config
                        fi

                        cetak_info "[Langkah 3/3] Melakukan restart service SSH..."
                        systemctl restart sshd || systemctl restart ssh
                        
                        if [ $? -eq 0 ]; then
                            cetak_sukses "Port SSH Berhasil diubah ke $NEW_SSH_PORT dan sudah di-allow di UFW."
                            cetak_peringatan "PENTING: Jangan tutup terminal ini dulu! Buka tab terminal baru dan uji koneksi: 'ssh -p $NEW_SSH_PORT user@ip_server'"
                        else
                            cetak_bahaya "Gagal merestart layanan SSH. Mengembalikan konfigurasi awal..."
                            mv /etc/ssh/sshd_config.bak_port_* /etc/ssh/sshd_config
                            systemctl restart sshd || systemctl restart ssh
                        fi
                        sleep 5
                        ;;
                    5)
                        cetak_judul "Tindakan: Remediasi Massal Permission"
                        CUR_DIR=$(pwd)
                        find "$CUR_DIR" -type d -exec chmod 755 {} +
                        find "$CUR_DIR" -type f -exec chmod 644 {} +
                        cetak_sukses "Remediasi selesai."
                        sleep 2
                        ;;
                    6)
                        cetak_judul "Tindakan: Mengubah Hostname"
                        read -p "Masukkan nama host baru: " H_BARU
                        if [ -n "$H_BARU" ]; then
                            hostnamectl set-hostname "$H_BARU"
                            sed -i "s/127.0.1.1.*/127.0.1.1\t$H_BARU/g" /etc/hosts
                            cetak_sukses "Hostname diubah menjadi $H_BARU."
                        fi
                        sleep 2
                        ;;
                    7)
                        cetak_judul "Tindakan: Mengaktifkan UFW"
                        # Memastikan port SSH yang dikonfigurasi saat ini diizinkan sebelum mengaktifkan UFW
                        CURRENT_PORT=$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $2}')
                        [ -z "$CURRENT_PORT" ] && CURRENT_PORT=22
                        ufw allow "$CURRENT_PORT"/tcp comment 'SSH Active Port'
                        ufw default deny incoming
                        echo "y" | ufw enable
                        cetak_sukses "Firewall aktif dengan proteksi port SSH aktif ($CURRENT_PORT)."
                        sleep 2
                        ;;
                    8)
                        ufw disable; sleep 2 ;;
                    9)
                        ufw allow 80/tcp; ufw allow 443/tcp; cetak_sukses "Web port opened."; sleep 2 ;;
                    10)
                        cetak_judul "Kunci SSH ke IP Tertentu"
                        CURRENT_PORT=$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $2}')
                        [ -z "$CURRENT_PORT" ] && CURRENT_PORT=22
                        read -p "Masukkan IP Terpercaya: " IP_TRUSTED
                        if [ -n "$IP_TRUSTED" ]; then
                            ufw delete allow "$CURRENT_PORT"/tcp &>/dev/null
                            ufw allow from "$IP_TRUSTED" to any port "$CURRENT_PORT" proto tcp comment 'Whitelisted Custom SSH'
                            cetak_sukses "SSH Port $CURRENT_PORT dikunci hanya untuk IP $IP_TRUSTED";
                        fi
                        sleep 2
                        ;;
                    11)
                        cetak_judul "Status Interface & IP Address"
                        ip -br addr show
                        echo ""
                        ip route show | grep default
                        read -p "Tekan Enter untuk kembali..."
                        ;;
                    12)
                        cetak_judul "Ubah IP Sementara (Runtime)"
                        read -p "Masukkan nama interface (e.g. enp0s3): " INT_NAME
                        read -p "Masukkan IP Baru + Subnet (e.g. 192.168.1.100/24): " INT_IP
                        if [ -n "$INT_NAME" ] && [ -n "$INT_IP" ]; then
                            ip addr add "$INT_IP" dev "$INT_NAME"
                            cetak_sukses "IP temporary ditambahkan.";
                        fi
                        sleep 2
                        ;;
                    13)
                        cetak_judul "Ubah IP Permanen (Netplan)"
                        NETPLAN_FILE=$(ls /etc/netplan/*.yaml | head -n 1)
                        if [ -z "$NETPLAN_FILE" ]; then cetak_bahaya "File Netplan tidak ketemu."; sleep 2; continue; fi
                        read -p "Interface (e.g. enp0s3): " NET_INT
                        read -p "IP Statis Baru (e.g. 192.168.1.50/24): " NET_IP
                        read -p "Gateway: " NET_GW
                        read -p "DNS (e.g. 8.8.8.8): " NET_DNS
                        read -p "Tulis konfigurasi? (y/N): " KONF_NET
                        if [[ "$KONF_NET" =~ ^[Yy]$ ]]; then
                            cp "$NETPLAN_FILE" "${NETPLAN_FILE}.bak_$(date +%s)"
                            cat <<EOF > "$NETPLAN_FILE"
network:
  version: 2
  renderer: networkd
  ethernets:
    $NET_INT:
      dhcp4: no
      addresses: [$NET_IP]
      routes:
        - to: default
          via: $NET_GW
      nameservers:
        addresses: [$NET_DNS]
EOF
                            netplan apply
                            cetak_sukses "Netplan diterapkan.";
                        fi
                        sleep 3
                        ;;
                    14)
                        break
                        ;;
                esac
            done
            ;;

        5)
            echo "Keluar dari skrip keamanan. Pastikan log di $LOG_FILE dianalisis kembali."
            exit 0
            ;;
        *)
            cetak_warning "Opsi salah, silakan pilih menu 1-5."
            sleep 2
            ;;
    esac
done
