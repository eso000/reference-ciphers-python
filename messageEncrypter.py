from encryption_base import *
from AES import *
from Serpent import *
from Blowfish import *
from DES import *
from Twofish import *
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter.filedialog import askopenfilename, asksaveasfilename



d = AES()
d.generate_keys('0')

def make_key():
	global d
	if encryptalg.get() == 'Serpent':
		d = Serpent()
	if encryptalg.get() == 'AES':
		d = AES()
	if encryptalg.get() == 'Blowfish':
		d = Blowfish()
	if encryptalg.get() == 'Twofish':
		d = Twofish()
	if encryptalg.get() == 'DES':
		d = DES()
	if encryptalg.get() == '3DES':
		d = TrippleDES() 
	d.generate_keys(password.get(1.0, tk.END)[0:len(password.get(1.0, tk.END))-1])

def encrypt():
	text = clear_edit.get(1.0, tk.END)
	text = d.bin_to_hex(d.string_to_bin(text[0:len(text)-1]))
	text = d.encrypt(text,mode =  mode.get(), padding = padding.get(),
		 iv = iv_field.get(1.0, tk.END)[0:len(iv_field.get(1.0, tk.END))-1])
	cipher_edit.delete(1.0, tk.END)
	cipher_edit.insert(tk.END, text)


def decrypt():
	text = cipher_edit.get(1.0, tk.END)
	text = d.decrypt(text[0:len(text)-1], mode.get(),padding.get(), 
			iv = iv_field.get(1.0, tk.END)[0:len(iv_field.get(1.0, tk.END))-1])
	text = d.bin_to_string(d.hex_to_bin(text))
	clear_edit.delete(1.0, tk.END)
	clear_edit.insert(tk.END, text)

window = tk.Tk()
window.title("Encryptor")


clear_edit = scrolledtext.ScrolledText(window, height = 15, width = 80)
cipher_edit = scrolledtext.ScrolledText(window, height = 15, width = 80)
frame = tk.Frame(window, height = 20)

btn_encrypt = tk.Button(frame, text="encrypt", command=encrypt)
btn_decrypt = tk.Button(frame, text="decrypt", command=decrypt)

mkey = tk.Button(frame, text="mkey", command=make_key)


password = tk.Text(frame, height = 1, width = 50)
iv_field = tk.Text(frame, height = 1, width = 50)

encryptalg = ttk.Combobox(frame,width = 10, state='readonly')
encryptalg['values'] = ('AES', 
                        'Serpent',
                        'Twofish',
                        'Blowfish',
                        '3DES',
                        'DES')
encryptalg.current(0)
mode = ttk.Combobox(frame, width = 10,  state='readonly')
mode['values'] = ('ECB', 
                  'CBC')
mode.current(1)
padding = ttk.Combobox(frame, width = 10,  state='readonly')
padding['values'] = ('bit', 
                     'TBC',
                     'byt',
                     'ISO 7816-4',
                     'PKCS',
                     'ANSI X9.23')
padding.current(1)


btn_encrypt.grid(row=1, column=0, sticky="ew")
btn_decrypt.grid(row=1, column=1, sticky="ew")
encryptalg.grid(row = 0,column = 0, sticky="ew")
mode.grid(row = 0,column = 1, sticky="ew")
padding.grid(row = 0,column = 2, sticky="ew")
password.grid(row =0, column = 3, columnspan = 3, sticky="ew")
iv_field.grid(row =1, column = 3, columnspan = 3, sticky="ew")
mkey.grid(row =1 , column = 2, sticky="ew")

clear_edit.pack(expand=True, fill = 'both',side='top')#grid(row=0, column=0, sticky="nsew")
frame.pack(expand=True, fill = 'x',side='top')#grid(row=1, column=0, sticky="nsew")
cipher_edit.pack(expand=True, fill = 'both',side='top')#grid(row=2, column=0, sticky="nsew")

window.mainloop()