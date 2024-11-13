from encryptionBase import *
from AES import *
from Serpent import *
from Blowfish import *
from DES import *
from Twofish import *
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter.filedialog import askopenfilename, asksaveasfilename
import datetime



def decrypt():
    filepath = askopenfilename(
        filetypes=[("All Files", "*.*")]
    )
    if not filepath:
        return
    with open(filepath, "rb") as fp:
        data = fp.read()
    s = ''
    for x in data:
       s = s + hex(x)[2:].zfill(2)
    text = d.decrypt(s, mode.get(),padding.get())
    s = bytearray.fromhex(text)
    fp.close()
    with open(filepath, 'wb') as fp:
        fp.write(s)

def encrypt():
    filepath = askopenfilename(
        filetypes=[("All Files", "*.*")]
    )
    if not filepath:
        return
    with open(filepath, "rb") as fp:
        data = fp.read()
    s = ''
    for x in data:
       s = s + hex(x)[2:].zfill(2)
    text = d.encrypt(s, mode.get(),padding.get())
    s = bytearray.fromhex(text)
    fp.close()
    with open(filepath, 'wb') as fp:
        fp.write(s)

d = AES()
d.generateKeys('0')

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
	d.generateKeys(password.get(1.0, tk.END)[0:len(password.get(1.0, tk.END))-1])


window = tk.Tk()
window.title("Encryptor")

Textedit = scrolledtext.ScrolledText(window, height = 15, width = 80)
frame = tk.Frame(window, height = 20)
btn_open = tk.Button(frame, text="decrypt", command=decrypt)
btn_save = tk.Button(frame, text="encrypt", command=encrypt)


mkey = tk.Button(frame, text="make", command=make_key)


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


btn_save.grid(row=1, column=0, sticky="ew")
btn_open.grid(row=1, column=1, sticky="ew")
encryptalg.grid(row = 0,column = 0, sticky="ew")
mode.grid(row = 0,column = 1, sticky="ew")
padding.grid(row = 0,column = 2, sticky="ew")
password.grid(row =0, column = 3, columnspan = 3, sticky="ew")
iv_field.grid(row =1, column = 3, columnspan = 3, sticky="ew")
mkey.grid(row =1 , column = 2, sticky="ew")

frame.pack(expand=True, fill = 'x',side='top')#grid(row=1, column=0, sticky="nsew")
#Textedit.pack(expand=True, fill = 'both',side='top')#grid(row=0, column=0, sticky="nsew")

window.mainloop()