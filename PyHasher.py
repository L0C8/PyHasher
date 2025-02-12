import tkinter as tk
from tkinter import ttk

def setSize():
    root.resizable(False,False)                    
    w = 256 
    h = 128 
    ws = root.winfo_screenwidth()/2
    hs = root.winfo_screenheight() 
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    root.geometry('%dx%d+%d+%d' % (w, h, x, y))

def change_theme():
    if style.theme_use() == 'alt':
        style.theme_use('clam')
        root.configure(background='black')
    else:
        style.theme_use('alt')
        root.configure(background='white')

root = tk.Tk()
style = ttk.Style(root)
setSize()
#
style.theme_use('alt')

frame = ttk.Frame(root).grid()

btn = ttk.Button(frame, text="Sample", command=lambda: change_theme())
btn.grid(column=0, row=1)
#
root.mainloop()
