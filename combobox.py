#!/usr/bin/env python3  
# coding=utf-8  
  
from tkinter import *  
from tkinter import ttk  
  
__author__ = 'Administrator'  
  
  
def show_msg(*args):  
    print(players.get())  
  
root = Tk()  
name = StringVar()  
players = ttk.Combobox(root, textvariable=name)  
players["values"] = ("成龙", "刘德华", "周星驰")  
players["state"] = "readonly"  
  
players.current(2)  
# players.set("演员表")  
# print(players.get())  
  
players.bind("<<ComboboxSelected>>", show_msg)  
  
players.pack()  
root.mainloop()
