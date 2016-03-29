__author__ = 'Daniel Sánchez'
# encoding:utf-8
import tkinter.messagebox as msgbox
import tkinter as tk
from client_socket import SSLClientSocket
from server_socket import SSLServerSocket
import threading
import socket

# Possible options to the message box's format
msgbox_options = {"info": msgbox.showinfo,
           "warning": msgbox.showwarning,
           "error": msgbox.showerror}


def generate_msgbox(title="", message="", msgbox_option="info"):
    if msgbox_option not in msgbox_options:
        option = "info"  # if the option is none of the options, we set it "info" as default
    # In order to display a message box we need a root window
    root = tk.Tk()
    root.withdraw()  # With this sentence, we hide the root window in order to display only the message box

    msgbox_options[msgbox_option](title, message)  # displays the message box


def generate_server_interface():
    root = tk.Tk()
    root.title("Server socket - Stopped")
    root.resizable(width=tk.FALSE, height=tk.FALSE)
    root.geometry("300x60")
    global server
    server = None

    # Server status frame
    status_frame = tk.Frame(root)
    status_frame.pack()

    label = tk.Label(status_frame, text="Server status:")
    label.pack(side=tk.LEFT, padx=1, pady=1)
    status = tk.Label(status_frame, text="stopped", fg="red")
    status.pack(side=tk.LEFT, padx=1,pady=1)
    address = tk.Label(status_frame, text="Address: {0}:{1}".format(socket.gethostbyname(socket.gethostname()), "7070"))
    address.pack(side=tk.LEFT, padx=1, pady=1)

    # server = ServerSocket()

    # Buttons frame
    button_frame = tk.Frame(root)
    button_frame.pack()

    def start_server_callback():
        globals()['server'] = SSLServerSocket()

        # We call the server asynchronously to not freeze the application. We create a thread
        thr = threading.Thread(target=globals()['server'].run_server, args=(), kwargs={})
        thr.start()

        root.title("Server socket - Running")
        status['text'] = "running"
        status['fg'] = "green"

        stop_btn['state'] = tk.NORMAL
        start_btn['state'] = tk.DISABLED

    start_btn = tk.Button(button_frame, text="Start server", command=start_server_callback)
    start_btn.pack(side=tk.LEFT, padx=1, pady=1)

    def stop_server_callback():
        server.stop_server()

        root.title("Server socket - Stopped")
        status['text'] = "stopped"
        status['fg'] = "red"
        stop_btn['state'] = tk.DISABLED
        start_btn['state'] = tk.NORMAL
        msgbox.showinfo("Stop server", "The server was stopped.")

    stop_btn = tk.Button(button_frame, text="Stop server", command=stop_server_callback, state=tk.DISABLED)
    stop_btn.pack(side=tk.LEFT, padx=1, pady=1)

    def on_closing():
        if server is not None:  # We check if the server was started
            server.stop_server()
            server.close_server()  # We clean the socket
        root.quit()  # We close the window

    root.protocol("WM_DELETE_WINDOW", on_closing)  # Handle the windows close
    root.mainloop()


def generate_client_interface():
    #TODO GENERATE METHOD
    """This method will generate the client interface to send the data to the server"""
    root = tk.Tk()
    root.title("Client socket - Not connected")
    root.resizable(width=tk.FALSE, height=tk.FALSE)
    global client
    client = None

    # Client status frame
    status_frame = tk.Frame(root)
    status_frame.pack()

    label = tk.Label(status_frame, text="Client status:")
    label.pack(side=tk.LEFT, padx=1, pady=1)
    status = tk.Label(status_frame, text="not connected", fg="red")
    status.pack(side=tk.LEFT, padx=1,pady=1)
    address = tk.Label(status_frame, text="Address: {0}:{1}".format(socket.gethostbyname(socket.gethostname()), "7070"))
    address.pack(side=tk.LEFT, padx=1, pady=1)

    # Buttons frame
    button_frame = tk.Frame(root)
    button_frame.pack(pady=(0, 2))

    def start_client_callback():
        globals()['client'] = SSLClientSocket()

        try:
            host = host = socket.gethostbyname(socket.gethostname())
            port = 7070
            client.connect(host, port)

            root.title("Client socket - Connected")
            status['text'] = "connected"
            status['fg'] = "green"

            stop_btn['state'] = tk.NORMAL
            start_btn['state'] = tk.DISABLED

            origin_entry['state'] = tk.NORMAL
            origin_label['state'] = tk.NORMAL
            destiny_entry['state'] = tk.NORMAL
            destiny_label['state'] = tk.NORMAL
            amount_entry['state'] = tk.NORMAL
            amount_label['state'] = tk.NORMAL

            send_button['state'] = tk.NORMAL

        except Exception:
            generate_msgbox("Error", "You can not establish a connection because the target machine expressly "
                                        "rejected that connection. Check if the server socket is running.\n"
                                        "The connection address was '{0}:{1}'".format(host, port), "error")
        except socket.timeout:
            generate_msgbox("Timeout", "Exceeded the timeout for the connection when waiting for data (timeout: 5 seconds).", "warning")

    start_btn = tk.Button(button_frame, text="Connect client", command=start_client_callback)
    start_btn.pack(side=tk.LEFT, padx=1, pady=1)

    def stop_client_callback():
        client.close_socket()

        root.title("Client socket - Not connected")
        status['text'] = "stopped"
        status['fg'] = "red"
        stop_btn['state'] = tk.DISABLED
        start_btn['state'] = tk.NORMAL

        origin_entry['state'] = tk.DISABLED
        origin_label['state'] = tk.DISABLED
        destiny_entry['state'] = tk.DISABLED
        destiny_label['state'] = tk.DISABLED
        amount_entry['state'] = tk.DISABLED
        amount_label['state'] = tk.DISABLED

        send_button['state'] = tk.DISABLED

        msgbox.showinfo("Disconnected", "The client was disconnected from the server.")

    stop_btn = tk.Button(button_frame, text="Disconnect client", command=stop_client_callback, state=tk.DISABLED)
    stop_btn.pack(side=tk.LEFT, padx=1, pady=1)

    # Data frame
    data_frame = tk.Frame(root)
    data_frame.pack()

    # Origin account name
    origin_label = tk.Label(data_frame, text="Origin account name", state=tk.DISABLED)
    origin_label.grid(row=0, column=0, padx=2, pady=2)
    origin_entry = tk.Entry(data_frame, state=tk.DISABLED)
    origin_entry.grid(row=1, column=0, padx=2, pady=2)

    coma_1 = tk.Label(data_frame, text=",")
    coma_1.grid(row=0, column=1, padx=2, pady=2)

    # Destiny account name
    destiny_label = tk.Label(data_frame, text="Destiny account name", state=tk.DISABLED)
    destiny_label.grid(row=0, column=2, padx=2, pady=2)
    destiny_entry = tk.Entry(data_frame, state=tk.DISABLED)
    destiny_entry.grid(row=1, column=2, padx=2, pady=2)

    coma_2 = tk.Label(data_frame, text=",")
    coma_2.grid(row=0, column=3, padx=2, pady=2)

    # Transfer amount
    amount_label = tk.Label(data_frame, text="Transfer amount", state=tk.DISABLED)
    amount_label.grid(row=0, column=4, padx=2, pady=2)
    amount_entry = tk.Entry(data_frame, state=tk.DISABLED)
    amount_entry.grid(row=1, column=4, padx=2, pady=2)

    def send_data_callback():
        origin = origin_entry.get()
        destiny = destiny_entry.get()
        amount = amount_entry.get()
        data_to_send = origin+", "+destiny+", "+amount

        try:
            _dict = client.send_data(data_to_send)
            generate_server_response(_dict)  # We show the server response in a window
        except socket.timeout:
            generate_msgbox("Timeout", "Exceeded the timeout for the connection (timeout: 5 seconds).", "warning")

    send_button = tk.Button(root, text="Send data", command=send_data_callback, state=tk.DISABLED)
    send_button.pack(pady=(0, 3))

    def on_closing():
        if client is not None:
            client.close_socket()  # We clean the socket on exit
        root.quit()  # We close the window

    root.protocol("WM_DELETE_WINDOW", on_closing)  # Handle the windows close
    root.mainloop()


def generate_server_response(dict):
    """This method will return the response sent by the server when the data is processed"""
    message = dict['message']  # The client message returned by the server
    nonce = dict['nonce']  # The client nonce returned by the server
    hmac = dict['hmac']  # The message hmac returned by the server
    replay = dict['replay']  # Sends if it's been a reply attack
    integrity = dict['integrity']  # Sends if the integrity is correct

    root = tk.Tk()
    root.title("Server response")
    root.resizable(0, 0)


    # The status frame
    status_frame = tk.Frame(root)
    status_frame.pack()

    status_label = tk.Label(status_frame, text="Message status:", font="bold")
    status_label.grid(row=0, column=0)
    status = tk.Label(status_frame, font="bold")
    if replay:
        status['text'] = "The NONCE was sent already (maybe replay attack)."
        status['fg'] = "orange"
    elif not integrity:
        status['text'] = "The message was modified. The integrity failed."
        status['fg'] = "red"
    else:
        status['text'] = "The message was received correctly."
        status['fg'] = "green"
    status.grid(row=0, column=1)

    # The content frame
    content = tk.Frame(root)
    content.pack(padx=2)

    message_label = tk.Label(content, text="Message received by the server:")
    message_label.grid(row=0, column=0, padx=2, pady=2, sticky=tk.E)
    _message = tk.Label(content, text="'{0}'".format(message))
    _message.grid(row=0, column=1, padx=2, pady=2, sticky=tk.W)

    hmac_label = tk.Label(content, text="HMAC received by the server:")
    hmac_label.grid(row=1, column=0, padx=2, pady=2, sticky=tk.E)
    _hmac = tk.Label(content, text="{0}".format(hmac))
    _hmac.grid(row=1, column=1, padx=2, pady=2, sticky=tk.W)

    nonce_label = tk.Label(content, text="NONCE received by the server:")
    nonce_label.grid(row=2, column=0, padx=2, pady=2, sticky=tk.E)
    _nonce = tk.Label(content, text="{0}".format(nonce))
    _nonce.grid(row=2, column=1, padx=2, pady=2, sticky=tk.W)

    def accept_callback():

        root.destroy()

    accept_btn = tk.Button(root,text="Accept", command=accept_callback)
    accept_btn.pack(padx=2, pady=2)

    root.mainloop()

if __name__ == "__main__":
    pass