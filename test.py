import socket

@app.route("/test")
def test():
    try:
        socket.create_connection(("smtp.gmail.com", 587), timeout=10)
        return "SMTP reachable"
    except Exception as e:
        return str(e)