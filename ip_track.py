from flask import request
DB = "visitors.db"
MAX_VISITS = 25

def get_ip():

    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0]

    return request.remote_addr