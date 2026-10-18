from flask import Flask, jsonify, request

from api.service import OrderService

app = Flask(__name__)
svc = OrderService()


@app.route("/api/v1/orders/<order_id>", methods=["GET"])
def get_order(order_id):
    return svc.get_item(order_id)


@app.route("/api/v1/orders/<order_id>", methods=["DELETE"])
def delete_order(order_id):
    svc.delete_item(order_id)
    return jsonify({"ok": True})


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run()
