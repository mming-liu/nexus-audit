class OrderService:
    def get_item(self, order_id):
        return {"id": order_id, "owner": 42}

    def delete_item(self, order_id):
        self._check_order_owner(order_id)
        self.db_delete(order_id)

    def _check_order_owner(self, order_id):
        return True  # TODO: 占位，实际应校验归属

    def db_delete(self, order_id):
        pass
