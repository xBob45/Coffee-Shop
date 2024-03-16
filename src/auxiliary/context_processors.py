from src.models.User import db, Product, OrderItems

def utility_processor():
    def get_product_by_id(product_id):
        product = Product.query.filter_by(id=product_id).first()
        return product
    
    def get_products_by_order_id(order_id):
        order_items = OrderItems.query.filter_by(order_id=order_id).all()
        print(order_items)
        product_ids = [order_item.product_id for order_item in order_items]
        print(product_ids)
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        print(products)
        return products
    
    def get_order_items(order_id):
        order_items_with_products = db.session.query(OrderItems, Product).join(Product, OrderItems.product_id == Product.id).filter(OrderItems.order_id == order_id).all()
        return order_items_with_products

    return dict(get_product_by_id=get_product_by_id,
                get_products_by_order_id=get_products_by_order_id,
                get_order_items=get_order_items)

    