from src.models.User import Product

def utility_processor():
    def get_product_by_id(product_id):
        # Query the database to retrieve the product with the given ID
        product = Product.query.filter_by(id=product_id).first()
        return product

    # Return the function as a dictionary so it can be used in templates
    return dict(get_product_by_id=get_product_by_id)