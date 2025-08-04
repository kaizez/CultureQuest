from sqlalchemy import create_engine, inspect, text 

engine = create_engine("mysql+pymysql://SQLUser:Pleasestopleakingenv@staging.nypdsf.me:8080/culturequest")

def check_tables():
        inspector = inspect(engine)
        
        # Get a list of all table names
        table_names = inspector.get_columns('user_points')
        
        if table_names:
            print("Existing tables:")
            for table_name in table_names:
                print(f"- {table_name}")

def check_data():
    query = text(f"SELECT * FROM users")

    # Execute the query
    result = connection.execute(query)

    # Fetch all rows from the result
    rows = result.fetchall()

    # Check if there are any rows to process
    if rows:
        print(f"Reading data from table':")
        # Iterate over the rows and print each one
        for row in rows:
            print(row)
try:
    with engine.connect() as connection:
        check_tables()        
except Exception as e:
    print(e)