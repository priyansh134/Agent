import mysql.connector

try:
    conn = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="12priyanshu#AS",  # change to your MySQL password
        database="DuckDb_Testing"     # change to your DB name
    )

    if conn.is_connected():
        print("✅ Connected to database!")

        cursor = conn.cursor()

        # Run the SELECT query
        cursor.execute("SELECT * FROM employee;")

        # Fetch all rows
        rows = cursor.fetchall()

        # Print results
        for row in rows:
            print(row)

        # Close the cursor & connection
        cursor.close()
        conn.close()

except mysql.connector.Error as err:
    print(f"❌ Error: {err}")
