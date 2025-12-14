import psycopg2
url = 'postgresql://postgres:postgres@ego-postgres:5432/ego?sslmode=disable'
print('Connecting to', url)
conn = psycopg2.connect(url)
cur = conn.cursor()
cur.execute('SELECT 1')
print('Result:', cur.fetchone())
conn.close()
