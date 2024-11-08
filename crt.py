import psycopg2
import sys
import time
QUERY = """
SELECT array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES, x509_commonName(sub.CERTIFICATE) COMMON_NAME, x509_notBefore(sub.CERTIFICATE) NOT_BEFORE
FROM (
	SELECT cai.*
	FROM certificate_and_identities cai
	WHERE plainto_tsquery('certwatch', '##DOMAIN##') @@ identities(cai.CERTIFICATE) AND cai.NAME_VALUE ILIKE ('%' || '##DOMAIN##' || '%')
	ORDER BY x509_notBefore(cai.CERTIFICATE) DESC
	LIMIT 20000
) sub 
GROUP BY sub.CERTIFICATE
ORDER BY NOT_BEFORE DESC;
"""

def get_domains(connection, domain_name):
	"""
	Resolve domains for a given root domain name.
	"""

	domains = []

	try:
		cursor = connection.cursor()

		start = time.time()
		cursor.execute(QUERY.replace("##DOMAIN##", domain_name))
		print(f'execute : {time.time() - start}')

		start = time.time()
		data = cursor.fetchall()
		print(f'fetchall : {time.time() - start}')

		cursor.close()
		for item in data:
			for d in item[0]:
				if d not in domains:
					domains.append(d)
			
			if item[1] not in domains:
				domains.append(item[1])

	except Exception as e:
		print(f"[-] get_domains error ({domain_name}): {e}")
		return []

	return domains


connection = psycopg2.connect(
	user = "guest",
	host = "crt.sh",
	port = "5432",
	dbname = "certwatch"
)
connection.set_session(readonly=True, autocommit=True)

domains = get_domains(connection, sys.argv[1])
for d in domains:
	pass
	# print(d)
