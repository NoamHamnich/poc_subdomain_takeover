import psycopg2
import sys
import time
from datetime import datetime
import signal

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

def is_valid(test, domain_name):
	if '*' in test:
		return False
	
	if not test.endswith(f'.{domain_name}'):
		return False

	return True

def get_domains(connection, domain_name):
	"""
	Resolve domains for a given root domain name.
	"""

	domains = []

	try:
		cursor = connection.cursor()

		start = time.time()
		cursor.execute(QUERY.replace("##DOMAIN##", domain_name))

		data = cursor.fetchall()

		cursor.close()
		for item in data:
			try:
				for domain in item[0]:
					domain = domain.lower()
					if domain not in domains:
						if is_valid(domain, domain_name):
							domains.append(domain)
			except:
				pass

			
			try:
				domain = item[1].lower()
				if domain not in domains:				
					if is_valid(domain, domain_name):
						domains.append(domain)
			except:
				pass
	
	except Exception as e:
		return []

	return domains


DOMAINS = []

def print_domains():
	global DOMAINS

	for domain in DOMAINS:
		print(domain)


def handler(signum, frame):
	print_domains()
	print('over !!')

	sys.exit()


signal.signal(signal.SIGALRM, handler)
signal.alarm(180)

connection = psycopg2.connect(
	user = "guest",
	host = "crt.sh",
	port = "5432",
	dbname = "certwatch"
)
connection.set_session(readonly=True, autocommit=True)

with open('/tmp/infile', 'r') as fp:
	lines = fp.read().split('\n')

for line in lines:
	if line.strip() == '':
		continue
	
	domains = get_domains(connection, line)
	for d in domains:
		DOMAINS.append(d)

print_domains()
