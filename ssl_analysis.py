import sys
import requests
from urllib import parse
from pprint import pprint
#This script takes the output of a www.immuniweb.com/ssl/ SSL test and checks it against the SSL decryption configurations that Palo Alto supports.

#todo:
#Feed in list of Hostnames
#Use the Immuniweb API for full automation and be able to run tests from the script.
#Add args for URL, file of URLs
#Run test for all PANOS versions

#This script does not distinguish between decryption ciphers, and perfect forward secrecy (PFS) decryption ciphers. This does not check RSA key size.
panos_81 = {
"tls_versions":["SSLv3","TLSv1.0","TLSv1.1","TLSv1.2"],
"decryption_ciphers":["RSA_RC4_128_MD5","RSA_RC4_128_SHA","RSA_3DES_EDE_CBC_SHA","RSA_AES_128_CBC_SHA","RSA_AES_256_CBC_SHA","RSA_AES_128_CBC_SHA_256","RSA_AES_256_CBC_SHA_256","RSA_AES_128_GCM_SHA_256","RSA_AES_256_GCM_SHA_384","DHE_RSA_3DES_EDE_CBC_SHA","DHE_RSA_AES_128_CBC_SHA","DHE_RSA_AES_256_CBC_SHA","DHE_RSA_AES_128_CBC_SHA_256","DHE_RSA_AES_256_CBC_SHA_256","DHE_RSA_AES_128_GCM_SHA_256","DHE_RSA_AES_256_GCM_SHA_384","ECDHE_RSA_AES_128_CBC_SHA","ECDHE_RSA_AES_256_CBC_SHA","ECDHE_RSA_AES_128_CBC_SHA_256","ECDHE_RSA_AES_256_CBC_SHA_384","ECDHE_RSA_AES_128_GCM_SHA_256","ECDHE_RSA_AES_256_GCM_SHA_384","ECDHE_ECDSA_AES_128_CBC_SHA","ECDHE_ECDSA_AES_256_CBC_SHA","ECDHE_ECDSA_AES_128_CBC_SHA_256","ECDHE_ECDSA_AES_256_CBC_SHA_384","ECDHE_ECDSA_AES_128_GCM_SHA_256","ECDHE_ECDSA_AES_256_GCM_SHA_384"],
"elliptical_curves":["P-192","P-224","P-256","P-384","P-521"]
}


def extract_id(url):
	parameters=dict(parse.parse_qsl(parse.urlsplit(url).query))
	return parameters["id"]
	
def get_test(url):
	#Get the actual JSON from the API
	payload={"id":extract_id(url)}
	headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"}
	get_results=requests.post("https://www.immuniweb.com/ssl/api/v1/get_result/get_result_1564778052344.html", data=payload,headers=headers)
	return get_results.json()
	
	
'''
If automating this more, then we'll start down this path.
def start_test(domain,port,choosen_ip,recheck):
	start_test_payload={"domain":domain,"port":port,"choosen_ip":choosen_ip,"recheck":recheck}
	start_test=requests.post("https://www.immuniweb.com/ssl/api/v1/check/1451425590.html", data=start_test_payload)
	
	response=start_test.json()
	return response[job_id]

def get_results(job_id):
	have_results=False
	while have_results==False:
		retreive_reults_payload={"job_id":job_id}
		retreive_reults=requests.post("https://www.immuniweb.com/ssl/api/v1/get_result/1451425590.html", data=retreive_reults_payload)
		retreive_reults_response=retreive_reults.json()
		if retreive_reults_response["status"] ==
'''
url=input("First, go to https://www.immuniweb.com/ssl/ and run your test. Once the test is complete, paste the url here.\n>>")
ssl_report = get_test(url)
compact_cipher=[]
panos=panos_81
#Immuniweb's cipher format is slightly different from Palo Alto's.
#Remove the underscores to make the format consistent.
for cipher in panos["decryption_ciphers"]:
	compact_cipher.append(cipher.replace("_",""))
panos["decryption_ciphers"]=compact_cipher
unsupported_config=[]


#Check supported Ciphers/Versions based on the NIST output
for server_cipher_suite in ssl_report["nist"]["supported_cipher_suites"]:
	#Remove text we don't need so that the supported cipher list matches the output of immuniweb.com's JSON.
	prepped_cipher=server_cipher_suite["value"].replace("WITH_","").replace("TLS_","").replace("_","")

	#Check ciphers
	if prepped_cipher not in panos["decryption_ciphers"]:
		unsupported_config.append(server_cipher_suite["value"])
	
	#Check TLS/SSL version
	for protocol in server_cipher_suite["protocols"]:
		if protocol not in panos["tls_versions"]:
			unsupported_config.append("SSL/TLS "+protocol)

#Check support Elliptic curves
for ecc in ssl_report["nist"]["supported_elliptic_curves"]:
	tokenized_value=ecc["value"].split(" ")
	server_ecc=tokenized_value[0]
	if server_ecc not in panos["elliptical_curves"]:
		unsupported_config.append("Elliptical Curve "+server_ecc)
			
#Remove duplicates
unsupported_config = list(dict.fromkeys(unsupported_config))
pprint(unsupported_config)
