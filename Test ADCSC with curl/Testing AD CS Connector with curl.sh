#!/bin/bash

# Purpose: Test ADCS Connector setup.
# 2018-05 / ol

# ==========================================================================
# Purpose: 
# 
# The AD CS Connector is used to retrieve certificates for Jamf Pro.
# Before configuring Jamf Pro, we may need to test network connectivity to
# ensure that communications will flow properly and make sure our service 
# account has permissions to get certs from AD CS. It may be easier to test
# this from this script since running a full enrollment workflow to
# trigger certificate requests in Jamf Pro take more time. 
# 
# Procedure:
# 
# After installing the AD CS Connector, you will have saved three items: 
# - client-cert.pfx
# - adcs-proxy-ca.cer
# - The pfx/p12 password that was written to your PowerShell terminal.
# 
# Put the two cert files in a folder alongside this script and assign the 
# password for client-cert.pfx to the "clientPfxPassword" variable up above. 
# 
# There are two curl commands that we will be sending to the Connector.
# The first call is to tell it that it should ask AD CS to sign a
# certificate. AD CS will create the signature and save it in it's database. 
# The second curl command will ask AD CS to retrieve the signature from the 
# keystore. 
# ==========================================================================


# ==========================================================================
# [!] This is for lab-ing things out. Like if you're testing
#     against a production CA, don't go copying your ADCS 
#     Connector Client key and password all over the place
#     willy-nilly. Guard it like a very important password. 
# 
#     Re-do the install once you have things tested so you
#     get a new client cert. 
# ==========================================================================

# TO-DO:
# Split CONNECTOR_HOSTPORT, test dns resolution for correct hostname, ping server (but only warn if you can't), test curl to hostport.


# ==========================================================================
# SETTINGS: 
# ==========================================================================

# What's the hostname of your issuing or stand-alone CA server? 
# (Just the FQDN host name, no https/ports or anything like that...)
ADCS_CA_hostname="adcs.my.org"

# What's the instance name of the CA? You can run certsrv if you're not sure what it is. 
# The instance name will be listed right under "Certificate Authority (Local)"
ADCS_CA_InstanceName="My Issuing CA"

# What template do you want to use? 
# If using an enterprise CA, fill this in. 
# If using a standalone CA, leave it blank.
# The AD CS template can determine things like the how long until the 
#  cert expires, certificate purpose (OIDs), etc. 
ADCS_CA_template="User"   # On an enterprise CA
# ADCS_CA_template=""       # On a standalone CA

# The passphrase for the private key file ("client-cert.pfx") that we will use to identify 
# ourselves to the AD CS Connector. You get this from the connector's PowerShell installer 
# script's output)
clientPfxPassword='crypticpassword'

# The "fqdn:port" of the AD CS Connector host running IIS 
# (Don't include https:// or a trailing "/"). 
# You only need to includ a :port at the end if you're not using 443
# E.g. : "adcs_connector.my.org" or "adcs_connector.my.org:8443" 

CONNECTOR_HOSTPORT="adcs_connector_host.my.org"

# INFORMATION FOR THE CSR... 
# What do you want as the subject for our cert? It can be anything you want... 
subject="username@my.org"
# When we have a new keypair created and signed by the CA, we'll export it to a p12 
# locked with a password. You wouldn't put a password in a script or pass it on the
# command line in real life, of course. Put the password you want to use here...
passwordForTheNewIdentityFile='mI gr8 pa55w0rd'

#  END OF SETTINGS...

# =================================================================================
# =================================================================================

# CODE...

myexit () {
  echo
  echo '======================================================'
  echo "Script ended on error."
  echo '======================================================'
  echo '======================================================'
  echo
  echo
  exit 1
}

echo "Starting test of ADCSC"

pathToMe=$( dirname "$0" )
pathToMe="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

CONNECTOR_URL="https://${CONNECTOR_HOSTPORT}"

echo "Your settings: "
echo " CN for requested cert: /CN=${subject}"

echo " ADCS_CA_hostname : $ADCS_CA_hostname"
echo " ADCS_CA_InstanceName : $ADCS_CA_InstanceName"
echo " ADCS_CA_template : $ADCS_CA_template"
#echo " clientPfxPassword : $clientPfxPassword"
echo
echo " CONNECTOR_URL : $CONNECTOR_URL"
echo
echo " Path to this script : "
echo "  $pathToMe"
echo



subjNoDots=$(echo "$subject" | tr "." "_" )
timeStamp=$(date +"%Y-%m-%d_%H-%M-%S")
testFolder="${pathToMe}/ADCS Connector Test - ${subjNoDots} ${timeStamp}" 

echo " Folder where I'll save the keypair I'm about to request:"
echo "  \"${testFolder}\""

# Make a folder to save the new identity keypair we're creating...
mkdir "${testFolder}"
open "${testFolder}"


authenticationCertSubFolder='ADCSC Certs'

# When the connector exports IIS's TLS cert's public key for upload into the JSS setup 
# page, it's a CER/DER format, but the curl commands we'll be using require a .PEM, so 
# we'll need to convert. Alternately, we could just ask IIS for it's cert, or just use 
# "--insecure" curl.
serverCertPath_supplied="${pathToMe}/${authenticationCertSubFolder}/server-cert.cer"
echo
echo " serverCertPath_supplied : "
echo "  $serverCertPath_supplied"
echo


echo '======================================================'
echo '[step] Testing paths...'
if test -f "$serverCertPath_supplied"; then
	echo " [ok] I found the server cert file."
else
	echo " [error] Could not find the server cert file."
	myexit
fi

#This is the "ask the server for the cert" method...
# openssl s_client -showcerts -connect "${CONNECTOR_HOSTPORT}" </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${serverCertChainPath}"
# echo
# echo "Server cert retrieved from Connector and saved to \"${serverCertChainPath}\""

serverCertPath_converted="${testFolder}/server-cert.pem"
echo " A .pem version of the server cert will be saved to  : $serverCertPath_converted"

# Convert .cer to .pem...
openssl x509 -inform der -in "$serverCertPath_supplied" -out "$serverCertPath_converted"

if test -f "$serverCertPath_converted"; then
  echo '======================================================'
	echo " [ok] Server cert file converted to .pem."
else
	echo " [error] Error converting the server cert file."
	myexit
fi

echo "[debug] THE SERVER TLS CERT IN .PEM FORMAT :"
cat  "${serverCertPath_converted}"
echo '======================================================'




# When the connector installer exports the client identity, it's in .pfx format. 
# But openssl wants that to have a .p12 extension. 
echo
echo '[step] Copying the client cert from .pfx to .p12'
clientCertPath_supplied="${pathToMe}/${authenticationCertSubFolder}/client-cert.pfx"
echo " clientCertPath_supplied : "
echo "  $clientCertPath_supplied"
echo
if test -f "$clientCertPath_supplied"; then
	echo " [ok] $clientCertPath_supplied found"
	echo
else
	echo " [error] Could not find the client cert supplied file."
	myexit
fi
clientCertPath_converted="${testFolder}/client-cert.p12"
echo " A .p12-named copy of the client cert will be saved to  :"
echo "  $clientCertPath_converted"
echo
cp "$clientCertPath_supplied" "$clientCertPath_converted"
if test -f "$clientCertPath_converted"; then
	echo " [ok] Client cert was copied to .p12"
else
	echo " [error] Problem copying the client cert file."
	myexit
fi
echo '======================================================'
echo "[debug] CLIENT IDENTITY INFORMATION :"
echo "[info] Reading from ${clientCertPath_converted}"
# echo '[TEST]'
# echo "openssl pkcs12 -info -in \"${clientCertPath_converted}\" -password \"pass:${clientPfxPassword}\""
echo
# openssl pkcs12 -in mypfx.pfx -noout

openssl pkcs12 -info -in "${clientCertPath_converted}" -password "pass:${clientPfxPassword}"
# openssl pkcs12 -info -in "${clientCertPath_converted}" -password "pass:nChKHZTy20"
passwordTestRetCode=$?
# echo "Client Identity Read Result : " $passwordTestRetCode
if [[ $passwordTestRetCode -eq 1 ]]; then
  echo "[error] I couldn't read the client certificate. Did you give me the right password?"
  myexit
fi
echo '======================================================'

echo
echo
echo '[step] Creating a key and CSR for the new identity...'
# Make a path where we'll save the private key we generate with openssl. 
# Then we can create a CSR based on that and ask ADCSC to get the CA to sign the CSR.
keyPath="${testFolder}/${subjNoDots}.key"

# Generate a CSR and save it in a var...
csr=$( openssl \
  req \
  -new \
  -newkey rsa:2048 \
  -nodes \
  -keyout "${keyPath}" \
  -subj "/CN=${subject}" )

if [[ -z $csr ]]; then
	echo "[error] could not create CSR. Check your request values. Did you provide a subject?"
	myexit
fi



# We're just sticking the csr into a variable, but if you wanted to save the csr to disk
# for troubleshooting, you could define a path...
#  csrPath="${DIR}/${subjNoDots}.csr"
# And then add a -out on the end of the openssl call...
#  -out "${csrPath}" \
# Then you could read it back in with...
#  csr=$(cat "$csrPath" )

echo '======================================================'
echo "We created the following CSR: "
echo "${csr}"
echo '======================================================'
echo

# Strip off the header and footer lines from the CSR. We don't want those, just the csr part... 
csr=$(echo "$csr" | sed '1d;$d' )

echo
echo
echo '======================================================'
echo " CSR after stripping off the header and footer lines..."
echo "${csr}"
echo '======================================================'
echo
echo


# Compose a JSON message we'll be sending to the ADCS Connector as a request to create a cert...
echo '[step] preparing a request json body to send to the connector.'
read -r -d '' requestJson <<EOF
	{ "pkcs10": "$csr",
		"template": "${ADCS_CA_template}",
		"config": {
			"dc": "${ADCS_CA_hostname}",
			"ca": "${ADCS_CA_InstanceName}" }
}
EOF



# If you are debugging and want to save the request json to disk you can...
#jsonPayloadFilePath="${testFolder}/requestBody.json"
#echo "$requestJson" > "$jsonPayloadFilePath"
# If you wanted to feed json in from the file, you could use @ in your curl --data 
#--data "@${jsonPayloadFilePath}" \

echo '======================================================'
echo " Request API body to send to the Connector will be:"
echo "${requestJson}"
echo '======================================================'
echo
echo


# Now we can use curl to submit a signing request to the connector...
echo '[step] Sending the request to the connector via curl...'
requestResponse=$( curl \
  --cert "${clientCertPath_converted}:${clientPfxPassword}" \
	--cert-type "P12" \
	--cacert "${serverCertPath}" \
  --http1.1 \
  --header "Content-Type: application/json" \
  --write-out $'\n%{http_code}' \
  --request POST  \
  --data "${requestJson}" \
  --show-error \
  --silent \
	--cacert "${serverCertPath_converted}" \
	--insecure \
  $CONNECTOR_URL/api/v1/certificate/request )

# echo "$requestResponse"

if [[ -z $requestResponse ]]; then
  echo "[error] No response body received from the Connector."
  myexit
fi

HTTP_Status=$( echo "$requestResponse" | tail -1)
requestResponse=$( echo "$requestResponse" | sed \$d )

echo "[debug] HTTP_Status : $HTTP_Status"

# Strip carriage returns from the response since they'll be in CR NL line endings which look double-spaced on mac/linux...
requestResponse="${requestResponse//$'\r'/}"

if [[ $HTTP_Status = "200" ]]; then
  echo '[OK] Response received.'
elif [[ $HTTP_Status = "201" ]]; then
  echo '[OK] Response received.'
elif [[ $HTTP_Status = "400" ]]; then
  echo "[error] Invalid request."
  echo "$requestResponse"
  myexit
elif [[ $HTTP_Status = "500" ]]; then
  echo "[error] Server error."
  echo "$requestResponse"
  myexit
elif [[ $HTTP_Status = "503" ]]; then
  echo "[error] HTTP Error 503. \"The service is unavailable.\""
  echo "[error] This can happen for a few reasons, including that the user on your certificate to user mapping in IIS config is wrong."
  echo "$requestResponse"
  myexit
else
  echo "[error] Server did not respond correctly. "
  echo "$requestResponse"
  myexit
fi


# That will spit out something like this: 

# This example is from a standalone CA with explicit admin approval required. 
# {
#   "request-status": {
#     "status": "CR_DISP_UNDER_SUBMISSION",
#     "message": "Request taken under submission"
#   },
#   "request-id": 90
# }

# Here's an example response from a server with an auto-issue policy...
# {
#   "request-status":{
#  	 "status":"CR_DISP_ISSUED",
#  	 "message":"Certificate issued"
#   },
#   "request-id":95
# }

# CA not set up properly...
# {
#   "request-status": {
#     "status": "CR_DISP_DENIED",
#     "message": "Request denied"
#   },
#   "x509": null
# }
# I've seen this when the ca admin rejects the request or the CA itself 
# denies the request based on policy.
# In certsrv denied requests, I see...
# "The revocation function was unable to check revocation because the revocation server was offline."
# I stop/started the CA service by right-clicking the ca name in certsrv. That fixed it. If not...
#  https://blogs.technet.microsoft.com/nexthop/2012/12/17/updated-creating-a-certificate-revocation-list-distribution-point-for-your-internal-certification-authority/
# Another example of something that could be wrong... 
#  https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4888

# Bad ADCS/IIS install might return...
# <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
# <HTML><HEAD><TITLE>Service Unavailable</TITLE>
#  <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
#  <BODY><h2>Service Unavailable</h2>
#   <hr><p>HTTP Error 503. The service is unavailable.</p>
#  </BODY>
# </HTML>
 
echo
echo "CONNECTOR SIGNING REQUEST RESPONSE: "
echo "$requestResponse"
echo


echo '[step] Parsing response to get the request ID for use in retrieving the signature...'
requestID=$( echo "$requestResponse" | python -c "import sys, json; print json.load(sys.stdin)['request-id']" )
echo "Request ID: $requestID"
echo
# No python? We could do it another way, but that's weak sauce...

if [[ -z $requestID ]]; then
  echo "[error] The response did not include a request ID. I'm giving up."
  exit
fi



# Now that we have a requestID, we can redeem that to get the actual cert from the CA. 

# Create json for the retrieval request...
echo '[step] Preparing a signature retrieval json body to send to the connector.'
read -r -d '' retrievalJSON <<EOF
{ "request-id": ${requestID},
	"config": {
		"dc": "${ADCS_CA_hostname}",
		"ca": "${ADCS_CA_InstanceName}" }
}
EOF

# Submit the retrieval request
echo '[step] Sending the retrieval command to the connector via curl...'
retrievalResponse=$( curl \
  --cert "${clientCertPath_converted}:${clientPfxPassword}" \
	--cert-type "P12" \
  --http1.1 \
  --header "Content-Type: application/json" \
  --request POST  \
  --data "$retrievalJSON" \
  --show-error \
  --silent \
	--cacert "${serverCertPath_converted}" \
	--insecure \
  "$CONNECTOR_URL/api/v1/certificate/retrieve" )


echo
echo "SIGNATURE RETRIEVAL REQUEST RESPONSE:"
echo $retrievalResponse
echo 
# The returned signature will look something like this...
# {
#   "request-status": {
#     "status": "CR_DISP_ISSUED",
#     "message": "Certificate issued"
#   },
#   "x509": "MIIDrTCCApWgAwIBAgITOQAAAGSFKa9cUkKauQAAAAAAZDANBgkqhkiG9w0BAQsF\r\nADA5MRQwEgYKCZImiZPyLGQBGRYEY2x1YjEUMBIGCgmSJomT8ixkARkWBGphbWYx\r\nCzAJBgNVBAMTAkNBMB4XDTE5MDcwMjIwMDMyNVoXDTIwMDcwMjIwMTMyNVowFzEV\r\nMBMGA1UEAxMMd3d3LmphbWYuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\r\nCgKCAQEAv9VydAldW1vpH1g2N2YupMULrtmhNkUxxaxgB+oKLSpXDw4mS8CY0MHx\r\n04KB/qr9qlLAvJxM/jrYwERzK8aUCriKxLZ/XNPPv3sn8Cjq9Qatlf1aelXrSA72\r\n1XI/QALuNj1jVx9fDlsRfspMV/52R/8KET8PT1pC0IbGxzNyVVL26dirasTx/78i\r\nGW4RBgRpCCBMhT7wm/YR08aw7uwL3bIbPGOYOLSjG/o6rfP98pvBU2lifmEp33oN\r\nJw9WRh0cmUmMcH4T9sT3C9xtSk2RwlV3Mc44T78oBX4Mh8Dv5LczaAMsDTCJC/6Y\r\nzAg+2CO8pcFvWx2R5cSpD0ITod1AaQIDAQABo4HPMIHMMB0GA1UdDgQWBBSnU8EY\r\nNsmwbQqbE6ShpPvMCFQ8XzAfBgNVHSMEGDAWgBTBLReeD31V01LFAOZaLZkIYzVA\r\nHTA4BgNVHR8EMTAvMC2gK6AphidmaWxlOi8vLy9tcy5qYW1mLmNsdWIvQ2VydEVu\r\ncm9sbC9DQS5jcmwwUAYIKwYBBQUHAQEERDBCMEAGCCsGAQUFBzAChjRmaWxlOi8v\r\nLy9tcy5qYW1mLmNsdWIvQ2VydEVucm9sbC9tcy5qYW1mLmNsdWJfQ0EuY3J0MA0G\r\nCSqGSIb3DQEBCwUAA4IBAQA4Bi6EsnoBSkPvutq4yUTrrcRpnik3Iz8FExCrJc4T\r\naFf100m3oVDO/mjHph5D9K6QMsQ/mZtamgsQwh5V5HNTeRe52n+zpnbPLwkHMq5W\r\nFj190NA3iviMz4gS46kNqV1Q7VbipNCg4gdJtixnv08J8kmzBTOnWpl7xczQMVpF\r\n+6gUhjJvYTvN8z1gg5KYS2vVzy/HjtarIK88no4qqWhEkxQoEBdCIY1pO9TeCLwG\r\n8IalQ1/dktURZSQZd7pPt2UeW8GQradCyeQvlBsgdzWG6EiPCctDrWH/epYhSv0n\r\neNGaM4cjQHFXVs2D7pzxK5SYb0Gb6FR3CMQpZhKFgp3r\r\n"
# }

echo '[step] Parse out the x.509 crt from the connector response...'
crt=$( echo "$retrievalResponse" | python -c "import sys, json; print json.load(sys.stdin)['x509']" )

echo '[debug] The crt portion of the response was:'
echo "\"$crt\""
echo

if [[ -z $crt ]]; then
  echo "[error] Couldn't parse a certificate signature from the retrieval response. I'm giving up."
  echo '======================================================'
  exit
fi

if [[ $crt -eq "None" ]]; then
  echo "[error] The retrieval response's certificate signature field was empty. I'm giving up."
  echo '======================================================'
  exit
fi


# Strip carriage return
crt="${crt//$'\r'/}"

# Add header/footer...
crt="-----BEGIN CERTIFICATE-----
${crt}
-----END CERTIFICATE-----"

echo
echo '======================================================'
echo "Finished CRT signature for our CSR :"
echo "$crt"
echo '======================================================'
echo

crtPath="${testFolder}/${subjNoDots}.crt"
# Save to disk since it has to be supplied to openssl in a file...
echo "$crt" > "$crtPath"
echo '======================================================'
echo "[step] Testing the crt key signing file: "
openssl x509 -text -noout -in "${crtPath}"
echo '======================================================'

# Now combine the signature cert and the private key into a p12...
identPath="${testFolder}/${subjNoDots}.p12"
openssl pkcs12 \
       -inkey "$keyPath" \
       -in "$crtPath" \
       -export \
       -password "pass:${passwordForTheNewIdentityFile}" \
       -out "$identPath"

echo
echo "[note] You'd need to add in the trust chain from your CA to have a full path identity file."
 
echo
echo '===END==='
echo

open "${testFolder}"

exit 0

# Pssst... if that worked, good for you. But you've already copied your 
# private key and password too many places. Go re-install your Connector
# to get a new client identity generated and upload it to Jamf Pro directly.
