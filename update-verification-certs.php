<?php
/***************************************************************************
 * Copyright (C) 2014 Ping Identity Corporation
* All rights reserved.
*
* The contents of this file are the property of Ping Identity Corporation.
* For further information please contact:
*
*      Ping Identity Corporation
*      1099 18th St Suite 2950
*      Denver, CO 80202
*      303.468.2900
*      http://www.pingidentity.com
*
* DISCLAIMER OF WARRANTIES:
*
* THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
* ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
* WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
* MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
* WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
* USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
* YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
* WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
		* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**************************************************************************/
/*
* This script parses an EntitiesDescriptor from SAML 2.0 metadata and runs 
* side-by-side certificate comparison against the connections configured in
* PingFederate, as obtained over the PingFederate Admin REST API.
* 
* It subsequently updates the primary and/or secondary verification certificates
* when found out-of-sync and as such can be used as a cronjob to keep signing keys
* in sync with centrally hosted federation metadata that is (signed and) distributed
* by a multi-party federation operator.
* 
* Documentation for the PingFederate Admin REST API is at:
* https://localhost:9999/pf-admin-api/api-docs/
* 
* @Author: Hans Zandbelt - hzandbelt@pingidentity.com
*
**************************************************************************/

// TODO: split out metadata_retrieve_and_verify and http_exec in their own utils/common.php
//       file, shared with provision.php (which really should be named import-entities.php 

/*
 * configuration parameters
 */
$cfg = array(
	/* the URL (may be file://) to the federation metadata that contains the EntitiesDescriptor */
#	'remote-metadata-url' => 'http://md.incommon.org/InCommon/InCommon-metadata.xml',
	'remote-metadata-url' => 'file://InCommon-metadata.xml',

	'pingfed-admin-api' => array(
		/* the URL to the PingFederate Admin REST API */
		'url' => 'https://localhost:9999/pf-admin-api/rest',
		/* the username to use against the Admin API */
		'admin_username' => 'administrator',
		/* the password to use against the Admin API */
		'admin_password' => '2Federate',
	),
);

/*
 * perform HTTP call (GET/POST/PUT) and return results
 */
function http_exec($url, $method = NULL, $data = NULL, $username = NULL, $password = NULL, $verify_peer = 1, $verify_host = 1) {
	$ch = curl_init();

	#curl_setopt($ch, CURLOPT_VERBOSE, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify_peer);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verify_host);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

	if ( ($username != NULL) and ($password != NULL) ) {
		curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC ) ;
		curl_setopt($ch, CURLOPT_USERPWD, $username . ':' . $password);
	}

	curl_setopt($ch, CURLOPT_URL, $url);

	$headers = array('X-XSRF-Header: dummy');
	if ($method == "POST") {
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
	} else if ($method == "PUT") {
		$headers[] = 'Content-type: application/json';
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
	}
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

	$result = curl_exec($ch);
	print_r(curl_error($ch));
	curl_close($ch);
	
	return $result;
}

/*
 * Retrieve a SAML 2.0 metadata document from the specified location and optionally verify the signature on it.
 */
function metadata_retrieve_and_verify($url, $cert = NULL) {
	$metadata = http_exec($url);
	$doc = new DOMDocument(true);
	$doc->loadXML($metadata);
	$result = xml_sig_verify($doc, $cert);
	if ($result !== true) {
		echo " # ERROR: signature verification failed!\n";
		exit;
	}
	if ($cert !== NULL) echo " # INFO: signature verification OK.\n";
	return $doc;
}

/*
 * Calculate the SHA1 fingerprint for a PEM-encoded X.509 certificate.
 */
function sha1_thumbprint($cert) {
	$file = preg_replace('/\-+BEGIN CERTIFICATE\-+/','',$cert);
	$file = preg_replace('/\-+END CERTIFICATE\-+/','',$cert);
	$file = trim($cert);
	$file = str_replace( array("\n\r","\n","\r"), '', $cert);
	$bin = base64_decode($cert);
	return sha1($bin);
}

/*
 * Extract a PEM-encoded X.509 certificate from an XML KeyDescriptor element.
 */
function keydescriptor_certifcate_get($xpath, $key_desc) {
	$cert = $xpath->query('ds:KeyInfo/ds:X509Data/ds:X509Certificate', $key_desc);
	$cert = "-----BEGIN CERTIFICATE-----\n" . trim($cert->item(0)->textContent) . "\n-----END CERTIFICATE-----\n";
	return $cert;
}

/*
 * Create an X.509 certificate element in decoded PF JSON/REST-style formatting.
 */
function json_certificate_create($xml, $primary) {
	$cert = new stdClass();
	$cert->x509File = new stdClass();
	$cert->x509File->fileData = $xml;
	$cert->primaryVerificationCert = $primary;
	$cert->secondaryVerificationCert = !$primary;
	return $cert;
}

/*
 * Retrieve XML metadata from a URL and parse out the EntitiesDescriptor element.
 */
function xml_retrieve_entities_descriptor($metadata_url) {
	$metadata = http_exec($metadata_url, "GET", NULL, NULL, NULL, 0, 0, 0);
	$doc = new DOMDocument(true);
	$doc->loadXML($metadata);
	$xpath = new DOMXpath($doc);
	$xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
	$xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
	return array($xpath, $xpath->query('/md:EntitiesDescriptor', $doc->documentElement));
}

/*
 * Retrieve a list of JSON-formatted IDP connection information entries from the PingFederate Admin REST API.
 */
function pingfed_idps_retrieve($cfg) {
	$ht = array();
	$url = $cfg['pingfed-admin-api']['url'] . '/sp/idpConnections';
	$json = http_exec($url, "GET", NULL, $cfg['pingfed-admin-api']['admin_username'], $cfg['pingfed-admin-api']['admin_password'], 0, 0);
	if ($json) {
		$idps = json_decode($json);
		if ($idps) {
			foreach ($idps->items as $idp) $ht[$idp->entityId] = $idp;
		}
	}
	return $ht;	
}

/*
 * Update/write/put/push the connection information for a connection over the PingFederate Admin REST API.
 */
function pingfed_idp_update($cfg, $json) {
	$url = $cfg['pingfed-admin-api']['url'] . '/sp/idpConnections/' . $json->id;
	$result = http_exec($url, "PUT", json_encode($json), $cfg['pingfed-admin-api']['admin_username'], $cfg['pingfed-admin-api']['admin_password'], 0, 0);
	$json = json_decode($result);
	if ($json->resultId == "validation_error") {
		print " # error: " . $json->validationErrors[0]->message . "\n";
		//exit;
	}
}

/*
 * Return the indexes of the primary and secondary certificates in the list of configured certificates for a connection.
 */
function json_get_indexes($json) {
	$primary_index = -1;
	$secondary_index = -1;	
	for ($i = 0; $i < count($json->credentials->certs); $i++) {
		if ($json->credentials->certs[$i]->primaryVerificationCert) {
			$primary_index = $i;
		} else if ($json->credentials->certs[$i]->secondaryVerificationCert) {
			$secondary_index = $i;
		}
	}
	return array($primary_index, $secondary_index);
}

/* 
 * See if a certificate already exists in the list of verification certs for a connection.
 */
function metadata_get_matching_index($cert_xml, $json) {
	$index = -1;
	for ($i = 0; $i < count($json->credentials->certs); $i++) {
		if (sha1_thumbprint($cert_xml) == sha1_thumbprint($json->credentials->certs[$i]->x509File->fileData)) {
			$index = $i;
			break;
		}
	}
	return $index;
}

/*
 * Return the first and second signing certificates in the list of KeyDescriptors in the IDPSSODescriptor.
 */
function metadata_get_signing_certs($xpath, $idp_desc) {
	$primary_xml = NULL;
	$secondary_xml = NULL;
	foreach ($xpath->query('md:KeyDescriptor', $idp_desc->item(0)) as $key_desc) {
		$use = $key_desc->getAttribute('use');
		if ( ($use == NULL) || ($use == "signing") ) {
			if ($primary_xml == NULL) {
				$primary_xml = keydescriptor_certifcate_get($xpath, $key_desc);
			} else {
				$secondary_xml = keydescriptor_certifcate_get($xpath, $key_desc);
				break;
			}
		}
	}
	return array($primary_xml, $secondary_xml);
}

/*
 * Check if a connection needs a certificate update.
 */
function metadata_needs_update($primary_index, $secondary_index, $primary_xml, $secondary_xml, $json) {

	$update = false;
	
	/* do we currently have a primary cert configured currently for this connection? */
	if ($primary_index != -1) {
		/* yes, now see if the primary cert still matches */
		if (sha1_thumbprint($primary_xml) != sha1_thumbprint($json->credentials->certs[$primary_index]->x509File->fileData)) {
			/* the currently configured primary cert is out-of-sync with the one that we obtained remotely */
			print " updating primary certificate for entity: " . $json->entityId . "\n";
			$json->credentials->certs[$primary_index]->x509File->fileData = $primary_xml;
			$update = true;
		}
	} else {
		/* no primary verification certificate found, this should not happen */
		print " adding primary certificate for entity: " . $json->entityId . "\n";
		$json->credentials->certs[] = json_certificate_create($primary_xml, true);
		$update = true;
	}
	
	/* see if we have obtained a secondary certificate at all from the metadata feed */
	if ($secondary_xml != null) {
		/* do we currently have a secondary cert configured? */
		if ($secondary_index != -1) {
			/* yes, now see if the secondary cert still matches */
			if (sha1_thumbprint($secondary_xml) != sha1_thumbprint($json->credentials->certs[$secondary_index]->x509File->fileData)) {
				/* currently configured secondary cert is out-of-sync with the one that we obtained remotely */
				print " updating secondary certificate for entity: " . $json->entityId . "\n";
				$json->credentials->certs[$secondary_index]->x509File->fileData = $secondary_xml;
				$update = true;
			}
		} else {
			/* no secondary configured currently, but the cert may be in the list of configured (but unused) certs, check that */
			$secondary_index = metadata_get_matching_index($secondary_xml, $json);
			if ($secondary_index != -1) {
				/* got the certificate imported already, it was just not configured as secondary yet: do that now */
				print " promoting existing certificate to secondary certificate for entity: " . $json->entityId . "\n";
				$json->credentials->certs[$secondary_index]->secondaryVerificationCert = true;
			} else {
				/* our cert is no secondary cert currently and it is not in the list of other (unused) certificates either;
				 * add it as a secondary cert then */
				print " adding secondary certificate for entity: " . $json->entityId . "\n";
				$json->credentials->certs[] = json_certificate_create($secondary_xml, false);				
			}
			$update = true;
		}
	} else {
		/* no secondary certificate in remote metadata; if we currently have one set as a secondary, unset it */
		if ($secondary_index != -1) {
			print " removing existing secondary certificate for entity: " . $json->entityId . "\n";
			$json->credentials->certs[$secondary_index]->secondaryVerificationCert = false;
		}
	}

	// TODO: do we ever remove certs?
	
	return $update;
}

/*
 * Process an IDPSSODescriptor
 */
function xml_process_existing_idp_sso_descriptor($cfg, $json, $xpath, $idp_desc) {
	/* get the indexes of the primary and secondary verification certs in the list of certs for this IDP */
	list($primary_index, $secondary_index) = json_get_indexes($json);
	/* get the first and second signing cert from the remote metadata */
	list($primary_xml, $secondary_xml) = metadata_get_signing_certs($xpath, $idp_desc);
	/* see if the certs match; if not, we need to update them */
	if (metadata_needs_update($primary_index, $secondary_index, $primary_xml, $secondary_xml, $json)) {
		/* TODO: shouldn't need to do this, right? report issue */
		unset($json->credentials->signingSettings);
		/* perform a cert update because they're out of sync */
		pingfed_idp_update($cfg, $json);
	} else {
		print " skipping entity that needs no update: " . $json->entityId . "\n";
	}
}

/*
 * process an EntitiesDescriptor
 */
function xml_process_entities_descriptor($cfg, $ht, $xpath, $descriptor) {
	/* loop over the EntityDescriptor's embedded in this EntitiesDescriptor */
	foreach ($xpath->query('md:EntityDescriptor', $descriptor->item(0)) as $desc) {
		$entityid = $desc->getAttribute('entityID');
		/* check if this EntityDescriptor is an IDP */
		$idp_desc = $xpath->query('md:IDPSSODescriptor', $desc);
		if ($idp_desc->length > 0) {
			/* check if this entity is currently configured as an IDP in PingFederate (otherwise ignore it) */
			if (!array_key_exists($entityid, $ht)) continue;
			xml_process_existing_idp_sso_descriptor($cfg, $ht[$entityid], $xpath, $idp_desc);
		}
	}
}

/*
 * Retrieve the EntitiesDescriptor from the remote location (may be URL to a file on disk).
 */
list($xpath, $descriptor) = xml_retrieve_entities_descriptor($cfg['remote-metadata-url']);

/*
 * Retrieve the JSON formatted IDP connections through the PingFederate Admin REST API.
*/
$ht = pingfed_idps_retrieve($cfg);

/*
 * Process/compare the connection information.
 */
xml_process_entities_descriptor($cfg, $ht, $xpath, $descriptor);

?>
